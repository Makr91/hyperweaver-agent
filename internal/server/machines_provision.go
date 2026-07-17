package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/provisioner"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// The provisioning surface — POST /machines/{name}/provision runs the ONE
// document walk (Mark's ruling 2026-07-17: THERE ARE NO PHASES — the stored
// provisioner document is the program, executed AS WRITTEN): extract → boot
// → wait_ssh → folder sync → pre[] hooks → the provisioning: methods in
// stored-document KEY ORDER (each method's entries in list order) → post[]
// hooks → syncback. /sync is the ad-hoc folder slice; /run-provisioners is
// the SAME walk minus prepare/boot/wait_ssh/sync/syncback;
// /provision/status reports the pipeline's state.

// templateSources converts the configured registries into the machines
// package's source shape.
func (s *Server) templateSources() []machines.TemplateSource {
	sources := make([]machines.TemplateSource, 0, len(s.cfg.TemplateSources.Sources))
	for _, source := range s.cfg.TemplateSources.Sources {
		sources = append(sources, machines.TemplateSource{
			Name:      source.Name,
			URL:       source.URL,
			Enabled:   source.Enabled,
			Default:   source.Default,
			AuthToken: source.AuthToken,
			CAFile:    source.CAFile,
		})
	}
	return sources
}

// provisionValidation is ValidationHelper.validateProvisioningRequest's
// result: the stored provisioner document, the control IP, credentials, and
// the resolved communicator (zoneweaver's shipped winrm shape, sync
// 2026-07-17: W-Q1..W-Q5) — ssh (default) or winrm, with the ruled winrm
// knobs and the vagrant_* keys the new spellings shadowed (narrated onto the
// response task_chain[] — zoneweaver's channel).
type provisionValidation struct {
	config       machines.MachineConfig
	provisioner  map[string]any
	ip           string
	port         int
	credentials  machines.Credentials
	communicator string
	winrm        machines.WinRMSettings
	shadowedKeys []string
}

// validateProvisionRequest ports validateProvisioningRequest: provisioner
// config stored (else "set via PUT first"), settings present, vagrant_user
// required, control IP resolvable. The communicator resolves at READ time
// through the hostdoc alias reader — stored documents never rewrite.
func validateProvisionRequest(machine *machines.Machine) (validation *provisionValidation, problem string) {
	config := machines.ParseConfiguration(machine)
	provisionerDoc := config.Provisioner()
	if len(provisionerDoc) == 0 {
		return nil, "No provisioner configuration found. Set provisioner config via PUT /machines/{name} first."
	}
	settings := config.Section("settings")
	if len(settings) == 0 {
		return nil, "Machine configuration has no settings section (Hosts.yml structure required)"
	}
	credentials := machines.ExtractCredentials(settings)
	if credentials.Username == "" {
		return nil, "Credentials missing: settings.vagrant_user is required"
	}
	winrm, shadowed := machines.ExtractWinRM(settings)
	communicator := "ssh"
	if winrm.Enabled {
		communicator = "winrm"
	}
	// The control IP is the FALLBACK transport only — resolveTransport
	// prefers the provisioning NIC's ssh port-forward and errors when
	// neither exists.
	ip := machines.ExtractControlIP(config.List("networks"))
	port := 22
	if p, ok := provisionerDoc["ssh_port"].(float64); ok && p > 0 {
		port = int(p)
	}
	return &provisionValidation{
		config: config, provisioner: provisionerDoc,
		ip: ip, port: port, credentials: credentials,
		communicator: communicator, winrm: winrm, shadowedKeys: shadowed,
	}, ""
}

// hostHooksPreflight is the design §5 confirmation gate, STRICTLY pre-flight
// (a running sequence is never aborted by this check): a document carrying
// host-target hooks needs provisioning.host_hooks on, and — unless the
// machine's package is INSTALLER-SEEDED — a one-time per-machine
// confirmation. confirm records it (configuration.host_hooks_confirmed);
// needsConfirmation asks the caller to answer the needs-confirmation shape.
func (s *Server) hostHooksPreflight(ctx context.Context, machine *machines.Machine,
	v *provisionValidation, confirm bool,
) (problem string, needsConfirmation bool) {
	if !machines.HasHostHooks(v.provisioner) {
		return "", false
	}
	if !s.cfg.Provisioning.HostHooks {
		return "This machine's document carries host-target hooks and provisioning.host_hooks is false on this agent — remove the hooks or enable the gate", false
	}
	if confirmed, _ := v.config["host_hooks_confirmed"].(bool); confirmed {
		return "", false
	}
	if spec, serr := machines.ParseSpec(machine); serr == nil && spec.HasProvisioner() {
		if provisioner.SeededFamilies()[spec.Provisioner.Name] {
			// Installer-shipped packages never prompt (design §5).
			return "", false
		}
	}
	if !confirm {
		return "", true
	}
	if merr := s.machines.MergeConfigurationSections(ctx, machine.Name,
		map[string]any{"host_hooks_confirmed": true}); merr != nil {
		slog.Error("record host-hooks confirmation", "machine", machine.Name, "error", merr)
		return "Failed to record the host-hooks confirmation", false
	}
	slog.Info("host hooks confirmed for machine", "machine", machine.Name)
	return "", false
}

// resolveTransport picks the pipeline's SSH target (Mark's architecture,
// 2026-07-07): the provisioning NIC's NAT ssh port-forward first — vagrant's
// model, immune to anything the guest's networking role does to real
// adapters — falling back to the document's control IP for machines without
// a forward (pre-forward creates, user-built VMs).
func resolveTransport(ctx context.Context, machine *machines.Machine, v *provisionValidation) (problem string) {
	if v.communicator == "winrm" {
		// winrm machines prefer 127.0.0.1:<winrm forward> (the same NAT model
		// as ssh — W-Q1..W-Q5), falling back to the control IP with the RULED
		// guest winrm port.
		if port := machines.FindWinRMForward(ctx, machine, v.winrm.Port); port > 0 {
			v.ip, v.port = "127.0.0.1", port
			return ""
		}
		if v.ip == "" {
			return "No WinRM transport: machine has no NAT winrm port-forward and no control IP in networks[] (set is_control: true on one network)"
		}
		v.port = v.winrm.Port
		return ""
	}
	if port := machines.FindSSHForward(ctx, machine); port > 0 {
		v.ip, v.port = "127.0.0.1", port
		return ""
	}
	if v.ip == "" {
		return "No SSH transport: machine has no NAT ssh port-forward and no control IP in networks[] (set is_control: true on one network)"
	}
	return ""
}

// childMetadata marshals one provision child's metadata document. winrm
// machines emit communicator + the ruled winrm block into EVERY child's
// metadata (zoneweaver's exact metadata shape — W-Q1..W-Q5): the SAME ops
// branch on it at execution time.
func childMetadata(v *provisionValidation, extra map[string]any) (*string, error) {
	doc := map[string]any{
		"ip":          v.ip,
		"port":        v.port,
		"credentials": v.credentials,
	}
	if v.communicator == "winrm" {
		doc["communicator"] = "winrm"
		doc["winrm"] = map[string]any{
			"port":                  v.winrm.Port,
			"transport":             v.winrm.Transport,
			"ssl_peer_verification": v.winrm.SSLPeerVerification,
		}
	}
	for key, value := range extra {
		doc[key] = value
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	s := string(raw)
	return &s, nil
}

// createChainTask creates one chained task (TaskCreationHelper.createTask).
func (s *Server) createChainTask(ctx context.Context, machineName, operation string,
	metadata, dependsOn *string, parentID string, createdBy string,
) (*tasks.Task, error) {
	nt := tasks.NewTask{
		MachineName: machineName,
		Operation:   operation,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   createdBy,
		Metadata:    metadata,
		DependsOn:   dependsOn,
	}
	if parentID != "" {
		nt.ParentTaskID = &parentID
	}
	return s.tasks.Store().Create(ctx, &nt)
}

// walkStep is one planned walk child: its operation, the metadata extras
// beyond the transport triple, and — on a batch's first entry — the
// task_chain label and counts the response reports. An EMPTY operation is a
// RESPONSE-ONLY entry (zoneweaver's exact named shape — W-Q1..W-Q5): the
// winrm skips and method_not_executable records land in task_chain[] at
// their document position but never become tasks.
type walkStep struct {
	operation string
	extra     map[string]any
	step      string
	stepInfo  map[string]any
}

// docEnabled reads a method section's enabled gate in the document's own
// on/true/1/yes vocabulary (mirrors machines.onOff — the same words the
// shell/docker readers accept).
func docEnabled(value any) bool {
	if b, ok := value.(bool); ok {
		return b
	}
	s, _ := value.(string)
	switch strings.ToLower(s) {
	case "on", "true", "1", "yes":
		return true
	}
	return false
}

// hookSteps plans one hook bracket (pre[] | post[]) — one machine_hook child
// per run-filtered entry, list order.
func hookSteps(hooks []machines.Hook, label string) []walkStep {
	steps := make([]walkStep, 0, len(hooks))
	for i := range hooks {
		step := walkStep{operation: machines.OpHook, extra: map[string]any{"hook": hooks[i]}}
		if i == 0 {
			step.step = label
			step.stepInfo = map[string]any{"hook_count": len(hooks)}
		}
		steps = append(steps, step)
	}
	return steps
}

// playbookSteps plans one run-filtered playbook batch — entries exactly as
// the document lists them: the list an entry sits in (local | remote) picks
// its execution mechanism, never its position.
func playbookSteps(playbooks []machines.Playbook, skippedCount int) []walkStep {
	steps := make([]walkStep, 0, len(playbooks))
	for i := range playbooks {
		operation := machines.OpProvisionPlaybook
		if playbooks[i].Remote {
			operation = machines.OpRemotePlaybook
		}
		step := walkStep{operation: operation, extra: map[string]any{"playbook": playbooks[i]}}
		if i == 0 {
			step.step = "method:ansible"
			step.stepInfo = map[string]any{
				"playbook_count":    len(playbooks),
				"playbooks_skipped": skippedCount,
			}
		}
		steps = append(steps, step)
	}
	return steps
}

// winnowLocalPlaybooksForWinRM drops the LOCAL playbooks from a run-filtered
// batch on winrm guests — in-guest ansible is impossible over winrm
// (zoneweaver's exact named shape, W-Q1..W-Q5): the drop is a RESPONSE-ONLY
// task_chain[] entry {step: ansible_local_skipped_winrm, playbook_count} at
// its document position; remote playbooks STILL RUN. ssh machines pass
// through untouched.
func winnowLocalPlaybooksForWinRM(v *provisionValidation, playbooks []machines.Playbook,
	methods []walkStep,
) ([]machines.Playbook, []walkStep) {
	if v.communicator != "winrm" {
		return playbooks, methods
	}
	remote := make([]machines.Playbook, 0, len(playbooks))
	localCount := 0
	for i := range playbooks {
		if playbooks[i].Remote {
			remote = append(remote, playbooks[i])
		} else {
			localCount++
		}
	}
	if localCount > 0 {
		methods = append(methods, walkStep{
			step:     "ansible_local_skipped_winrm",
			stepInfo: map[string]any{"playbook_count": localCount},
		})
	}
	return remote, methods
}

// planWalk plans the document walk's direct children: pre[] hooks, then the
// provisioning: methods in the order their KEYS APPEAR in the stored document
// (each method's entries in list order — Mark's ruling: there are no phases,
// the document executes AS WRITTEN), then post[] hooks. sync/syncback are the
// walk's outer brackets and ride their own sub-parents. Unknown method keys
// NARRATE-SKIP into skippedMethods — named loudly, never a failure.
func planWalk(machine *machines.Machine, v *provisionValidation, provisionedBefore bool,
) (walk []walkStep, skippedMethods []string, skippedPlaybooks []machines.SkippedPlaybook, playbookCount int) {
	skippedPlaybooks = []machines.SkippedPlaybook{}
	walk = append(walk, hookSteps(machines.FilterHooksByRun(
		machines.ProvisionerHooks(v.provisioner, "pre"), provisionedBefore), "pre_hooks")...)

	// The method key order comes from the stored document's RAW bytes — the
	// map view alphabetizes; only the arrays inside each method survive maps.
	provisioningRaw := machines.RawObject(machines.RawProvisioner(machine))["provisioning"]
	methodKeys := machines.OrderedKeys(provisioningRaw)
	provisioning, _ := v.provisioner["provisioning"].(map[string]any)
	methods := []walkStep{}
	for _, key := range methodKeys {
		switch key {
		case "pre", "post":
			// The walk's brackets — planned above/below, never methods.
		case "shell":
			scripts := machines.ProvisionerShellScripts(v.provisioner)
			for i, script := range scripts {
				step := walkStep{
					operation: machines.OpShellScript,
					extra:     map[string]any{"script": script},
				}
				if i == 0 {
					step.step = "method:shell"
					step.stepInfo = map[string]any{"script_count": len(scripts)}
				}
				methods = append(methods, step)
			}
		case "ansible":
			// Hosts.rb:501's gate — provisioning.ansible.enabled, the same
			// enabled vocabulary the shell/docker readers apply.
			ansible, _ := provisioning["ansible"].(map[string]any)
			if !docEnabled(ansible["enabled"]) {
				continue
			}
			playbooks, skipped := machines.FilterPlaybooksByRun(
				machines.ProvisionerPlaybooks(v.provisioner), provisionedBefore)
			skippedPlaybooks = append(skippedPlaybooks, skipped...)
			playbooks, methods = winnowLocalPlaybooksForWinRM(v, playbooks, methods)
			playbookCount += len(playbooks)
			methods = append(methods, playbookSteps(playbooks, len(skipped))...)
		case "docker":
			enabled, composeFiles := machines.ProvisionerDocker(v.provisioner)
			if !enabled {
				continue
			}
			if v.communicator == "winrm" {
				// docker compose rides the SSH transport — skipped whole on
				// winrm guests (zoneweaver's exact named shape, W-Q1..W-Q5).
				methods = append(methods, walkStep{step: "docker_skipped_winrm"})
				continue
			}
			for i, file := range composeFiles {
				step := walkStep{
					operation: machines.OpDockerCompose,
					extra:     map[string]any{"compose_file": file},
				}
				if i == 0 {
					step.step = "method:docker"
					step.stepInfo = map[string]any{"compose_count": len(composeFiles)}
				}
				methods = append(methods, step)
			}
		default:
			// Unknown methods keep skipped_methods (Go's already-shipped
			// wire) PLUS zoneweaver's per-method task_chain[] record.
			skippedMethods = append(skippedMethods, key)
			methods = append(methods, walkStep{
				step:     "method_not_executable",
				stepInfo: map[string]any{"method": key},
			})
		}
	}
	// The flat provisioners[] form lives OUTSIDE provisioning: (Hosts.yml's
	// simplest shape) — no method keys, but ProvisionerPlaybooks still
	// answers entries; they plan as the sole method batch. No ansible.enabled
	// gate applies: there is no ansible section.
	if len(methodKeys) == 0 {
		if flat := machines.ProvisionerPlaybooks(v.provisioner); len(flat) > 0 {
			playbooks, skipped := machines.FilterPlaybooksByRun(flat, provisionedBefore)
			skippedPlaybooks = append(skippedPlaybooks, skipped...)
			playbooks, methods = winnowLocalPlaybooksForWinRM(v, playbooks, methods)
			playbookCount += len(playbooks)
			methods = append(methods, playbookSteps(playbooks, len(skipped))...)
		}
	}
	walk = append(walk, methods...)

	walk = append(walk, hookSteps(machines.FilterHooksByRun(
		machines.ProvisionerHooks(v.provisioner, "post"), provisionedBefore), "post_hooks")...)
	return walk, skippedMethods, skippedPlaybooks, playbookCount
}

// buildProvisionChain queues the provision pipeline: extract (machine_prepare
// — render + materialize the working copy) → boot (the plain start op when
// not running) → wait_ssh → the document walk: folder sync under its
// sub-parent, then pre[] hooks, methods, post[] hooks as DIRECT children of
// the orchestration parent, then syncback under its sub-parent. The walk is
// PLANNED first and created second so the final flag lands on its overall
// last task. Per-machine queue exclusivity serializes the chain exactly like
// the base's one-task-per-zone rule.
func (s *Server) buildProvisionChain(ctx context.Context, machine *machines.Machine,
	v *provisionValidation, skipBoot bool, parentID, createdBy string,
) (chain []map[string]any, skippedMethods []string, err error) {
	chain = []map[string]any{}
	var previous *string

	// Shadowed communicator keys narrate onto the response task_chain[]
	// (zoneweaver's channel — W-Q1..W-Q5) AND the log; the stored document is
	// never rewritten.
	if len(v.shadowedKeys) > 0 {
		slog.Warn("communicator keys shadowed by their new spellings",
			"machine", machine.Name, "keys", v.shadowedKeys)
		chain = append(chain, map[string]any{
			"step": "communicator_keys_shadowed", "keys": v.shadowedKeys,
		})
	}

	// Extract slot: re-render + re-materialize the working copy from the
	// registry package (SHI regenerates before every provision; zoneweaver
	// extracts its artifact here). Only when the spec NAMES a package —
	// provisioner-less machines have nothing to render (their document
	// arrived via PUT and is consumed as stored, the base's model).
	if spec, serr := machines.ParseSpec(machine); serr == nil && spec.HasProvisioner() {
		specMeta, merr := json.Marshal(map[string]any{"spec": machine.Spec})
		if merr != nil {
			return nil, nil, merr
		}
		metadata := string(specMeta)
		task, terr := s.createChainTask(ctx, machine.Name, machines.OpPrepare,
			&metadata, nil, parentID, createdBy)
		if terr != nil {
			return nil, nil, terr
		}
		chain = append(chain, map[string]any{"step": "extract", "task_id": task.ID})
		previous = &task.ID
	}

	// Boot: the plain start operation queued as a child.
	if !skipBoot && machine.Status != machines.StatusRunning {
		task, terr := s.createChainTask(ctx, machine.Name, machines.OpStart,
			nil, previous, parentID, createdBy)
		if terr != nil {
			return nil, nil, terr
		}
		chain = append(chain, map[string]any{"step": "boot", "task_id": task.ID})
		previous = &task.ID
	}

	// Wait for SSH.
	sshMeta, err := childMetadata(v, nil)
	if err != nil {
		return nil, nil, err
	}
	sshTask, err := s.createChainTask(ctx, machine.Name, machines.OpWaitSSH,
		sshMeta, previous, parentID, createdBy)
	if err != nil {
		return nil, nil, err
	}
	chain = append(chain, map[string]any{"step": "wait_ssh", "task_id": sshTask.ID})
	previous = &sshTask.ID

	// The walk, PLANNED before any of its tasks exist.
	provisionedBefore := machines.HasProvisionedBefore(v.config)
	folders := machines.ProvisionerFolders(v.provisioner)
	syncbackFolders := machines.SyncbackFolders(folders)
	walk, skippedMethods, skippedPlaybooks, _ := planWalk(machine, v, provisionedBefore)
	if len(skippedPlaybooks) > 0 {
		slog.Info("playbooks skipped by run directive",
			"machine", machine.Name, "skipped", len(skippedPlaybooks))
	}

	// FINAL flag: exactly ONE task in the whole chain carries final: true —
	// the walk's overall LAST task in chain order. When the walk is
	// completely empty (no folders, no hooks, no methods), nothing stamps: a
	// document with nothing to execute never marks the machine provisioned.
	// winrm guests skip both folder brackets (no ssh, no rsync/scp — W-Q1..
	// W-Q5), so the final owner accounts for the skipped brackets: the walk's
	// last REAL task carries the stamp. Response-only walk entries (empty
	// operation) never own final.
	isWinRM := v.communicator == "winrm"
	lastRealWalk := -1
	for i := range walk {
		if walk[i].operation != "" {
			lastRealWalk = i
		}
	}
	finalOwner := ""
	switch {
	case len(syncbackFolders) > 0 && !isWinRM:
		finalOwner = "syncback"
	case lastRealWalk >= 0:
		finalOwner = "walk"
	case len(folders) > 0 && !isWinRM:
		finalOwner = "sync"
	}

	// FOLDER SYNC — the walk's opening bracket by document structure: one
	// machine_sync per folders[] entry under the sync sub-parent. winrm
	// guests skip the bracket whole — a RESPONSE-ONLY task_chain[] entry
	// (zoneweaver's exact named shape), never a task.
	if isWinRM && len(folders) > 0 {
		chain = append(chain, map[string]any{
			"step": "sync_skipped_winrm", "folder_count": len(folders),
		})
	}
	if !isWinRM && len(folders) > 0 {
		parentMeta, merr := json.Marshal(map[string]any{"total_folders": len(folders)})
		if merr != nil {
			return nil, nil, merr
		}
		metadata := string(parentMeta)
		syncParent, serr := s.createChainTask(ctx, machine.Name, machines.OpSyncParent,
			&metadata, previous, parentID, createdBy)
		if serr != nil {
			return nil, nil, serr
		}
		chain = append(chain, map[string]any{
			"step": "sync_parent", "task_id": syncParent.ID, "folder_count": len(folders),
		})
		childPrevious := &syncParent.ID
		for i := range folders {
			extra := map[string]any{"folder": folders[i]}
			if finalOwner == "sync" && i == len(folders)-1 {
				extra["final"] = true
			}
			folderMeta, ferr := childMetadata(v, extra)
			if ferr != nil {
				return nil, nil, ferr
			}
			child, cerr := s.createChainTask(ctx, machine.Name, machines.OpSyncFolder,
				folderMeta, childPrevious, syncParent.ID, createdBy)
			if cerr != nil {
				return nil, nil, cerr
			}
			childPrevious = &child.ID
		}
		// The next chain element gates on the LAST sync child, not the sync
		// parent: the parent anchor completes instantly, so depending on it
		// let a playbook overtake the folder syncs (runtime-proven
		// 2026-07-07 — "playbook not found" while its sync was still
		// running). The base carries the same latent hazard, masked only by
		// its ordering luck — flagged in the sync for the zoneweaver session.
		previous = childPrevious
	}

	// pre[] hooks → methods → post[] hooks: DIRECT children of the
	// orchestration parent, one linear chain in document order. Response-only
	// entries (winrm skips, method_not_executable) land in task_chain[] at
	// their document position and never become tasks.
	for i := range walk {
		if walk[i].operation == "" {
			entry := map[string]any{"step": walk[i].step}
			for key, value := range walk[i].stepInfo {
				entry[key] = value
			}
			chain = append(chain, entry)
			continue
		}
		extra := walk[i].extra
		if finalOwner == "walk" && i == lastRealWalk {
			extra["final"] = true
		}
		stepMeta, ferr := childMetadata(v, extra)
		if ferr != nil {
			return nil, nil, ferr
		}
		child, cerr := s.createChainTask(ctx, machine.Name, walk[i].operation,
			stepMeta, previous, parentID, createdBy)
		if cerr != nil {
			return nil, nil, cerr
		}
		if walk[i].step != "" {
			entry := map[string]any{"step": walk[i].step, "task_id": child.ID}
			for key, value := range walk[i].stepInfo {
				entry[key] = value
			}
			chain = append(chain, entry)
		}
		previous = &child.ID
	}

	// SYNCBACK (folders[].syncback — Mark's ruling 2026-07-12, replacing his
	// Hosts.rb results hack) — the walk's closing bracket by document
	// structure: one machine_syncback per flagged folder under the syncback
	// sub-parent, gated on the previous chain element. winrm guests skip the
	// bracket whole — response-only, like the opening one.
	if isWinRM && len(syncbackFolders) > 0 {
		chain = append(chain, map[string]any{
			"step": "syncback_skipped_winrm", "folder_count": len(syncbackFolders),
		})
	}
	if !isWinRM {
		if syncbackChain, serr := s.buildSyncbackChain(ctx, machine.Name, v,
			previous, parentID, createdBy, finalOwner == "syncback"); serr != nil {
			return nil, nil, serr
		} else if syncbackChain != nil {
			chain = append(chain, syncbackChain...)
		}
	}

	// The narrate-skip and run-directive records land on the orchestration
	// parent's metadata (the POST /provision response carries them too).
	if len(skippedMethods) > 0 || len(skippedPlaybooks) > 0 {
		doc := map[string]any{"ip": v.ip, "port": v.port}
		if len(skippedMethods) > 0 {
			doc["skipped_methods"] = skippedMethods
		}
		if len(skippedPlaybooks) > 0 {
			doc["skipped_playbooks"] = skippedPlaybooks
		}
		raw, merr := json.Marshal(doc)
		if merr != nil {
			return nil, nil, merr
		}
		if uerr := s.tasks.Store().UpdateMetadata(ctx, parentID, string(raw)); uerr != nil {
			slog.Warn("record walk skips on orchestration parent",
				"task_id", parentID, "error", uerr)
		}
	}
	return chain, skippedMethods, nil
}

// buildSyncbackChain queues the syncback parent + one machine_syncback child
// per flagged folder (nil when the document flags none). Shared by the
// provision walk's closing bracket and the ad-hoc sync handler. stampFinal
// marks the LAST child final: true — the whole-walk stamp rides it when the
// syncback closes a provision walk; the ad-hoc handler never stamps.
func (s *Server) buildSyncbackChain(ctx context.Context, machineName string,
	v *provisionValidation, previous *string, parentID, createdBy string, stampFinal bool,
) ([]map[string]any, error) {
	syncbackFolders := machines.SyncbackFolders(machines.ProvisionerFolders(v.provisioner))
	if len(syncbackFolders) == 0 {
		return nil, nil
	}
	parentMeta, err := json.Marshal(map[string]any{"total_folders": len(syncbackFolders)})
	if err != nil {
		return nil, err
	}
	metadata := string(parentMeta)
	syncbackParent, err := s.createChainTask(ctx, machineName, machines.OpSyncbackParent,
		&metadata, previous, parentID, createdBy)
	if err != nil {
		return nil, err
	}
	childPrevious := &syncbackParent.ID
	for i := range syncbackFolders {
		extra := map[string]any{"folder": syncbackFolders[i]}
		if stampFinal && i == len(syncbackFolders)-1 {
			extra["final"] = true
		}
		folderMeta, ferr := childMetadata(v, extra)
		if ferr != nil {
			return nil, ferr
		}
		child, cerr := s.createChainTask(ctx, machineName, machines.OpSyncbackFolder,
			folderMeta, childPrevious, syncbackParent.ID, createdBy)
		if cerr != nil {
			return nil, cerr
		}
		childPrevious = &child.ID
	}
	// last_task_id = the LAST child — the chain's true tail (the parent
	// anchor completes instantly); the response reports it.
	return []map[string]any{{
		"step": "syncback_parent", "task_id": syncbackParent.ID,
		"folder_count": len(syncbackFolders), "last_task_id": *childPrevious,
	}}, nil
}

// startProvisionPipeline creates the provision orchestration parent and its
// chain — handleProvisionMachine's core, shared with the provision-on-start
// hook (machines.provision_on_start). A chain-build failure cancels the
// half-built parent before the error returns.
func (s *Server) startProvisionPipeline(ctx context.Context, machine *machines.Machine,
	validation *provisionValidation, skipBoot bool, createdBy string,
) (parentID string, chain []map[string]any, skippedMethods []string, err error) {
	metadata, err := json.Marshal(map[string]any{
		"ip": validation.ip, "port": validation.port,
	})
	if err != nil {
		return "", nil, nil, err
	}
	metadataStr := string(metadata)
	parent, err := s.tasks.Store().Create(ctx, &tasks.NewTask{
		MachineName: machine.Name,
		Operation:   machines.OpProvisionOrchestration,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   createdBy,
		Metadata:    &metadataStr,
		Parent:      true,
	})
	if err != nil {
		return "", nil, nil, err
	}

	chain, skippedMethods, err = s.buildProvisionChain(ctx, machine, validation, skipBoot, parent.ID, createdBy)
	if err != nil {
		if _, cerr := s.tasks.Cancel(ctx, parent.ID); cerr != nil {
			slog.Warn("cancel half-built provision chain", "task_id", parent.ID, "error", cerr)
		}
		return "", nil, nil, err
	}
	return parent.ID, chain, skippedMethods, nil
}

// provisionOnStartPipeline queues the full provision pipeline for a start
// request when machines.provision_on_start applies — the machine's VERY
// FIRST start only (Mark's semantics 2026-07-07): a stored provisioner
// document, never provisioned. Anything that disqualifies the machine (no
// document, already provisioned, no transport, chain failure) answers false
// and the caller boots plainly — auto-provisioning must never block a start.
func (s *Server) provisionOnStartPipeline(ctx context.Context, machine *machines.Machine,
	createdBy string,
) (parentID string, ok bool) {
	if !s.cfg.Machines.ProvisionOnStart {
		return "", false
	}
	validation, problem := validateProvisionRequest(machine)
	if problem != "" {
		slog.Info("provision_on_start skipped — plain start queued",
			"machine", machine.Name, "reason", problem)
		return "", false
	}
	if machines.HasProvisionedBefore(validation.config) {
		return "", false
	}
	if problem := resolveTransport(ctx, machine, validation); problem != "" {
		slog.Info("provision_on_start skipped — plain start queued",
			"machine", machine.Name, "reason", problem)
		return "", false
	}
	// Host-hooks confirmation is an INTERACTIVE gate — auto-provisioning
	// never answers it, so the machine boots plainly and POST /provision
	// carries the confirmation flow.
	if problem, needsConfirmation := s.hostHooksPreflight(ctx, machine,
		validation, false); problem != "" || needsConfirmation {
		slog.Info("provision_on_start skipped — plain start queued (host hooks need confirmation or the gate is off)",
			"machine", machine.Name)
		return "", false
	}
	parent, _, _, err := s.startProvisionPipeline(ctx, machine, validation, false, createdBy)
	if err != nil {
		slog.Error("provision_on_start pipeline failed — plain start queued",
			"machine", machine.Name, "error", err)
		return "", false
	}
	slog.Info("provision_on_start: first start runs the provision pipeline",
		"machine", machine.Name, "parent_task_id", parent)
	return parent, true
}

// handleProvisionMachine starts the provisioning pipeline (provisionZone).
func (s *Server) handleProvisionMachine(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	var body struct {
		SkipBoot bool `json:"skip_boot"`
		// ConfirmHostHooks answers the one-time host-hooks confirmation
		// (design §5): true on the retry records it per machine and proceeds.
		ConfirmHostHooks bool `json:"confirm_host_hooks"`
	}
	if r.ContentLength > 0 {
		if err := decodeBody(r, &body); err != nil {
			taskError(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
	}
	validation, problem := validateProvisionRequest(machine)
	if problem != "" {
		taskError(w, http.StatusBadRequest, problem)
		return
	}
	if problem := resolveTransport(r.Context(), machine, validation); problem != "" {
		taskError(w, http.StatusBadRequest, problem)
		return
	}
	// Host-hooks pre-flight (design §5's ruled shape): the refusal is UP
	// FRONT and clearly needs-confirmation — never a mid-sequence failure.
	if problem, needsConfirmation := s.hostHooksPreflight(r.Context(), machine,
		validation, body.ConfirmHostHooks); problem != "" {
		taskError(w, http.StatusBadRequest, problem)
		return
	} else if needsConfirmation {
		writeJSONStatus(w, http.StatusConflict, map[string]any{
			"needs_confirmation": true,
			"reason":             "This machine's document carries host-target sequence hooks from a NON-SEEDED package — they run scripts on the agent host itself",
			"confirm_with":       `re-POST with {"confirm_host_hooks": true} (recorded once per machine)`,
		})
		return
	}

	createdBy := auth.FromContext(r.Context()).Name
	parentID, chain, skippedMethods, err := s.startProvisionPipeline(r.Context(), machine,
		validation, body.SkipBoot, createdBy)
	if err != nil {
		slog.Error("start provision pipeline", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to start provisioning pipeline")
		return
	}

	response := map[string]any{
		"success":        true,
		"message":        "Provisioning pipeline started for " + machine.Name,
		"machine_name":   machine.Name,
		"parent_task_id": parentID,
		"steps":          len(chain),
		"task_chain":     chain,
	}
	// The QG2 narrate-skip: unknown provisioning: method keys are named
	// loudly, never a failure.
	if len(skippedMethods) > 0 {
		response["skipped_methods"] = skippedMethods
	}
	writeJSON(w, response)
}

// handleSyncMachine creates the ad-hoc parentless sync chain (syncZone).
// Body {"syncback": true} reverses it: ONLY the syncback-flagged folders
// pull guest→host (folders[].syncback — the on-demand half of Mark's ruling
// 2026-07-12; the plain call stays host→guest for every folder).
func (s *Server) handleSyncMachine(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	var body struct {
		Syncback bool `json:"syncback"`
	}
	if r.ContentLength > 0 {
		if err := decodeBody(r, &body); err != nil {
			taskError(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
	}
	validation, problem := validateProvisionRequest(machine)
	if problem != "" {
		taskError(w, http.StatusBadRequest, problem)
		return
	}
	// /sync's winrm gate is a pre-flight 400 (W-Q1..W-Q5): folders only ride
	// ssh transports. Shadowed keys LOG only here — /sync has no task_chain.
	if len(validation.shadowedKeys) > 0 {
		slog.Warn("communicator keys shadowed by their new spellings",
			"machine", machine.Name, "keys", validation.shadowedKeys)
	}
	if validation.communicator == "winrm" {
		taskError(w, http.StatusBadRequest,
			"Folder sync needs ssh (rsync/scp) — this machine uses the winrm communicator, which cannot carry folders")
		return
	}
	if problem := resolveTransport(r.Context(), machine, validation); problem != "" {
		taskError(w, http.StatusBadRequest, problem)
		return
	}
	if body.Syncback {
		createdBy := auth.FromContext(r.Context()).Name
		// stampFinal false: an ad-hoc syncback is never a provision walk.
		chain, serr := s.buildSyncbackChain(r.Context(), machine.Name, validation,
			nil, "", createdBy, false)
		if serr != nil {
			slog.Error("create syncback chain", "machine", machine.Name, "error", serr)
			taskError(w, http.StatusInternalServerError, "Failed to create syncback task chain")
			return
		}
		if chain == nil {
			taskError(w, http.StatusBadRequest,
				"No folders are flagged syncback: true in provisioner metadata")
			return
		}
		writeJSON(w, map[string]any{
			"success":        true,
			"message":        "Machine syncback task chain created for " + machine.Name,
			"machine_name":   machine.Name,
			"parent_task_id": chain[0]["task_id"],
			"folder_count":   chain[0]["folder_count"],
		})
		return
	}
	folders := machines.ProvisionerFolders(validation.provisioner)
	if len(folders) == 0 {
		taskError(w, http.StatusBadRequest, "No folders configured in provisioner metadata")
		return
	}

	createdBy := auth.FromContext(r.Context()).Name
	parentMeta, err := json.Marshal(map[string]any{"total_folders": len(folders)})
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to create sync task chain")
		return
	}
	metadata := string(parentMeta)
	syncParent, err := s.createChainTask(r.Context(), machine.Name, machines.OpSyncParent,
		&metadata, nil, "", createdBy)
	if err != nil {
		slog.Error("create sync parent", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to create sync task chain")
		return
	}
	previous := &syncParent.ID
	for i := range folders {
		folderMeta, ferr := childMetadata(validation, map[string]any{"folder": folders[i]})
		if ferr != nil {
			taskError(w, http.StatusInternalServerError, "Failed to create sync task chain")
			return
		}
		child, cerr := s.createChainTask(r.Context(), machine.Name, machines.OpSyncFolder,
			folderMeta, previous, syncParent.ID, createdBy)
		if cerr != nil {
			slog.Error("create sync child", "machine", machine.Name, "error", cerr)
			taskError(w, http.StatusInternalServerError, "Failed to create sync task chain")
			return
		}
		previous = &child.ID
	}

	writeJSON(w, map[string]any{
		"success":        true,
		"message":        "Machine sync task chain created for " + machine.Name,
		"machine_name":   machine.Name,
		"parent_task_id": syncParent.ID,
		"folder_count":   len(folders),
	})
}

// handleRunProvisioners runs the SAME document walk ad-hoc — minus
// prepare/boot/wait_ssh/sync/syncback — under ONE machine_provision_parent
// anchor (its only surviving role): pre[] hooks → the provisioning: methods
// in stored-document key order → post[] hooks; the last planned child
// carries the whole-walk stamp. Nothing configured is a 400; everything
// run-skipped answers a 200 no-op with the skipped list.
func (s *Server) handleRunProvisioners(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	validation, problem := validateProvisionRequest(machine)
	if problem != "" {
		taskError(w, http.StatusBadRequest, problem)
		return
	}
	if problem := resolveTransport(r.Context(), machine, validation); problem != "" {
		taskError(w, http.StatusBadRequest, problem)
		return
	}
	walk, skippedMethods, skippedPlaybooks, playbookCount := planWalk(machine, validation,
		machines.HasProvisionedBefore(validation.config))

	// task_chain[] mirrors the provision response's channel (W-Q1..W-Q5):
	// shadowed-key narration first, then the labeled/skip entries as the
	// walk lands them.
	taskChain := []map[string]any{}
	if len(validation.shadowedKeys) > 0 {
		slog.Warn("communicator keys shadowed by their new spellings",
			"machine", machine.Name, "keys", validation.shadowedKeys)
		taskChain = append(taskChain, map[string]any{
			"step": "communicator_keys_shadowed", "keys": validation.shadowedKeys,
		})
	}
	lastRealWalk := -1
	for i := range walk {
		if walk[i].operation != "" {
			lastRealWalk = i
		}
	}
	if lastRealWalk < 0 {
		// Nothing executable. Response-only entries (winrm skips) still
		// answer a 200 no-op with the narration; the run-directive no-op and
		// the plain 400 keep their existing branches.
		for i := range walk {
			entry := map[string]any{"step": walk[i].step}
			for key, value := range walk[i].stepInfo {
				entry[key] = value
			}
			taskChain = append(taskChain, entry)
		}
		if len(skippedPlaybooks) > 0 || len(walk) > 0 {
			response := map[string]any{
				"success":           true,
				"machine_name":      machine.Name,
				"message":           "All configured playbooks were skipped by their run directives",
				"playbooks_skipped": skippedPlaybooks,
			}
			if len(walk) > 0 {
				response["message"] = "Nothing is executable on this machine's communicator — see task_chain"
			}
			if len(taskChain) > 0 {
				response["task_chain"] = taskChain
			}
			if len(skippedMethods) > 0 {
				response["skipped_methods"] = skippedMethods
			}
			writeJSON(w, response)
			return
		}
		taskError(w, http.StatusBadRequest, "No provisioners configured in provisioner metadata")
		return
	}

	createdBy := auth.FromContext(r.Context()).Name
	parentDoc := map[string]any{
		"total_playbooks":   playbookCount,
		"skipped_playbooks": skippedPlaybooks,
	}
	if len(skippedMethods) > 0 {
		parentDoc["skipped_methods"] = skippedMethods
	}
	parentMeta, err := json.Marshal(parentDoc)
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to create provisioner tasks")
		return
	}
	metadata := string(parentMeta)
	provisionParent, err := s.createChainTask(r.Context(), machine.Name,
		machines.OpProvisionParent, &metadata, nil, "", createdBy)
	if err != nil {
		slog.Error("create provision parent", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to create provisioner tasks")
		return
	}
	previous := &provisionParent.ID
	for i := range walk {
		if walk[i].operation == "" {
			// Response-only entries (winrm skips, method_not_executable) —
			// task_chain[] at document position, never tasks.
			entry := map[string]any{"step": walk[i].step}
			for key, value := range walk[i].stepInfo {
				entry[key] = value
			}
			taskChain = append(taskChain, entry)
			continue
		}
		extra := walk[i].extra
		if i == lastRealWalk {
			// The walk's last REAL child carries the whole-walk stamp —
			// response-only entries never own final.
			extra["final"] = true
		}
		stepMeta, ferr := childMetadata(validation, extra)
		if ferr != nil {
			taskError(w, http.StatusInternalServerError, "Failed to create provisioner tasks")
			return
		}
		child, cerr := s.createChainTask(r.Context(), machine.Name, walk[i].operation,
			stepMeta, previous, provisionParent.ID, createdBy)
		if cerr != nil {
			slog.Error("create provision child", "machine", machine.Name, "error", cerr)
			taskError(w, http.StatusInternalServerError, "Failed to create provisioner tasks")
			return
		}
		if walk[i].step != "" {
			entry := map[string]any{"step": walk[i].step, "task_id": child.ID}
			for key, value := range walk[i].stepInfo {
				entry[key] = value
			}
			taskChain = append(taskChain, entry)
		}
		previous = &child.ID
	}

	response := map[string]any{
		"success":           true,
		"machine_name":      machine.Name,
		"parent_task_id":    provisionParent.ID,
		"playbook_count":    playbookCount,
		"playbooks_skipped": skippedPlaybooks,
	}
	if len(taskChain) > 0 {
		response["task_chain"] = taskChain
	}
	if len(skippedMethods) > 0 {
		response["skipped_methods"] = skippedMethods
	}
	writeJSON(w, response)
}

// handleProvisionStatus reports the pipeline state (getProvisioningStatus):
// configured flag, provisioned|not_started, last_provisioned_at, and the 20
// most recent provisioning tasks.
func (s *Server) handleProvisionStatus(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	config := machines.ParseConfiguration(machine)
	state := config.Section("provisioner_state")
	lastProvisioned, _ := state["last_provisioned_at"].(string)

	recent := []*tasks.Task{}
	for _, operation := range []string{
		machines.OpProvisionOrchestration, machines.OpPrepare, machines.OpWaitSSH,
		machines.OpSyncParent, machines.OpSyncFolder,
		machines.OpShellScript,
		machines.OpProvisionParent, machines.OpProvisionPlaybook,
		machines.OpRemotePlaybook, machines.OpDockerCompose,
		machines.OpSyncbackParent, machines.OpSyncbackFolder,
		machines.OpHook,
	} {
		filter := tasks.ListFilter{MachineName: machine.Name, Operation: operation, Limit: 20}
		list, err := s.tasks.Store().List(r.Context(), &filter)
		if err != nil {
			slog.Warn("list provisioning tasks", "machine", machine.Name, "error", err)
			continue
		}
		recent = append(recent, list...)
	}
	if len(recent) > 20 {
		recent = recent[:20]
	}

	status := "not_started"
	if lastProvisioned != "" {
		status = "provisioned"
	}
	writeJSON(w, map[string]any{
		"success":                 true,
		"machine_name":            machine.Name,
		"provisioning_configured": len(config.Provisioner()) > 0,
		"provisioning_status":     status,
		"last_provisioned_at":     nullableString(lastProvisioned),
		"recent_tasks":            recent,
	})
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// handleListTemplates lists the local box-template registry.
func (s *Server) handleListTemplates(w http.ResponseWriter, r *http.Request) {
	list, err := s.machines.ListTemplates(r.Context())
	if err != nil {
		slog.Error("list templates", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to retrieve templates")
		return
	}
	writeJSON(w, map[string]any{
		"templates": list,
		"total":     len(list),
	})
}

// handleGetTemplate serves one local template row (the base's GET
// /templates/local/{id}).
func (s *Server) handleGetTemplate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("templateId"), 10, 64)
	if err != nil {
		taskError(w, http.StatusNotFound, "Template not found")
		return
	}
	template, err := s.machines.GetTemplate(r.Context(), id)
	if errors.Is(err, machines.ErrTemplateNotFound) {
		taskError(w, http.StatusNotFound, "Template not found")
		return
	}
	if err != nil {
		slog.Error("get template", "id", id, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to retrieve template details")
		return
	}
	writeJSON(w, template)
}

// handleDeleteTemplate queues a template_delete task (the base's DELETE
// /templates/local/{id}: remove the stored artifact + the row, async).
func (s *Server) handleDeleteTemplate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("templateId"), 10, 64)
	if err != nil {
		taskError(w, http.StatusNotFound, "Template not found")
		return
	}
	template, err := s.machines.GetTemplate(r.Context(), id)
	if errors.Is(err, machines.ErrTemplateNotFound) {
		taskError(w, http.StatusNotFound, "Template not found")
		return
	}
	if err != nil {
		slog.Error("get template for delete", "id", id, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to create delete task")
		return
	}

	raw, err := json.Marshal(map[string]int64{"template_id": template.ID})
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to create delete task")
		return
	}
	metadata := string(raw)
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: "system",
		Operation:   machines.OpTemplateDelete,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   auth.FromContext(r.Context()).Name,
		Metadata:    &metadata,
	})
	if err != nil {
		slog.Error("queue template delete", "id", id, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to create delete task")
		return
	}
	acceptedTask(w, task.ID, "Delete task created for template "+template.BoxName)
}

// handleExportTemplate queues a template_export task (the base's POST
// /templates/export: machine → local .box; here VBoxManage export + tar.gz →
// a standard Vagrant virtualbox box under <templates root>/exports).
func (s *Server) handleExportTemplate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		MachineName string `json:"machine_name"`
		Filename    string `json:"filename"`
	}
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.MachineName == "" {
		taskError(w, http.StatusBadRequest, "machine_name is required")
		return
	}
	machine, err := s.machines.Get(r.Context(), body.MachineName)
	if errors.Is(err, machines.ErrNotFound) {
		taskError(w, http.StatusNotFound, "Machine not found")
		return
	}
	if err != nil {
		slog.Error("load machine for export", "machine", body.MachineName, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to create export task")
		return
	}

	raw, err := json.Marshal(map[string]string{"filename": body.Filename})
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to create export task")
		return
	}
	metadata := string(raw)
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: machine.Name,
		Operation:   machines.OpTemplateExport,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   auth.FromContext(r.Context()).Name,
		Metadata:    &metadata,
	})
	if err != nil {
		slog.Error("queue template export", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to create export task")
		return
	}
	acceptedTask(w, task.ID, "Export task created for machine "+machine.Name)
}

// handlePublishTemplate queues a template_upload task (the base's POST
// /templates/publish: machine export OR existing .box → chunked registry
// upload → release). Registry credentials live on the configured source only
// — the base's per-request auth_token has no analog here (tokens never ride
// task metadata).
func (s *Server) handlePublishTemplate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		MachineName  string `json:"machine_name"`
		BoxPath      string `json:"box_path"`
		SourceName   string `json:"source_name"`
		Organization string `json:"organization"`
		BoxName      string `json:"box_name"`
		Version      string `json:"version"`
		Description  string `json:"description"`
		Architecture string `json:"architecture"`
	}
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if (body.MachineName == "" && body.BoxPath == "") || body.SourceName == "" ||
		body.Organization == "" || body.BoxName == "" || body.Version == "" {
		taskError(w, http.StatusBadRequest, "Missing required fields")
		return
	}
	taskMachine := "system"
	if body.MachineName != "" {
		machine, err := s.machines.Get(r.Context(), body.MachineName)
		if errors.Is(err, machines.ErrNotFound) {
			taskError(w, http.StatusNotFound, "Machine not found")
			return
		}
		if err != nil {
			slog.Error("load machine for publish", "machine", body.MachineName, "error", err)
			taskError(w, http.StatusInternalServerError, "Failed to create publish task")
			return
		}
		taskMachine = machine.Name
	}

	raw, err := json.Marshal(map[string]string{
		"machine_name": body.MachineName,
		"box_path":     body.BoxPath,
		"source_name":  body.SourceName,
		"organization": body.Organization,
		"box_name":     body.BoxName,
		"version":      body.Version,
		"description":  body.Description,
		"architecture": body.Architecture,
	})
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to create publish task")
		return
	}
	metadata := string(raw)
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: taskMachine,
		Operation:   machines.OpTemplatePublish,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   auth.FromContext(r.Context()).Name,
		Metadata:    &metadata,
	})
	if err != nil {
		slog.Error("queue template publish", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to create publish task")
		return
	}
	acceptedTask(w, task.ID, "Publish task created for "+body.Organization+"/"+body.BoxName)
}

// handleMoveTemplate queues a template_move task (the base's POST
// /templates/local/{id}/move: relocate the stored artifact — file move here,
// zfs rename/send-recv there).
func (s *Server) handleMoveTemplate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("templateId"), 10, 64)
	if err != nil {
		taskError(w, http.StatusNotFound, "Template not found")
		return
	}
	var body struct {
		TargetPath string `json:"target_path"`
	}
	if derr := decodeBody(r, &body); derr != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.TargetPath == "" {
		taskError(w, http.StatusBadRequest, "target_path is required")
		return
	}
	template, err := s.machines.GetTemplate(r.Context(), id)
	if errors.Is(err, machines.ErrTemplateNotFound) {
		taskError(w, http.StatusNotFound, "Template not found")
		return
	}
	if err != nil {
		slog.Error("get template for move", "id", id, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to create move task")
		return
	}

	raw, err := json.Marshal(map[string]any{
		"template_id": template.ID,
		"target_path": body.TargetPath,
	})
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to create move task")
		return
	}
	metadata := string(raw)
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: "system",
		Operation:   machines.OpTemplateMove,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   auth.FromContext(r.Context()).Name,
		Metadata:    &metadata,
	})
	if err != nil {
		slog.Error("queue template move", "id", id, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to create move task")
		return
	}
	acceptedTask(w, task.ID, "Move task created for template "+template.BoxName)
}

// handlePullTemplate queues a template_download task (the base's
// /templates/pull): the caller names the source (or the default is used) and
// the exact box tuple.
func (s *Server) handlePullTemplate(w http.ResponseWriter, r *http.Request) {
	var meta machines.TemplateDownloadMetadata
	if err := decodeBody(r, &meta); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if meta.Organization == "" || meta.BoxName == "" || meta.Version == "" ||
		meta.Version == "latest" {
		taskError(w, http.StatusBadRequest,
			"organization, box_name, and a specific version are required")
		return
	}
	if meta.SourceName == "" {
		source, serr := machines.FindTemplateSourceForURL(s.templateSources(), "")
		if serr != nil {
			taskError(w, http.StatusBadRequest, serr.Error())
			return
		}
		meta.SourceName = source.Name
	}
	meta.Provider = machines.TemplateProvider
	// Already-exists pre-check (the base's rule, mirrored 2026-07-12): answer
	// an honest 409 with the existing row instead of queueing a download the
	// executor would no-op. FindTemplate self-heals stale rows (disk image
	// deleted by hand), so a re-pull after manual cleanup still works.
	existing, ferr := s.machines.FindTemplate(r.Context(), meta.Organization,
		meta.BoxName, meta.Version, meta.Architecture)
	switch {
	case ferr == nil:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		if werr := json.NewEncoder(w).Encode(map[string]any{
			"error":       "Template already exists locally",
			"template_id": existing.ID,
		}); werr != nil {
			slog.Error("write template conflict response", "error", werr)
		}
		return
	case !errors.Is(ferr, machines.ErrTemplateNotFound):
		slog.Error("check existing template", "error", ferr)
		taskError(w, http.StatusInternalServerError, "Failed to queue template download")
		return
	}
	raw, err := json.Marshal(&meta)
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to queue template download")
		return
	}
	metadata := string(raw)
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: "system",
		Operation:   machines.OpTemplateDownload,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   auth.FromContext(r.Context()).Name,
		Metadata:    &metadata,
	})
	if err != nil {
		slog.Error("queue template download", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue template download")
		return
	}
	acceptedTask(w, task.ID, "Template download task queued successfully")
}
