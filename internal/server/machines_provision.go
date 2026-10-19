package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/certs"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/provisioner"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// The provisioning surface — POST /api/machines/{name}/provision runs the ONE
// document walk (Mark's ruling 2026-07-17: THERE ARE NO PHASES — the stored
// provisioner document is the program, executed AS WRITTEN): extract → boot
// → wait_ssh → folder sync → pre[] hooks → the provisioning: methods in
// stored-document KEY ORDER (each method's entries in list order) → post[]
// hooks → syncback. /sync is the ad-hoc folder slice; /run-provisioners is
// the SAME walk minus prepare/boot/wait_ssh/sync/syncback;
// /provision/status reports the pipeline's state.

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
	credentialID string
	communicator string
	winrm        machines.WinRMSettings
	shadowedKeys []string
}

// walkNarrow is a provision run narrowed to part of the document: the roles, the shell scripts or the one playbook a body names.
type walkNarrow struct {
	roles    []string
	scripts  []string
	playbook string
}

// validateProvisionRequest ports validateProvisioningRequest: provisioner
// config stored (else "set via PUT first"), settings present, a username from
// the machine's vagrant credential or settings.vagrant_user, control IP
// resolvable. The communicator resolves at READ time through the hostdoc
// alias reader — stored documents never rewrite.
func (s *Server) validateProvisionRequest(ctx context.Context, machine *machines.Machine) (validation *provisionValidation, problem string) {
	config := machines.ParseConfiguration(machine)
	provisionerDoc := config.Provisioner()
	if len(provisionerDoc) == 0 {
		return nil, "No provisioner configuration found. Set provisioner config via PUT /api/machines/{name} first."
	}
	settings := config.Section("settings")
	if len(settings) == 0 {
		return nil, "Machine configuration has no settings section (Hosts.yml structure required)"
	}
	credentials := machines.ExtractCredentials(settings)
	credentialID := ""
	if row, rerr := s.pickCredential(ctx, machine, certs.Reader{Admin: true}, "vagrant", ""); rerr != nil {
		return nil, "The machine's vagrant credential " + rerr.Error()
	} else if row != nil {
		if user := machines.CredentialUsername(row); user != "" {
			credentials.Username = user
		}
		credentialID = row.ID
	}
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
		ip: ip, port: port, credentials: credentials, credentialID: credentialID,
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
	if v.credentialID != "" {
		doc["credential_id"] = v.credentialID
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
	stepInfo  taskChainEntry
}

type taskChainEntry struct {
	Step          string   `json:"step"`
	TaskID        string   `json:"task_id,omitempty"`
	LastTaskID    string   `json:"last_task_id,omitempty"`
	Keys          []string `json:"keys,omitempty"`
	FolderCount   int      `json:"folder_count,omitempty"`
	HookCount     int      `json:"hook_count,omitempty"`
	ScriptCount   int      `json:"script_count,omitempty"`
	ComposeCount  int      `json:"compose_count,omitempty"`
	PlaybookCount int      `json:"playbook_count,omitempty"`
	Method        string   `json:"method,omitempty"`
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
			step.stepInfo = taskChainEntry{HookCount: len(hooks)}
		}
		steps = append(steps, step)
	}
	return steps
}

// playbookSteps plans one playbook batch — entries exactly as the document
// lists them: the list an entry sits in (local | remote) picks its execution
// mechanism, never its position; roles, when given, narrow every entry's run to those document roles.
func playbookSteps(playbooks []machines.Playbook, roles []string) []walkStep {
	steps := make([]walkStep, 0, len(playbooks))
	for i := range playbooks {
		operation := machines.OpProvisionPlaybook
		if playbooks[i].Remote {
			operation = machines.OpRemotePlaybook
		}
		extra := map[string]any{"playbook": playbooks[i]}
		if len(roles) > 0 {
			extra["roles"] = roles
		}
		step := walkStep{operation: operation, extra: extra}
		if i == 0 {
			step.step = "method:ansible"
			step.stepInfo = taskChainEntry{PlaybookCount: len(playbooks)}
		}
		steps = append(steps, step)
	}
	return steps
}

// narrowPlaybooks keeps the playbooks a narrowed run names: the one playbook when the body names one, every entry when it names roles alone.
func narrowPlaybooks(playbooks []machines.Playbook, narrow *walkNarrow) []machines.Playbook {
	if narrow == nil || narrow.playbook == "" {
		return playbooks
	}
	kept := []machines.Playbook{}
	for i := range playbooks {
		if playbooks[i].Playbook == narrow.playbook {
			kept = append(kept, playbooks[i])
		}
	}
	return kept
}

// narrowScripts keeps the shell scripts a narrowed run names; a narrowed run naming none runs no script.
func narrowScripts(scripts []string, narrow *walkNarrow) []string {
	if narrow == nil {
		return scripts
	}
	wanted := map[string]bool{}
	for _, script := range narrow.scripts {
		wanted[script] = true
	}
	kept := []string{}
	for _, script := range scripts {
		if wanted[script] {
			kept = append(kept, script)
		}
	}
	return kept
}

// winnowLocalPlaybooksForWinRM drops the LOCAL playbooks from a
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
			stepInfo: taskChainEntry{PlaybookCount: localCount},
		})
	}
	return remote, methods
}

// planWalk plans the document walk's direct children: pre[] hooks, then the
// provisioning: methods in the order their KEYS APPEAR in the stored document
// (each method's entries in list order — Mark's ruling: there are no phases,
// the document executes AS WRITTEN), then post[] hooks; every entry runs on
// every explicit run, the document's run directives never thin a Provision
// press. A narrowed run keeps the shell scripts, the playbook or the roles the
// body names and drops the hooks and the docker entries. sync/syncback are the
// walk's outer brackets and ride their own sub-parents. Unknown method keys
// NARRATE-SKIP into skippedMethods — named loudly, never a failure.
func planWalk(machine *machines.Machine, v *provisionValidation, narrow *walkNarrow,
) (walk []walkStep, skippedMethods []string, playbookCount int) {
	if narrow == nil {
		walk = append(walk, hookSteps(machines.ProvisionerHooks(v.provisioner, "pre"), "pre_hooks")...)
	}
	var roles []string
	if narrow != nil {
		roles = narrow.roles
	}

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
			scripts := narrowScripts(machines.ProvisionerShellScripts(v.provisioner), narrow)
			for i, script := range scripts {
				step := walkStep{
					operation: machines.OpShellScript,
					extra:     map[string]any{"script": script},
				}
				if i == 0 {
					step.step = "method:shell"
					step.stepInfo = taskChainEntry{ScriptCount: len(scripts)}
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
			if narrow != nil && narrow.playbook == "" && len(narrow.roles) == 0 {
				continue
			}
			playbooks := narrowPlaybooks(machines.ProvisionerPlaybooks(v.provisioner), narrow)
			playbooks, methods = winnowLocalPlaybooksForWinRM(v, playbooks, methods)
			playbookCount += len(playbooks)
			methods = append(methods, playbookSteps(playbooks, roles)...)
		case "docker":
			enabled, composeFiles := machines.ProvisionerDocker(v.provisioner)
			if !enabled || narrow != nil {
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
					step.stepInfo = taskChainEntry{ComposeCount: len(composeFiles)}
				}
				methods = append(methods, step)
			}
		default:
			// Unknown methods keep skipped_methods (Go's already-shipped
			// wire) PLUS zoneweaver's per-method task_chain[] record.
			skippedMethods = append(skippedMethods, key)
			methods = append(methods, walkStep{
				step:     "method_not_executable",
				stepInfo: taskChainEntry{Method: key},
			})
		}
	}
	// The flat provisioners[] form lives OUTSIDE provisioning: (Hosts.yml's
	// simplest shape) — no method keys, but ProvisionerPlaybooks still
	// answers entries; they plan as the sole method batch. No ansible.enabled
	// gate applies: there is no ansible section.
	if len(methodKeys) == 0 && (narrow == nil || narrow.playbook != "" || len(narrow.roles) > 0) {
		if flat := narrowPlaybooks(machines.ProvisionerPlaybooks(v.provisioner), narrow); len(flat) > 0 {
			var playbooks []machines.Playbook
			playbooks, methods = winnowLocalPlaybooksForWinRM(v, flat, methods)
			playbookCount += len(playbooks)
			methods = append(methods, playbookSteps(playbooks, roles)...)
		}
	}
	walk = append(walk, methods...)

	if narrow == nil {
		walk = append(walk, hookSteps(machines.ProvisionerHooks(v.provisioner, "post"), "post_hooks")...)
	}
	return walk, skippedMethods, playbookCount
}

// narrowOf reads a provision body's narrowing members and checks each against the stored document: the roles against roles[], the scripts against provisioning.shell.scripts, the playbook against the ansible entries; nil when the body narrows nothing.
func narrowOf(body *provisionRequest, v *provisionValidation) (narrow *walkNarrow, problem string) {
	if len(body.Roles) == 0 && len(body.Scripts) == 0 && body.Playbook == "" {
		return nil, ""
	}
	if !machines.HasProvisionedBefore(v.config) {
		return nil, "roles, scripts and playbook narrow a run on a machine that has provisioned once"
	}
	known := map[string]bool{}
	for _, name := range machines.DocumentRoleNames(v.provisioner) {
		known[name] = true
		if dot := strings.LastIndex(name, "."); dot >= 0 {
			known[name[dot+1:]] = true
		}
	}
	for _, role := range body.Roles {
		if !known[role] {
			return nil, "role " + role + " is not a role of the machine's document"
		}
	}
	scripts := map[string]bool{}
	for _, script := range machines.ProvisionerShellScripts(v.provisioner) {
		scripts[script] = true
	}
	for _, script := range body.Scripts {
		if !scripts[script] {
			return nil, "script " + script + " is not one of the document's provisioning.shell.scripts"
		}
	}
	if body.Playbook != "" {
		found := false
		playbooks := machines.ProvisionerPlaybooks(v.provisioner)
		for i := range playbooks {
			if playbooks[i].Playbook == body.Playbook {
				found = true
				break
			}
		}
		if !found {
			return nil, "playbook " + body.Playbook + " is not one of the document's provisioning.playbooks"
		}
	}
	return &walkNarrow{roles: body.Roles, scripts: body.Scripts, playbook: body.Playbook}, ""
}
