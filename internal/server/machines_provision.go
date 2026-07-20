package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"

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
