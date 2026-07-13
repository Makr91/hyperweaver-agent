package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// The provisioning pipeline surface — zoneweaver's
// ProvisioningPipelineController/ProvisioningSyncController/
// ProvisioningProvisionerController + TaskChainBuilder ported: POST
// /machines/{name}/provision orchestrates extract → boot → wait_ssh →
// per-folder sync → run-filtered per-playbook provision against the STORED
// provisioner document; /sync and /run-provisioners are the ad-hoc slices;
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
// result: the stored provisioner document, the control IP, and credentials.
type provisionValidation struct {
	config      machines.MachineConfig
	provisioner map[string]any
	ip          string
	port        int
	credentials machines.Credentials
}

// validateProvisionRequest ports validateProvisioningRequest: provisioner
// config stored (else "set via PUT first"), settings present, vagrant_user
// required, control IP resolvable.
func validateProvisionRequest(machine *machines.Machine) (validation *provisionValidation, problem string) {
	config := machines.ParseConfiguration(machine)
	provisioner := config.Provisioner()
	if len(provisioner) == 0 {
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
	// The control IP is the FALLBACK transport only — resolveTransport
	// prefers the provisioning NIC's ssh port-forward and errors when
	// neither exists.
	ip := machines.ExtractControlIP(config.List("networks"))
	port := 22
	if p, ok := provisioner["ssh_port"].(float64); ok && p > 0 {
		port = int(p)
	}
	return &provisionValidation{
		config: config, provisioner: provisioner,
		ip: ip, port: port, credentials: credentials,
	}, ""
}

// resolveTransport picks the pipeline's SSH target (Mark's architecture,
// 2026-07-07): the provisioning NIC's NAT ssh port-forward first — vagrant's
// model, immune to anything the guest's networking role does to real
// adapters — falling back to the document's control IP for machines without
// a forward (pre-forward creates, user-built VMs).
func resolveTransport(ctx context.Context, machine *machines.Machine, v *provisionValidation) (problem string) {
	if port := machines.FindSSHForward(ctx, machine); port > 0 {
		v.ip, v.port = "127.0.0.1", port
		return ""
	}
	if v.ip == "" {
		return "No SSH transport: machine has no NAT ssh port-forward and no control IP in networks[] (set is_control: true on one network)"
	}
	return ""
}

// childMetadata marshals one provision child's metadata document.
func childMetadata(v *provisionValidation, extra map[string]any) (*string, error) {
	doc := map[string]any{
		"ip":          v.ip,
		"port":        v.port,
		"credentials": v.credentials,
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

// buildProvisionChain ports buildProvisioningTaskChain: extract (our
// machine_prepare — render + materialize, the provisioning-content step) →
// boot (the plain start op as a child when not running) → wait_ssh →
// sync_parent + one machine_sync per folder → provision_parent + one
// machine_provision per run-filtered playbook. Per-machine queue exclusivity
// serializes the chain exactly like the base's one-task-per-zone rule.
func (s *Server) buildProvisionChain(ctx context.Context, machine *machines.Machine,
	v *provisionValidation, skipBoot bool, parentID, createdBy string,
) ([]map[string]any, error) {
	chain := []map[string]any{}
	var previous *string

	// Extract slot: re-render + re-materialize the working copy from the
	// registry package (SHI regenerates before every provision; zoneweaver
	// extracts its artifact here). Only when the spec NAMES a package —
	// provisioner-less machines have nothing to render (their document
	// arrived via PUT and is consumed as stored, the base's model).
	if spec, serr := machines.ParseSpec(machine); serr == nil && spec.HasProvisioner() {
		specMeta, err := json.Marshal(map[string]any{"spec": machine.Spec})
		if err != nil {
			return nil, err
		}
		metadata := string(specMeta)
		task, terr := s.createChainTask(ctx, machine.Name, machines.OpPrepare,
			&metadata, nil, parentID, createdBy)
		if terr != nil {
			return nil, terr
		}
		chain = append(chain, map[string]any{"step": "extract", "task_id": task.ID})
		previous = &task.ID
	}

	// Boot: the plain start operation queued as a child.
	if !skipBoot && machine.Status != machines.StatusRunning {
		task, err := s.createChainTask(ctx, machine.Name, machines.OpStart,
			nil, previous, parentID, createdBy)
		if err != nil {
			return nil, err
		}
		chain = append(chain, map[string]any{"step": "boot", "task_id": task.ID})
		previous = &task.ID
	}

	// Wait for SSH.
	sshMeta, err := childMetadata(v, nil)
	if err != nil {
		return nil, err
	}
	sshTask, err := s.createChainTask(ctx, machine.Name, machines.OpWaitSSH,
		sshMeta, previous, parentID, createdBy)
	if err != nil {
		return nil, err
	}
	chain = append(chain, map[string]any{"step": "wait_ssh", "task_id": sshTask.ID})
	previous = &sshTask.ID

	// Per-folder sync under a sync parent.
	folders := machines.ProvisionerFolders(v.provisioner)
	if len(folders) > 0 {
		parentMeta, merr := json.Marshal(map[string]any{"total_folders": len(folders)})
		if merr != nil {
			return nil, merr
		}
		metadata := string(parentMeta)
		syncParent, serr := s.createChainTask(ctx, machine.Name, machines.OpSyncParent,
			&metadata, previous, parentID, createdBy)
		if serr != nil {
			return nil, serr
		}
		chain = append(chain, map[string]any{
			"step": "sync_parent", "task_id": syncParent.ID, "folder_count": len(folders),
		})
		childPrevious := &syncParent.ID
		for i := range folders {
			folderMeta, ferr := childMetadata(v, map[string]any{"folder": folders[i]})
			if ferr != nil {
				return nil, ferr
			}
			child, cerr := s.createChainTask(ctx, machine.Name, machines.OpSyncFolder,
				folderMeta, childPrevious, syncParent.ID, createdBy)
			if cerr != nil {
				return nil, cerr
			}
			childPrevious = &child.ID
		}
		// The provision phase gates on the LAST sync child, not the sync
		// parent: the parent anchor completes instantly, so depending on it
		// let a playbook overtake the folder syncs (runtime-proven
		// 2026-07-07 — "playbook not found" while its sync was still
		// running). The base carries the same latent hazard, masked only by
		// its ordering luck — flagged in the sync for the zoneweaver session.
		previous = childPrevious
	}

	// Per-playbook provision under a provision parent, run-filtered first.
	playbooks, skipped := machines.FilterPlaybooksByRun(
		machines.ProvisionerPlaybooks(v.provisioner),
		machines.HasProvisionedBefore(v.config))
	if len(skipped) > 0 {
		slog.Info("playbooks skipped by run directive",
			"machine", machine.Name, "skipped", len(skipped))
	}
	if len(playbooks) > 0 {
		parentMeta, merr := json.Marshal(map[string]any{
			"total_playbooks":   len(playbooks),
			"skipped_playbooks": skipped,
		})
		if merr != nil {
			return nil, merr
		}
		metadata := string(parentMeta)
		provisionParent, perr := s.createChainTask(ctx, machine.Name, machines.OpProvisionParent,
			&metadata, previous, parentID, createdBy)
		if perr != nil {
			return nil, perr
		}
		chain = append(chain, map[string]any{
			"step": "provision_parent", "task_id": provisionParent.ID,
			"playbook_count": len(playbooks), "playbooks_skipped": len(skipped),
		})
		childPrevious := &provisionParent.ID
		for i := range playbooks {
			extra := map[string]any{"playbook": playbooks[i]}
			if i == len(playbooks)-1 {
				// The last playbook carries the provisioned-state stamp
				// (Hosts.rb's results.yml semantics — never a partial run).
				extra["final"] = true
			}
			playbookMeta, ferr := childMetadata(v, extra)
			if ferr != nil {
				return nil, ferr
			}
			child, cerr := s.createChainTask(ctx, machine.Name, machines.OpProvisionPlaybook,
				playbookMeta, childPrevious, provisionParent.ID, createdBy)
			if cerr != nil {
				return nil, cerr
			}
			childPrevious = &child.ID
		}
		previous = childPrevious
	}

	// The syncback phase (folders[].syncback — Mark's ruling 2026-07-12,
	// replacing his Hosts.rb results hack): flagged folders pull guest→host
	// AFTER the provision phase — one machine_syncback per flagged folder
	// under a syncback parent, gated on the LAST playbook child (the same
	// last-child rule the provision phase rides).
	if syncbackChain, serr := s.buildSyncbackChain(ctx, machine.Name, v,
		previous, parentID, createdBy); serr != nil {
		return nil, serr
	} else if syncbackChain != nil {
		chain = append(chain, syncbackChain...)
	}
	return chain, nil
}

// buildSyncbackChain queues the syncback parent + one machine_syncback child
// per flagged folder (nil when the document flags none). Shared by the
// provision pipeline's post-provision phase and the ad-hoc sync handler.
func (s *Server) buildSyncbackChain(ctx context.Context, machineName string,
	v *provisionValidation, previous *string, parentID, createdBy string,
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
	chain := []map[string]any{{
		"step": "syncback_parent", "task_id": syncbackParent.ID,
		"folder_count": len(syncbackFolders),
	}}
	childPrevious := &syncbackParent.ID
	for i := range syncbackFolders {
		folderMeta, ferr := childMetadata(v, map[string]any{"folder": syncbackFolders[i]})
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
	return chain, nil
}

// startProvisionPipeline creates the provision orchestration parent and its
// chain — handleProvisionMachine's core, shared with the provision-on-start
// hook (machines.provision_on_start). A chain-build failure cancels the
// half-built parent before the error returns.
func (s *Server) startProvisionPipeline(ctx context.Context, machine *machines.Machine,
	validation *provisionValidation, skipBoot bool, createdBy string,
) (parentID string, chain []map[string]any, err error) {
	metadata, err := json.Marshal(map[string]any{
		"ip": validation.ip, "port": validation.port,
	})
	if err != nil {
		return "", nil, err
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
		return "", nil, err
	}

	chain, err = s.buildProvisionChain(ctx, machine, validation, skipBoot, parent.ID, createdBy)
	if err != nil {
		if _, cerr := s.tasks.Cancel(ctx, parent.ID); cerr != nil {
			slog.Warn("cancel half-built provision chain", "task_id", parent.ID, "error", cerr)
		}
		return "", nil, err
	}
	return parent.ID, chain, nil
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
	parent, _, err := s.startProvisionPipeline(ctx, machine, validation, false, createdBy)
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

	createdBy := auth.FromContext(r.Context()).Name
	parentID, chain, err := s.startProvisionPipeline(r.Context(), machine, validation,
		body.SkipBoot, createdBy)
	if err != nil {
		slog.Error("start provision pipeline", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to start provisioning pipeline")
		return
	}

	writeJSON(w, map[string]any{
		"success":        true,
		"message":        "Provisioning pipeline started for " + machine.Name,
		"machine_name":   machine.Name,
		"parent_task_id": parentID,
		"steps":          len(chain),
		"task_chain":     chain,
	})
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
	if problem := resolveTransport(r.Context(), machine, validation); problem != "" {
		taskError(w, http.StatusBadRequest, problem)
		return
	}
	if body.Syncback {
		createdBy := auth.FromContext(r.Context()).Name
		chain, serr := s.buildSyncbackChain(r.Context(), machine.Name, validation,
			nil, "", createdBy)
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

// handleRunProvisioners runs the run-filtered playbooks ad-hoc
// (runProvisioners): configured-but-empty is a 400, all-skipped answers a
// 200 no-op with the skipped list.
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
	configured := machines.ProvisionerPlaybooks(validation.provisioner)
	if len(configured) == 0 {
		taskError(w, http.StatusBadRequest, "No provisioners configured in provisioner metadata")
		return
	}
	playbooks, skipped := machines.FilterPlaybooksByRun(configured,
		machines.HasProvisionedBefore(validation.config))
	if len(playbooks) == 0 {
		writeJSON(w, map[string]any{
			"success":           true,
			"machine_name":      machine.Name,
			"message":           "All configured playbooks were skipped by their run directives",
			"playbooks_skipped": skipped,
		})
		return
	}

	createdBy := auth.FromContext(r.Context()).Name
	parentMeta, err := json.Marshal(map[string]any{
		"total_playbooks":   len(playbooks),
		"skipped_playbooks": skipped,
	})
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
	for i := range playbooks {
		extra := map[string]any{"playbook": playbooks[i]}
		if i == len(playbooks)-1 {
			// The stamp rides the run's last playbook (Hosts.rb semantics).
			extra["final"] = true
		}
		playbookMeta, ferr := childMetadata(validation, extra)
		if ferr != nil {
			taskError(w, http.StatusInternalServerError, "Failed to create provisioner tasks")
			return
		}
		child, cerr := s.createChainTask(r.Context(), machine.Name,
			machines.OpProvisionPlaybook, playbookMeta, previous, provisionParent.ID, createdBy)
		if cerr != nil {
			slog.Error("create provision child", "machine", machine.Name, "error", cerr)
			taskError(w, http.StatusInternalServerError, "Failed to create provisioner tasks")
			return
		}
		previous = &child.ID
	}

	writeJSON(w, map[string]any{
		"success":           true,
		"machine_name":      machine.Name,
		"parent_task_id":    provisionParent.ID,
		"playbook_count":    len(playbooks),
		"playbooks_skipped": skipped,
	})
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
		machines.OpProvisionParent, machines.OpProvisionPlaybook,
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
