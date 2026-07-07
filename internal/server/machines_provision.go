package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

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
	// extracts its artifact here).
	if len(machine.Spec) > 0 {
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
	}
	return chain, nil
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
	metadata, err := json.Marshal(map[string]any{
		"ip": validation.ip, "port": validation.port,
	})
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to start provisioning pipeline")
		return
	}
	metadataStr := string(metadata)
	parent, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: machine.Name,
		Operation:   machines.OpProvisionOrchestration,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   createdBy,
		Metadata:    &metadataStr,
		Parent:      true,
	})
	if err != nil {
		slog.Error("create provision parent", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to start provisioning pipeline")
		return
	}

	chain, err := s.buildProvisionChain(r.Context(), machine, validation,
		body.SkipBoot, parent.ID, createdBy)
	if err != nil {
		slog.Error("build provision chain", "machine", machine.Name, "error", err)
		if _, cerr := s.tasks.Cancel(r.Context(), parent.ID); cerr != nil {
			slog.Warn("cancel half-built provision chain", "task_id", parent.ID, "error", cerr)
		}
		taskError(w, http.StatusInternalServerError, "Failed to start provisioning pipeline")
		return
	}

	writeJSON(w, map[string]any{
		"success":        true,
		"message":        "Provisioning pipeline started for " + machine.Name,
		"machine_name":   machine.Name,
		"parent_task_id": parent.ID,
		"steps":          len(chain),
		"task_chain":     chain,
	})
}

// handleSyncMachine creates the ad-hoc parentless sync chain (syncZone).
func (s *Server) handleSyncMachine(w http.ResponseWriter, r *http.Request) {
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
