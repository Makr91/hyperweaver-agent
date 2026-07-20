package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

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

// handleListTemplates lists the local box-template registry.
//
//	@Summary		List box templates
//	@Description	Minimum role: viewer. The local box-template registry: downloaded box disk images machines clone from (organization/box_name/version/architecture tuples; stale rows whose disk image vanished self-delete on resolution).
//	@Tags			Machine Management
//	@Produce		json
//	@Success		200	{object}	map[string]interface{}	"Templates retrieved"
//	@Router			/templates [get]
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
//
//	@Summary		Local template details
//	@Description	Minimum role: viewer. One local template registry row (the base's GET /templates/local/{id}).
//	@Tags			Machine Management
//	@Produce		json
//	@Param			templateId	path	int	true	"Template ID"
//	@Success		200	"The template row"
//	@Failure		404	"Template not found"
//	@Router			/templates/{templateId} [get]
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
//
//	@Summary		Delete a local template
//	@Description	Minimum role: operator. Queues template_delete: the disk image is released from VirtualBox's media registry and deleted, the version directory pruned, the row removed. Machines built with clone_strategy copy (the default) are untouched — they cloned their own media. THE CHILDREN GATE (frozen, sync 2026-07-19): a template whose clone-base (clone-base.vdi beside the disk image) still feeds differencing children is LIVE infrastructure — clone-strategy machines boot from it; the task refuses naming the holding machines (`template clone base is still linked by machine(s): <names> — delete those machines first`); orphaned children from failed creates are swept, and a child-free base is removed with the template.
//	@Tags			Machine Management
//	@Produce		json
//	@Param			templateId	path	int	true	"Template ID"
//	@Success		202	"Delete task created"
//	@Failure		404	"Template not found"
//	@Router			/templates/{templateId} [delete]
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
//
//	@Summary		Export a machine to a local .box
//	@Description	Minimum role: operator. Queues template_export (the machine must be powered off): VBoxManage export writes the machine as OVF + disk images, metadata.json marks provider virtualbox, and the tar.gz lands as a standard Vagrant box under <templates root>/exports/ — the path and sha256 in the task output. The base's zone → .box export in VirtualBox terms.
//	@Tags			Machine Management
//	@Accept			json
//	@Produce		json
//	@Param			request	body	map[string]interface{}	true	"{machine_name, filename}"
//	@Success		202	"Export task created"
//	@Failure		400	"Missing machine_name"
//	@Failure		404	"Machine not found"
//	@Router			/templates/export [post]
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
//
//	@Summary		Publish a template to a registry
//	@Description	Minimum role: operator. Queues template_upload (the base's publish): exports the machine (or takes an existing .box by path), ensures the registry structure (box → version → provider virtualbox → architecture; duplicates tolerated), chunk-uploads the artifact (100MB chunks, three retries with backoff), and releases the box. While the upload runs, the TASK carries real byte progress (the converged wire, sync 2026-07-17): progress_info is exactly {status: "uploading", received_bytes, total_bytes} — received_bytes is bytes SENT so far (the uniform field name for both directions), total_bytes the .box file size — and progress_percent maps the bytes into the step's existing 85→95 window, throttled to one update per 1s or 1% of total (whichever first), final update always emitted; a retried chunk re-reports its own range instead of inflating the count. Registry credentials live on the configured source ONLY (auth_token — the registry API key, a BoxVault service-account token sent as Bearer; ca_file trusts self-signed registries) — tokens never ride task metadata, so the base's per-request auth_token has no analog.
//	@Tags			Machine Management
//	@Accept			json
//	@Produce		json
//	@Param			request	body	map[string]interface{}	true	"{machine_name|box_path, source_name, organization, box_name, version, description, architecture}"
//	@Success		202	"Publish task created"
//	@Failure		400	"Missing required fields"
//	@Failure		404	"Machine not found"
//	@Router			/templates/publish [post]
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
//
//	@Summary		Move a template's storage
//	@Description	Minimum role: operator. Queues template_move: the disk image relocates to <target_path>/<org>/<box>/<version>/ (same-volume rename; cross-volume copy+delete) and the row's disk_path updates — the base's template move (zfs rename vs send-recv) in file terms.
//	@Tags			Machine Management
//	@Accept			json
//	@Produce		json
//	@Param			templateId	path	int	true	"Template ID"
//	@Param			request		body	map[string]interface{}	true	"{target_path}"
//	@Success		202	"Move task created"
//	@Failure		400	"Missing target_path"
//	@Failure		404	"Template not found"
//	@Router			/templates/{templateId}/move [post]
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
//
//	@Summary		Download a box template
//	@Description	Minimum role: operator. Queues a template_download task: the .box streams from the named source (or the default registry), its disk image lands in the template storage, and the registry row is created. While the download runs, the TASK carries real byte progress (the converged wire, sync 2026-07-17): progress_info is exactly {status: "downloading", received_bytes, total_bytes|null} and progress_percent maps the bytes into the step's existing 10→60 window — throttled to one update per 1s or 1% of total (whichever first), final update always emitted; an unknown Content-Length parks the percent at 10 while received_bytes streams. An already-local tuple answers an honest 409 with the existing row's id instead of queueing a no-op download (the shared already-exists pre-check; a row whose disk image vanished self-heals, so re-pull after manual cleanup works). Private-box credentials live on the configured source (template_sources.sources[].auth_token) — never in task metadata.
//	@Tags			Machine Management
//	@Accept			json
//	@Produce		json
//	@Param			request	body	map[string]interface{}	true	"{organization, box_name, version, source_name, provider, architecture}"
//	@Success		202	"Template download task queued"
//	@Failure		400	"Missing tuple fields, non-specific version, an invalid provider, or no usable source"
//	@Failure		409	{object}	map[string]interface{}	"Template already exists locally"
//	@Router			/templates/pull [post]
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
	// The provider defaults to this agent's own (virtualbox); "utm" pulls a
	// box.utm-carrying box for the UTM backend — anything else refuses.
	switch meta.Provider {
	case "", machines.TemplateProvider:
		meta.Provider = machines.TemplateProvider
	case machines.TemplateProviderUTM:
	default:
		taskError(w, http.StatusBadRequest,
			"provider must be "+machines.TemplateProvider+" or "+machines.TemplateProviderUTM)
		return
	}
	// Already-exists pre-check (the base's rule, mirrored 2026-07-12): answer
	// an honest 409 with the existing row instead of queueing a download the
	// executor would no-op. FindTemplate self-heals stale rows (disk image
	// deleted by hand), so a re-pull after manual cleanup still works.
	existing, ferr := s.machines.FindTemplate(r.Context(), meta.Organization,
		meta.BoxName, meta.Version, meta.Provider, meta.Architecture)
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
