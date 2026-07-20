package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/provisioner"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// Provisioner registry endpoints (Agent API v1 provisioning surface —
// architecture §8, the first slice of the provisioning engine): list and
// inspect provisioner packages, import new ones (task-queued: folder,
// archive, or git clone), delete families or versions no machine references.

// listProvisionersResponse is GET /provisioning/provisioners's answer.
type listProvisionersResponse struct {
	Provisioners []*provisioner.Collection `json:"provisioners"`
	Total        int                       `json:"total"`
}

// handleListProvisioners: every package family, versions newest first.
//
//	@Summary		List provisioner packages
//	@Description	Minimum role: viewer. Every package family in the registry with its versions (newest first). The filesystem is the source of truth — packages dropped in by installers or by hand appear without registration. Family objects carry source — the git provenance recorded at git import ({source_type, url, branch?}) or null; the detail GET carries the same field.
//	@Tags			Provisioning
//	@Produce		json
//	@Success		200	{object}	listProvisionersResponse	"Provisioner families"
//	@Router			/provisioning/provisioners [get]
func (s *Server) handleListProvisioners(w http.ResponseWriter, _ *http.Request) {
	list, err := s.provisioners.List()
	if err != nil {
		slog.Error("list provisioners", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to retrieve provisioners")
		return
	}
	writeJSON(w, listProvisionersResponse{
		Provisioners: list,
		Total:        len(list),
	})
}

// handleProvisionerDetails: one family with its full version metadata.
//
//	@Summary		Provisioner family details
//	@Description	Minimum role: viewer. The family with its full version metadata.
//	@Tags			Provisioning
//	@Produce		json
//	@Param			name	path	string	true	"Provisioner family name"
//	@Success		200	{object}	provisioner.Collection	"The family"
//	@Failure		404	"Provisioner not found"
//	@Router			/provisioning/provisioners/{name} [get]
func (s *Server) handleProvisionerDetails(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	collection, err := s.provisioners.Get(name)
	if errors.Is(err, provisioner.ErrNotFound) {
		taskError(w, http.StatusNotFound, "Provisioner not found")
		return
	}
	if err != nil {
		slog.Error("get provisioner", "name", name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to retrieve provisioner")
		return
	}
	writeJSON(w, collection)
}

// handleProvisionerVersion: one version's full manifest (metadata.roles +
// configuration.basicFields/advancedFields drive the UI's machine-create
// forms).
//
//	@Summary		Provisioner version details
//	@Description	Minimum role: viewer. One version's full manifest — the document the machine-create forms render from. version matches the manifest version or the directory name.
//	@Tags			Provisioning
//	@Produce		json
//	@Param			name	path	string	true	"Provisioner family name"
//	@Param			version	path	string	true	"Version string or directory name"
//	@Success		200	{object}	provisioner.Version	"The version"
//	@Failure		404	"Provisioner or version not found"
//	@Router			/provisioning/provisioners/{name}/versions/{version} [get]
func (s *Server) handleProvisionerVersion(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	version, err := s.provisioners.GetVersion(name, r.PathValue("version"))
	if errors.Is(err, provisioner.ErrNotFound) {
		taskError(w, http.StatusNotFound, "Provisioner not found")
		return
	}
	if errors.Is(err, provisioner.ErrVersionNotFound) {
		taskError(w, http.StatusNotFound, "Provisioner version not found")
		return
	}
	if err != nil {
		slog.Error("get provisioner version", "name", name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to retrieve provisioner version")
		return
	}
	writeJSON(w, version)
}

// refreshSpecsResponse is POST /provisioning/provisioners/refresh-specs's answer.
type refreshSpecsResponse struct {
	Success   bool                         `json:"success"`
	Refreshed []provisioner.RefreshedSpecs `json:"refreshed"`
	Total     int                          `json:"total"`
}

// handleRefreshProvisionerSpecs re-derives every version's role-specs cache
// (POST /provisioning/provisioners/refresh-specs — the manual refresh for
// hand-dropped packages and updated specs; imports rebuild automatically).
//
//	@Summary		Re-derive every version's caches (role-specs + schema.json)
//	@Description	Minimum role: operator. Walks each registry version and rebuilds BOTH derived artifacts: role-specs.yml from the shipped roles' meta/argument_specs.yml, and the Field DSL's schema.json (JSON Schema 2020-12) from metadata.configuration — the manual refresh for hand-dropped packages and updated specs (imports rebuild them automatically). Synchronous.
//	@Tags			Provisioning
//	@Produce		json
//	@Success		200	{object}	refreshSpecsResponse	"Per-version refresh summary"
//	@Failure		500	"Registry scan failed"
//	@Router			/provisioning/provisioners/refresh-specs [post]
func (s *Server) handleRefreshProvisionerSpecs(w http.ResponseWriter, r *http.Request) {
	refreshed, err := s.provisioners.RefreshAllRoleSpecs()
	if err != nil {
		slog.Error("refresh role specs", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to refresh role specs")
		return
	}
	slog.Info("provisioner role-specs refreshed", "versions", len(refreshed),
		"by", auth.FromContext(r.Context()).Name)
	writeJSON(w, refreshSpecsResponse{
		Success:   true,
		Refreshed: refreshed,
		Total:     len(refreshed),
	})
}

// importProvisionerResponse is POST /provisioning/provisioners/import's 202 answer.
type importProvisionerResponse struct {
	Success    bool   `json:"success"`
	TaskID     string `json:"task_id"`
	SourceType string `json:"source_type"`
	Status     string `json:"status"`
	Message    string `json:"message"`
}

// handleImportProvisioner queues a provisioner_import task. The request body
// is the task metadata verbatim: {source_type: folder|archive|git, path?,
// url?, branch?} — paths name locations on the agent host.
//
//	@Summary		Import a provisioner package
//	@Description	Minimum role: operator. Queues a provisioner_import task (machine_name "system", category-locked: one import at a time). Sources: folder (a directory on the agent host holding provisioner-collection.yml, or provisioner.yml for a bare version), archive (.tar.gz/.tgz/.zip on the agent host), or git (http(s) URL, cloned --depth 1 --recursive so nested submodules arrive; optional branch). The package root is searched up to 3 directory levels deep. Archive imports may carry an optional checksum — the sha256 hex digest OF THE ARCHIVE (the converged wire, sync 2026-07-17) — verified against the file BEFORE extraction (compared case-insensitively); a mismatch fails the task honestly, naming expected vs actual, and nothing extracts. Every version's Field DSL is LINTED fail-closed before anything copies (design §3.1): an unknown field type, legacy basicFields/advancedFields, a bad show_if operand, a pattern without pattern_error — any problem fails the import with the full annotated list in the task output. Existing versions are never touched — re-importing is idempotent; update = import a newer version beside the old.
//	@Tags			Provisioning
//	@Accept			json
//	@Produce		json
//	@Param			request	body	provisioner.ImportMetadata	true	"Import request: source_type (folder|archive|git) plus the source-specific fields"
//	@Success		202	{object}	importProvisionerResponse	"Import task queued"
//	@Failure		400	"Invalid body, source_type, path, url, branch, or checksum ("checksum must be a 64-character sha256 hex digest")"
//	@Router			/provisioning/provisioners/import [post]
func (s *Server) handleImportProvisioner(w http.ResponseWriter, r *http.Request) {
	var meta provisioner.ImportMetadata
	if err := decodeBody(r, &meta); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if err := meta.Validate(); err != nil {
		taskError(w, http.StatusBadRequest, err.Error())
		return
	}

	raw, err := json.Marshal(meta)
	if err != nil {
		slog.Error("serialize import metadata", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue import task")
		return
	}
	metadata := string(raw)
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: "system",
		Operation:   provisioner.OpImport,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   auth.FromContext(r.Context()).Name,
		Metadata:    &metadata,
	})
	if err != nil {
		slog.Error("queue provisioner import", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue import task")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	if werr := json.NewEncoder(w).Encode(importProvisionerResponse{
		Success:    true,
		TaskID:     task.ID,
		SourceType: meta.SourceType,
		Status:     tasks.StatusPending,
		Message:    "Provisioner import task queued successfully",
	}); werr != nil {
		slog.Error("write import response", "error", werr)
	}
}

// refreshFromSourceResponse is POST
// /provisioning/provisioners/{name}/refresh-from-source's 202 answer.
type refreshFromSourceResponse struct {
	Success bool                `json:"success"`
	TaskID  string              `json:"task_id"`
	Name    string              `json:"name"`
	Source  *provisioner.Source `json:"source"`
	Status  string              `json:"status"`
	Message string              `json:"message"`
}

// handleRefreshProvisionerFromSource queues the ORDINARY provisioner_import
// task against a family's stored git provenance (POST
// /provisioning/provisioners/{name}/refresh-from-source — converged with
// zoneweaver, sync 2026-07-17). Non-clobber is the import's own rule:
// existing versions refuse, new versions land beside. Families without git
// provenance answer 400 — catalog-installed families update through the
// catalog, folder/archive imports carry no source to replay.
//
//	@Summary		Re-import a family from its stored git source
//	@Description	Minimum role: operator. Queues the ORDINARY provisioner_import op against the family's stored git provenance (the source field recorded at git import — url and branch; never read from package files): same clone, same fail-closed DSL lint gate, same non-clobber rules — a newer upstream version lands beside the old, existing versions are never touched, and re-running against an unchanged repository is an idempotent no-op. Families without git provenance answer 400 (folder/archive imports carry none; catalog families update through the catalog).
//	@Tags			Provisioning
//	@Produce		json
//	@Param			name	path	string	true	"Provisioner family name"
//	@Success		202	{object}	refreshFromSourceResponse	"Refresh import task queued"
//	@Failure		400	"Family carries no git provenance (catalog families update through the catalog)"
//	@Failure		404	"Provisioner not found"
//	@Router			/provisioning/provisioners/{name}/refresh-from-source [post]
func (s *Server) handleRefreshProvisionerFromSource(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	collection, err := s.provisioners.Get(name)
	if errors.Is(err, provisioner.ErrNotFound) {
		taskError(w, http.StatusNotFound, "Provisioner not found")
		return
	}
	if err != nil {
		slog.Error("get provisioner for refresh", "name", name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue refresh task")
		return
	}
	if collection.Source == nil || collection.Source.SourceType != provisioner.SourceGit {
		taskError(w, http.StatusBadRequest,
			"Provisioner "+name+" has no git source recorded — catalog families update through the catalog")
		return
	}

	// token_name replays into the ordinary import, which resolves the actual
	// token from the secrets store at run time (Mark's private-repo ruling
	// 2026-07-17) — provenance and task metadata carry the NAME only.
	raw, err := json.Marshal(&provisioner.ImportMetadata{
		SourceType: provisioner.SourceGit,
		URL:        collection.Source.URL,
		Branch:     collection.Source.Branch,
		TokenName:  collection.Source.TokenName,
	})
	if err != nil {
		slog.Error("serialize refresh metadata", "name", name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue refresh task")
		return
	}
	metadata := string(raw)
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: "system",
		Operation:   provisioner.OpImport,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   auth.FromContext(r.Context()).Name,
		Metadata:    &metadata,
	})
	if err != nil {
		slog.Error("queue provisioner refresh-from-source", "name", name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue refresh task")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	if werr := json.NewEncoder(w).Encode(refreshFromSourceResponse{
		Success: true,
		TaskID:  task.ID,
		Name:    name,
		Source:  collection.Source,
		Status:  tasks.StatusPending,
		Message: "Refresh-from-source task queued for " + name,
	}); werr != nil {
		slog.Error("write refresh-from-source response", "error", werr)
	}
}

// handleDeleteProvisioner removes a whole family — refused while any machine
// references any of its versions (SHI rule, minus its built-in
// special-casing: every package is deletable when unreferenced).
//
//	@Summary		Delete a provisioner family
//	@Description	Minimum role: operator. Removes the family and every version — refused (409) while any machine references any of its versions. No package is special-cased by name.
//	@Tags			Provisioning
//	@Produce		json
//	@Param			name	path	string	true	"Provisioner family name"
//	@Success		200	"Family deleted"
//	@Failure		404	"Provisioner not found"
//	@Failure		409	{object}	provisionerConflictResponse	"Referenced by existing machines"
//	@Router			/provisioning/provisioners/{name} [delete]
func (s *Server) handleDeleteProvisioner(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, err := s.provisioners.Get(name); errors.Is(err, provisioner.ErrNotFound) {
		taskError(w, http.StatusNotFound, "Provisioner not found")
		return
	} else if err != nil {
		slog.Error("get provisioner", "name", name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to delete provisioner")
		return
	}

	if !s.refuseReferencedProvisioner(r.Context(), w, name, "") {
		return
	}
	if err := s.provisioners.Delete(name); err != nil {
		slog.Error("delete provisioner", "name", name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to delete provisioner")
		return
	}
	slog.Info("provisioner deleted", "name", name, "by", auth.FromContext(r.Context()).Name)
	writeJSON(w, map[string]any{
		"success": true,
		"message": "Provisioner " + name + " deleted successfully",
	})
}

// handleDeleteProvisionerVersion removes one version — refused while any
// machine references it.
//
//	@Summary		Delete a provisioner version
//	@Description	Minimum role: operator. Removes one version, leaving its siblings — refused (409) while any machine references it (versions in use are never touched).
//	@Tags			Provisioning
//	@Produce		json
//	@Param			name	path	string	true	"Provisioner family name"
//	@Param			version	path	string	true	"Version string or directory name"
//	@Success		200	"Version deleted"
//	@Failure		404	"Provisioner or version not found"
//	@Failure		409	{object}	provisionerConflictResponse	"Referenced by existing machines"
//	@Router			/provisioning/provisioners/{name}/versions/{version} [delete]
func (s *Server) handleDeleteProvisionerVersion(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	versionKey := r.PathValue("version")
	version, err := s.provisioners.GetVersion(name, versionKey)
	if errors.Is(err, provisioner.ErrNotFound) {
		taskError(w, http.StatusNotFound, "Provisioner not found")
		return
	}
	if errors.Is(err, provisioner.ErrVersionNotFound) {
		taskError(w, http.StatusNotFound, "Provisioner version not found")
		return
	}
	if err != nil {
		slog.Error("get provisioner version", "name", name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to delete provisioner version")
		return
	}

	if !s.refuseReferencedProvisioner(r.Context(), w, name, version.Version) {
		return
	}
	if derr := s.provisioners.DeleteVersion(name, versionKey); derr != nil {
		slog.Error("delete provisioner version", "name", name, "version", versionKey, "error", derr)
		taskError(w, http.StatusInternalServerError, "Failed to delete provisioner version")
		return
	}
	slog.Info("provisioner version deleted", "name", name, "version", version.Version,
		"by", auth.FromContext(r.Context()).Name)
	writeJSON(w, map[string]any{
		"success": true,
		"message": "Provisioner " + name + "/" + version.Version + " deleted successfully",
	})
}

// provisionerConflictResponse is the 409 body returned when machines still
// reference the family or version being deleted.
type provisionerConflictResponse struct {
	Error    string   `json:"error"`
	Machines []string `json:"machines"`
}

// refuseReferencedProvisioner answers 409 (and returns false) when machines
// still reference the family (version "" = any version).
func (s *Server) refuseReferencedProvisioner(ctx context.Context, w http.ResponseWriter, name, version string) bool {
	references, err := s.provisionerReferences(ctx, name, version)
	if err != nil {
		slog.Error("check provisioner references", "name", name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to check provisioner references")
		return false
	}
	if len(references) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		if werr := json.NewEncoder(w).Encode(provisionerConflictResponse{
			Error:    "Provisioner is referenced by existing machines and cannot be deleted",
			Machines: references,
		}); werr != nil {
			slog.Error("write provisioner conflict response", "error", werr)
		}
		return false
	}
	return true
}

// provisionerReferences lists machines whose creation spec references the
// provisioner (the spec's provisioner {name, version} block).
func (s *Server) provisionerReferences(ctx context.Context, name, version string) ([]string, error) {
	list, err := s.machines.List(ctx, &machines.ListFilter{})
	if err != nil {
		return nil, err
	}
	references := []string{}
	for _, machine := range list {
		if len(machine.Spec) == 0 {
			continue
		}
		spec, perr := machines.ParseSpec(machine)
		if perr != nil {
			continue
		}
		if spec.Provisioner.Name != name {
			continue
		}
		if version != "" && spec.Provisioner.Version != version {
			continue
		}
		references = append(references, machine.Name)
	}
	return references, nil
}
