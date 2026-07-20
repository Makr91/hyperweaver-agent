package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/provisioner"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
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

// bridgedInterfaceRow is one row of GET /provisioning/bridged-interfaces.
type bridgedInterfaceRow struct {
	Name  string `json:"name"`
	Class string `json:"class"`
	// Status is omitted when VirtualBox reports none.
	Status   string `json:"status,omitempty"`
	Wireless bool   `json:"wireless"`
}

// bridgedInterfacesResponse is GET /provisioning/bridged-interfaces's answer.
type bridgedInterfacesResponse struct {
	Interfaces []bridgedInterfaceRow `json:"interfaces"`
	Default    string                `json:"default"`
	Total      int                   `json:"total"`
}

// handleBridgedInterfaces lists the host's bridgeable interfaces (VBoxManage
// list bridgedifs) — the UI's uplink dropdown and the source for
// provisioning.default_network_interface values. FLAT ROWS (converged with
// zoneweaver, sync 2026-07-17): every row is {name, class} — on this
// hypervisor every bridgeable interface is a physical adapter, so class is
// always "phys" (zoneweaver's vocabulary adds aggr/etherstub/simnet/overlay
// for its link families) — plus the ADDITIVE picker fields status ("up"|
// "down") and wireless (the sync proposal 2026-07-19: macOS lists pseudo and
// down interfaces the picker should filter). On darwin the hostonlynet
// families' vmnet backing bridges are excluded (BridgeCandidates). The
// `default` extra rides as before.
//
//	@Summary		Host bridgeable interfaces
//	@Description	Minimum role: viewer. VBoxManage list bridgedifs — the UI's uplink dropdown and the bridge/default-NIC picker's choices. FLAT ROWS (the converged wire, sync 2026-07-17 — one shape on both agents): every entry is {name, class}, class from each agent's own link vocabulary. On this hypervisor every bridgeable interface is a physical adapter, so class is always "phys"; zoneweaver's rows additionally speak aggr/etherstub/simnet/overlay for its link families. ADDITIVE picker fields (the sync proposal 2026-07-19): status ("up"|"down") and wireless — macOS lists pseudo and down interfaces the picker should filter. macOS additionally EXCLUDES the hostonlynet families' vmnet backing bridges (bridge100-style entries carrying a hostonlynet's own subnet — never real bridge candidates; vagrant #13025's picker hole). default echoes provisioning.default_network_interface.
//	@Tags			Provisioning
//	@Produce		json
//	@Success		200	{object}	bridgedInterfacesResponse	"Interface rows"
//	@Failure		503	"VirtualBox is not installed"
//	@Router			/provisioning/bridged-interfaces [get]
func (s *Server) handleBridgedInterfaces(w http.ResponseWriter, r *http.Request) {
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}
	interfaces, err := machines.BridgeCandidates(r.Context(), exe)
	if err != nil {
		slog.Error("list bridged interfaces", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to list bridged interfaces")
		return
	}
	rows := make([]bridgedInterfaceRow, 0, len(interfaces))
	for i := range interfaces {
		row := bridgedInterfaceRow{
			Name:     interfaces[i].Name,
			Class:    "phys",
			Wireless: interfaces[i].Wireless,
		}
		if interfaces[i].Status != "" {
			row.Status = strings.ToLower(interfaces[i].Status)
		}
		rows = append(rows, row)
	}
	writeJSON(w, bridgedInterfacesResponse{
		Interfaces: rows,
		Default:    s.cfg.Provisioning.DefaultNetworkInterface,
		Total:      len(rows),
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

// importUploadMaxBytes caps one provisioner import-upload body — far above
// any real package archive.
const importUploadMaxBytes = int64(4) << 30

// handleExportProvisionerVersion queues provisioner_export (design §7's
// share half): the version → one registry-shaped tar.gz + the archive's
// sha256 (task output + .sha256 sidecar) under <registry>/exports.
//
//	@Summary		Export a version as a shareable archive
//	@Description	Minimum role: operator. Queues provisioner_export (design §7's host-to-host share): the version becomes ONE tar.gz — REGISTRY-SHAPED (<name>/<version>/… inside the tar, so the receiving agent's ordinary import consumes it) — under <registry>/exports, with the sha256 OF THE ARCHIVE (whole-file only) in the task output and a `<file>.sha256` sidecar beside it. Symlinks and specials never enter the archive.
//	@Tags			Provisioning
//	@Produce		json
//	@Param			name	path	string	true	"Provisioner family name"
//	@Param			version	path	string	true	"Version string or directory name"
//	@Success		202	"Export task queued"
//	@Failure		404	"Provisioner or version not found"
//	@Router			/provisioning/provisioners/{name}/versions/{version}/export [post]
func (s *Server) handleExportProvisionerVersion(w http.ResponseWriter, r *http.Request) {
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
		slog.Error("get provisioner version for export", "name", name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue export task")
		return
	}

	raw, err := json.Marshal(&provisioner.ExportMetadata{Name: name, Version: version.Version})
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to queue export task")
		return
	}
	metadata := string(raw)
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: "system",
		Operation:   provisioner.OpExport,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   auth.FromContext(r.Context()).Name,
		Metadata:    &metadata,
	})
	if err != nil {
		slog.Error("queue provisioner export", "name", name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue export task")
		return
	}
	acceptedTask(w, task.ID, "Export task queued for "+name+"/"+version.Version)
}

// handleImportUploadProvisioner receives a package archive as multipart
// form-data (part name "file") and queues the ordinary import task against
// it — the share contract's receiving half. The temp archive cleans up after
// the import attempt (cleanup_source). An optional "checksum" field (sha256
// of the archive — the converged wire, sync 2026-07-17) rides into the
// import's pre-extraction verification; like the file-manager precedent,
// non-file fields must arrive BEFORE the file part — the stream is consumed
// in order and the task queues the moment the file lands.
//
//	@Summary		Upload a package archive and import it
//	@Description	Minimum role: operator. The share contract's receiving half: multipart/form-data with a "file" part (.tar.gz/.tgz/.zip, ≤4 GiB) streams to a temp file and queues the ordinary provisioner_import task against it (same DSL lint gate, same non-clobber rules; the temp archive removes itself after the attempt). An optional checksum field — the sender's published sha256 OF THE ARCHIVE (64 hex chars; the converged wire, sync 2026-07-17) — rides into the import's pre-extraction verification: a mismatch fails the task honestly, nothing extracts. Like the file-manager upload, non-file fields must arrive BEFORE the file part — the stream is consumed in order and the task queues the moment the file lands.
//	@Tags			Provisioning
//	@Accept			mpfd
//	@Produce		json
//	@Param			checksum	formData	string	false	"Optional sha256 hex digest (64 characters) of the archive, verified before extraction — must precede the file part"
//	@Param			file	formData	file	true	"The package archive (.tar.gz, .tgz, or .zip; ≤4 GiB)"
//	@Success		202	"Import task queued ({success, task_id, filename, size, status, message})"
//	@Failure		400	"Not multipart, no file part, not a supported archive name, or an invalid checksum ("checksum must be a 64-character sha256 hex digest")"
//	@Failure		413	"Upload exceeds the 4 GiB cap"
//	@Router			/provisioning/provisioners/import-upload [post]
func (s *Server) handleImportUploadProvisioner(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, importUploadMaxBytes)
	reader, err := r.MultipartReader()
	if err != nil {
		taskError(w, http.StatusBadRequest, "multipart/form-data with a file part is required")
		return
	}
	checksum := ""
	for {
		part, perr := reader.NextPart()
		if errors.Is(perr, io.EOF) {
			taskError(w, http.StatusBadRequest, `no "file" part in the upload`)
			return
		}
		if perr != nil {
			taskError(w, http.StatusBadRequest, "Malformed multipart body: "+perr.Error())
			return
		}
		if part.FormName() == "checksum" {
			raw, rerr := io.ReadAll(io.LimitReader(part, 4096))
			if rerr != nil {
				taskError(w, http.StatusBadRequest, "Malformed multipart body: "+rerr.Error())
				return
			}
			checksum = strings.TrimSpace(string(raw))
			continue
		}
		if part.FormName() != "file" {
			continue
		}
		filename := filepath.Base(part.FileName())
		if filename == "" || filename == "." || !provisioner.IsArchiveName(filename) {
			taskError(w, http.StatusBadRequest, "the uploaded file must be a .tar.gz, .tgz, or .zip package archive")
			return
		}

		temp, terr := os.MkdirTemp("", "hyperweaver-upload-*")
		if terr != nil {
			slog.Error("create upload temp dir", "error", terr)
			taskError(w, http.StatusInternalServerError, "Failed to receive upload")
			return
		}
		archivePath := filepath.Join(temp, filename)
		size, werr := safepath.WriteFileFrom(archivePath, part, 0o600)
		if werr != nil {
			_ = os.RemoveAll(temp)
			var tooLarge *http.MaxBytesError
			if errors.As(werr, &tooLarge) {
				taskError(w, http.StatusRequestEntityTooLarge, "Upload exceeds the import size cap")
				return
			}
			slog.Error("receive provisioner upload", "error", werr)
			taskError(w, http.StatusInternalServerError, "Failed to receive upload")
			return
		}

		meta := &provisioner.ImportMetadata{
			SourceType:    provisioner.SourceArchive,
			Path:          archivePath,
			CleanupSource: true,
			Checksum:      checksum,
		}
		if verr := meta.Validate(); verr != nil {
			_ = os.RemoveAll(temp)
			taskError(w, http.StatusBadRequest, verr.Error())
			return
		}
		raw, merr := json.Marshal(meta)
		if merr != nil {
			_ = os.RemoveAll(temp)
			taskError(w, http.StatusInternalServerError, "Failed to queue import task")
			return
		}
		metadata := string(raw)
		task, cerr := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
			MachineName: "system",
			Operation:   provisioner.OpImport,
			Priority:    tasks.PriorityMedium,
			CreatedBy:   auth.FromContext(r.Context()).Name,
			Metadata:    &metadata,
		})
		if cerr != nil {
			_ = os.RemoveAll(temp)
			slog.Error("queue uploaded provisioner import", "error", cerr)
			taskError(w, http.StatusInternalServerError, "Failed to queue import task")
			return
		}
		slog.Info("provisioner upload received", "filename", filename, "bytes", size,
			"task_id", task.ID, "by", auth.FromContext(r.Context()).Name)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		if werr := json.NewEncoder(w).Encode(map[string]any{
			"success":  true,
			"task_id":  task.ID,
			"filename": filename,
			"size":     size,
			"status":   tasks.StatusPending,
			"message":  "Provisioner import task queued from upload",
		}); werr != nil {
			slog.Error("write import-upload response", "error", werr)
		}
		return
	}
}

// catalogSourceList converts the configured catalogs into the provisioner
// package's source shape.
func (s *Server) catalogSourceList() []provisioner.CatalogSource {
	sources := make([]provisioner.CatalogSource, 0, len(s.cfg.CatalogSources.Sources))
	for _, source := range s.cfg.CatalogSources.Sources {
		sources = append(sources, provisioner.CatalogSource{
			Name:    source.Name,
			URL:     source.URL,
			Enabled: source.Enabled,
			Default: source.Default,
			CAFile:  source.CAFile,
		})
	}
	return sources
}

// catalogSourceRow is one entry of GET /provisioning/catalog/sources.
type catalogSourceRow struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Default bool   `json:"default"`
}

// listCatalogSourcesResponse is GET /provisioning/catalog/sources's answer.
type listCatalogSourcesResponse struct {
	Enabled bool               `json:"enabled"`
	Sources []catalogSourceRow `json:"sources"`
}

// handleListCatalogSources lists the enabled catalog definitions (the
// templates/sources shape — never the CA file path).
//
//	@Summary		List configured provisioner catalogs
//	@Description	Minimum role: viewer. The enabled catalog_sources definitions (name, url, default) — the HACS model's registries; fork the catalog repo and add your own as another source. CA bundles are never returned.
//	@Tags			Provisioning
//	@Produce		json
//	@Success		200	{object}	listCatalogSourcesResponse	"Enabled catalogs"
//	@Router			/provisioning/catalog/sources [get]
func (s *Server) handleListCatalogSources(w http.ResponseWriter, _ *http.Request) {
	sources := []catalogSourceRow{}
	for _, source := range s.catalogSourceList() {
		if !source.Enabled {
			continue
		}
		sources = append(sources, catalogSourceRow{
			Name:    source.Name,
			URL:     source.URL,
			Default: source.Default,
		})
	}
	// enabled = zoneweaver's converged field (its provisioning.catalog_sources
	// carries a subsystem gate); this agent has no catalog kill-switch, so the
	// honest constant is true.
	writeJSON(w, listCatalogSourcesResponse{Enabled: true, Sources: sources})
}

// handleGetCatalog fetches one catalog's document live (?source= names a
// configured catalog; empty = the default) — parsed, format_version-gated,
// relayed with the source name.
//
//	@Summary		Browse a provisioner catalog
//	@Description	Minimum role: viewer. Fetches the source's catalog.json LIVE (?source= names a configured catalog; empty = the default), validates format_version 1, and relays the parsed document: {name, format_version, updated, provisioners: [{name, repo, description, versions: [{version, artifacts: [{url, checksum_type, checksum}]}]}]} — versions semver-DESC, artifact URLs OPAQUE (release tags carry slashes; never parse or construct them). Versions may disappear between fetches when an author deletes a release.
//	@Tags			Provisioning
//	@Produce		json
//	@Param			source	query	string	false	"A configured catalog source; empty = the default"
//	@Success		200	{object}	provisioner.CatalogDocument	"The catalog document — the parsed catalog.json IS the response (no envelope; the resolved source rides /provisioning/catalog/sources)"
//	@Failure		404	"No such (or no default) enabled catalog source"
//	@Failure		502	"Catalog unreachable, unparseable, or wrong format_version"
//	@Router			/provisioning/catalog [get]
func (s *Server) handleGetCatalog(w http.ResponseWriter, r *http.Request) {
	source, err := provisioner.FindCatalogSource(s.catalogSourceList(), r.URL.Query().Get("source"))
	if err != nil {
		taskError(w, http.StatusNotFound, err.Error())
		return
	}
	document, err := provisioner.FetchCatalog(r.Context(), source)
	if err != nil {
		slog.Error("fetch provisioner catalog", "source", source.Name, "error", err)
		taskError(w, http.StatusBadGateway, err.Error())
		return
	}
	// Parsed relay, the shared wire (UI's 2026-07-17 flag — the wrap was a
	// bug on BOTH agents once): the catalog document IS the response; the
	// resolved source rides /provisioning/catalog/sources, never an envelope.
	writeJSON(w, document)
}

// handleCatalogInstall queues provisioner_catalog_install: download the
// named family/version's VERSIONED asset, verify its sha256, import.
//
//	@Summary		Install a provisioner from a catalog
//	@Description	Minimum role: operator. Queues provisioner_catalog_install: the executor fetches the catalog FRESH (a stale pin would 404 anyway; published checksums never change), downloads the named version's immutable VERSIONED asset, verifies its sha256 DURING the stream (mismatch = loud failure, nothing imported), then runs the ordinary import path — DSL lint gate, non-clobber, role-specs + schema.json derivation all included. While the archive downloads, the TASK carries real byte progress (the converged wire, sync 2026-07-17): progress_info is exactly {status: "downloading", received_bytes, total_bytes|null} and progress_percent maps the bytes into 0→90 (this op had no intermediate percents; the sha256 verify + import ride after the window and completion lands 100) — throttled to one update per 1s or 1% of total (whichever first), final update always emitted; an unknown Content-Length parks the percent at 0 while received_bytes streams. Serialized with imports (one registry write at a time).
//	@Tags			Provisioning
//	@Accept			json
//	@Produce		json
//	@Param			request	body	provisioner.CatalogInstallMetadata	true	"Catalog install request: name + version (source_name optional; empty = the default catalog)"
//	@Success		202	"Catalog install task queued"
//	@Failure		400	"Missing/unusable name or version"
//	@Failure		404	"No such (or no default) enabled catalog source"
//	@Router			/provisioning/catalog/install [post]
func (s *Server) handleCatalogInstall(w http.ResponseWriter, r *http.Request) {
	var body provisioner.CatalogInstallMetadata
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if !provisioner.ValidName(body.Name) || !provisioner.ValidName(body.Version) {
		taskError(w, http.StatusBadRequest, "name and version are required (registry-legal names)")
		return
	}
	source, err := provisioner.FindCatalogSource(s.catalogSourceList(), body.SourceName)
	if err != nil {
		taskError(w, http.StatusNotFound, err.Error())
		return
	}
	// Already-present pre-check (zoneweaver's converged wire): versions are
	// immutable — an install of an existing version answers 409 up front
	// instead of queueing a task doomed to the import's non-clobber refusal.
	if _, verr := s.provisioners.GetVersion(body.Name, body.Version); verr == nil {
		taskError(w, http.StatusConflict,
			body.Name+"/"+body.Version+" is already in the registry — versions are immutable")
		return
	}

	raw, err := json.Marshal(&body)
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to queue catalog install")
		return
	}
	metadata := string(raw)
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: "system",
		Operation:   provisioner.OpCatalogInstall,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   auth.FromContext(r.Context()).Name,
		Metadata:    &metadata,
	})
	if err != nil {
		slog.Error("queue catalog install", "name", body.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue catalog install")
		return
	}
	// The converged 202 body (zoneweaver's shipped shape): name/version/source
	// ride alongside the task identity.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	if werr := json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"task_id": task.ID,
		"name":    body.Name,
		"version": body.Version,
		"source":  source.Name,
		"status":  tasks.StatusPending,
		"message": "Catalog install task queued for " + body.Name + "/" + body.Version,
	}); werr != nil {
		slog.Error("write catalog install response", "error", werr)
	}
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
