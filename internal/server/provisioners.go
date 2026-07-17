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
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// Provisioner registry endpoints (Agent API v1 provisioning surface —
// architecture §8, the first slice of the provisioning engine): list and
// inspect provisioner packages, import new ones (task-queued: folder,
// archive, or git clone), delete families or versions no machine references.

// handleListProvisioners: every package family, versions newest first.
func (s *Server) handleListProvisioners(w http.ResponseWriter, _ *http.Request) {
	list, err := s.provisioners.List()
	if err != nil {
		slog.Error("list provisioners", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to retrieve provisioners")
		return
	}
	writeJSON(w, map[string]any{
		"provisioners": list,
		"total":        len(list),
	})
}

// handleProvisionerDetails: one family with its full version metadata.
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

// handleRefreshProvisionerSpecs re-derives every version's role-specs cache
// (POST /provisioning/provisioners/refresh-specs — the manual refresh for
// hand-dropped packages and updated specs; imports rebuild automatically).
func (s *Server) handleRefreshProvisionerSpecs(w http.ResponseWriter, r *http.Request) {
	refreshed, err := s.provisioners.RefreshAllRoleSpecs()
	if err != nil {
		slog.Error("refresh role specs", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to refresh role specs")
		return
	}
	slog.Info("provisioner role-specs refreshed", "versions", len(refreshed),
		"by", auth.FromContext(r.Context()).Name)
	writeJSON(w, map[string]any{
		"success":   true,
		"refreshed": refreshed,
		"total":     len(refreshed),
	})
}

// handleImportProvisioner queues a provisioner_import task. The request body
// is the task metadata verbatim: {source_type: folder|archive|git, path?,
// url?, branch?} — paths name locations on the agent host.
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
	if werr := json.NewEncoder(w).Encode(map[string]any{
		"success":     true,
		"task_id":     task.ID,
		"source_type": meta.SourceType,
		"status":      tasks.StatusPending,
		"message":     "Provisioner import task queued successfully",
	}); werr != nil {
		slog.Error("write import response", "error", werr)
	}
}

// handleRefreshProvisionerFromSource queues the ORDINARY provisioner_import
// task against a family's stored git provenance (POST
// /provisioning/provisioners/{name}/refresh-from-source — converged with
// zoneweaver, sync 2026-07-17). Non-clobber is the import's own rule:
// existing versions refuse, new versions land beside. Families without git
// provenance answer 400 — catalog-installed families update through the
// catalog, folder/archive imports carry no source to replay.
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
	if werr := json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"task_id": task.ID,
		"name":    name,
		"source":  collection.Source,
		"status":  tasks.StatusPending,
		"message": "Refresh-from-source task queued for " + name,
	}); werr != nil {
		slog.Error("write refresh-from-source response", "error", werr)
	}
}

// handleDeleteProvisioner removes a whole family — refused while any machine
// references any of its versions (SHI rule, minus its built-in
// special-casing: every package is deletable when unreferenced).
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

// handleBridgedInterfaces lists the host's bridgeable interface names
// (VBoxManage list bridgedifs) — the UI's bridge/default-NIC picker and the
// source for provisioning.default_network_interface values.
func (s *Server) handleBridgedInterfaces(w http.ResponseWriter, r *http.Request) {
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}
	names, err := vbox.ListBridgedIfs(r.Context(), exe)
	if err != nil {
		slog.Error("list bridged interfaces", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to list bridged interfaces")
		return
	}
	writeJSON(w, map[string]any{
		"interfaces": names,
		"default":    s.cfg.Provisioning.DefaultNetworkInterface,
		"total":      len(names),
	})
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
		if werr := json.NewEncoder(w).Encode(map[string]any{
			"error":    "Provisioner is referenced by existing machines and cannot be deleted",
			"machines": references,
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

// handleListCatalogSources lists the enabled catalog definitions (the
// templates/sources shape — never the CA file path).
func (s *Server) handleListCatalogSources(w http.ResponseWriter, _ *http.Request) {
	sources := []map[string]any{}
	for _, source := range s.catalogSourceList() {
		if !source.Enabled {
			continue
		}
		sources = append(sources, map[string]any{
			"name":    source.Name,
			"url":     source.URL,
			"default": source.Default,
		})
	}
	// enabled = zoneweaver's converged field (its provisioning.catalog_sources
	// carries a subsystem gate); this agent has no catalog kill-switch, so the
	// honest constant is true.
	writeJSON(w, map[string]any{"enabled": true, "sources": sources})
}

// handleGetCatalog fetches one catalog's document live (?source= names a
// configured catalog; empty = the default) — parsed, format_version-gated,
// relayed with the source name.
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
