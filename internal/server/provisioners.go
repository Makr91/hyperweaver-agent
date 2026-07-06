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

// provisionerReferences lists machines whose configuration references the
// provisioner (the creation request's provisioner {name, version} block,
// stored on the machine row).
func (s *Server) provisionerReferences(ctx context.Context, name, version string) ([]string, error) {
	list, err := s.machines.List(ctx, &machines.ListFilter{})
	if err != nil {
		return nil, err
	}
	references := []string{}
	for _, machine := range list {
		if machine.Configuration == nil {
			continue
		}
		var configuration struct {
			Provisioner struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"provisioner"`
		}
		if uerr := json.Unmarshal(machine.Configuration, &configuration); uerr != nil {
			continue
		}
		if configuration.Provisioner.Name != name {
			continue
		}
		if version != "" && configuration.Provisioner.Version != version {
			continue
		}
		references = append(references, machine.Name)
	}
	return references, nil
}
