package server

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/config"
	"github.com/Makr91/hyperweaver-agent/internal/locations"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/problem"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

var storagePathSlug = regexp.MustCompile(`[^a-z0-9]+`)

func (s *Server) machinesLocation(id string) (location locations.Location, reason string) {
	if id == "" {
		found, ok := s.storage.Default(locations.Machines)
		if !ok {
			return locations.Location{}, "no machines storage path is available"
		}
		return found, ""
	}
	found, ok := s.storage.Get(locations.Machines, id)
	if !ok {
		return locations.Location{}, "storage_path_id " + id + " is not a machines storage path"
	}
	if !found.Enabled {
		return locations.Location{}, "storage_path_id " + id + " is disabled"
	}
	return found, ""
}

func (s *Server) machineRoot(machine *machines.Machine) string {
	if machine.Home != nil && *machine.Home != "" {
		if found, ok := s.storage.Containing(locations.Machines, *machine.Home); ok {
			return found.Path
		}
		return *machine.Home
	}
	return s.storage.DefaultPath(locations.Machines)
}

func (s *Server) storagePathItems(ctx context.Context, location *locations.Location) (int, error) {
	switch location.Type {
	case locations.Machines:
		list, err := s.machines.List(ctx, &machines.ListFilter{})
		if err != nil {
			return 0, err
		}
		count := 0
		for _, machine := range list {
			if machine.Home == nil || *machine.Home == "" {
				continue
			}
			if found, ok := s.storage.Containing(locations.Machines, *machine.Home); ok && found.ID == location.ID {
				count++
			}
		}
		return count, nil
	case locations.Templates:
		list, err := s.machines.ListTemplates(ctx)
		if err != nil {
			return 0, err
		}
		count := 0
		for _, template := range list {
			if found, ok := s.storage.Containing(locations.Templates, template.DiskPath); ok && found.ID == location.ID {
				count++
			}
		}
		return count, nil
	case locations.Provisioners:
		return len(s.provisioners.FamiliesIn(location.Path)), nil
	default:
		return 0, nil
	}
}

func (s *Server) saveStoragePaths(kind locations.Kind, paths map[string]config.StoragePathConfig) error {
	previous := s.cfg.StoragePaths(kind)
	s.cfg.SetStoragePaths(kind, paths)
	section := map[string]any{"provisioning": s.cfg.Provisioning}
	if kind == locations.Templates {
		section = map[string]any{"template_sources": s.cfg.TemplateSources}
	}
	if err := s.cfg.MergeAndSave(section); err != nil {
		s.cfg.SetStoragePaths(kind, previous)
		return err
	}
	return s.cfg.LoadStorageLocations(s.storage, kind)
}

func copyStoragePaths(paths map[string]config.StoragePathConfig) map[string]config.StoragePathConfig {
	out := make(map[string]config.StoragePathConfig, len(paths)+1)
	for id, entry := range paths {
		out[id] = entry
	}
	return out
}

type storagePathDocument struct {
	locations.Location
	ItemCount int `json:"item_count"`
}

type libraryPathsResponse struct {
	Paths      []storagePathDocument `json:"paths"`
	TotalPaths int                   `json:"total_paths"`
}

type libraryPathResponse struct {
	Success     bool                `json:"success"`
	Message     string              `json:"message"`
	StoragePath storagePathDocument `json:"storage_path"`
}

func (s *Server) storagePathDocument(ctx context.Context, location *locations.Location) storagePathDocument {
	count, err := s.storagePathItems(ctx, location)
	if err != nil {
		slog.Warn("count storage path items", "type", location.Type, "id", location.ID, "error", err)
	}
	return storagePathDocument{Location: *location, ItemCount: count}
}

// @Summary		List storage paths of machines, provisioners and templates
// @Description	Minimum role: viewer. Every storage path of the three kinds (type machines | provisioners | templates), the built-in one first. Each kind has exactly one path marked default: new machines, newly imported provisioner families and downloaded or exported templates land there. The built-in path (id builtin) is the folder named by provisioning.machines_dir, provisioning.provisioners_dir or template_sources.local_storage_path; added paths live in provisioning.machines_paths, provisioning.provisioners_paths and template_sources.storage_paths. item_count is the number of machines, provisioner families or templates living in the path. enabled false on a configured path means it is switched off or its folder could not be reached.
// @Tags			Storage Paths
// @Produce		json
// @Param			type	query		string						false	"machines, provisioners or templates"
// @Success		200		{object}	libraryPathsResponse	"Storage paths"
// @Failure		422		{object}	problem.Body				"Unknown type (enum at /type)"
// @Router			/api/storage/paths [get]
func (s *Server) handleListLibraryPaths(w http.ResponseWriter, r *http.Request) {
	kinds := []locations.Kind{locations.Machines, locations.Provisioners, locations.Templates}
	if raw := r.URL.Query().Get("type"); raw != "" {
		if !locations.ValidKind(raw) {
			problem.Invalid(w, problem.Enum("/type", "machines", "provisioners", "templates"))
			return
		}
		kinds = []locations.Kind{locations.Kind(raw)}
	}
	documents := []storagePathDocument{}
	for _, kind := range kinds {
		list := s.storage.List(kind)
		for i := range list {
			documents = append(documents, s.storagePathDocument(r.Context(), &list[i]))
		}
	}
	writeJSON(w, libraryPathsResponse{Paths: documents, TotalPaths: len(documents)})
}

type createLibraryPathRequest struct {
	Type        string `json:"type"`
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Path        string `json:"path"`
	Enabled     *bool  `json:"enabled"`
	Default     bool   `json:"default"`
}

// @Summary		Add a storage path
// @Description	Minimum role: operator. Adds a folder as a storage path of one kind (type machines | provisioners | templates), creates the folder when absent, and writes the entry into the configuration file (provisioning.machines_paths, provisioning.provisioners_paths or template_sources.storage_paths) so it survives a restart. It takes effect at once, no restart. id is the entry's key (lower-case letters, digits and underscores; builtin is reserved); when absent it is derived from display_name. default true makes it the path new items land in; items already made stay where they are.
// @Tags			Storage Paths
// @Accept			json
// @Produce		json
// @Param			body	body		createLibraryPathRequest	true	"The new storage path"
// @Success		201		{object}	libraryPathResponse	"Storage path added"
// @Failure		400		{object}	problem.Body				"Unreadable body"
// @Failure		422		{object}	problem.Body				"type outside machines, provisioners, templates (enum at /type); display_name or path missing (required); id not lower-case letters, digits and underscores or builtin (pattern storagePathId at /id); path not absolute (pattern absolutePath at /path); the folder cannot be created (writable at /path)"
// @Failure		409		{object}	problem.Body				"The id or the folder is already a storage path of this type (unique at /id or /path, scope the type)"
// @Router			/api/storage/paths [post]
func (s *Server) handleCreateLibraryPath(w http.ResponseWriter, r *http.Request) {
	var body createLibraryPathRequest
	if err := decodeBody(r, &body); err != nil {
		problem.BadRequest(w)
		return
	}
	failures := []problem.Error{}
	if !locations.ValidKind(body.Type) {
		failures = append(failures, problem.Enum("/type", "machines", "provisioners", "templates"))
	}
	if body.DisplayName == "" {
		failures = append(failures, problem.Required("/display_name"))
	}
	if body.Path == "" {
		failures = append(failures, problem.Required("/path"))
	}
	id := body.ID
	if id == "" {
		id = strings.Trim(storagePathSlug.ReplaceAllString(strings.ToLower(body.DisplayName), "_"), "_")
	}
	if !config.ValidStoragePathID(id) {
		failures = append(failures, problem.Pattern("/id", "storagePathId"))
	}
	clean, err := safepath.CleanAbs(body.Path)
	if err != nil && body.Path != "" {
		failures = append(failures, problem.Pattern("/path", "absolutePath"))
	}
	if len(failures) > 0 {
		problem.Invalid(w, failures...)
		return
	}
	kind := locations.Kind(body.Type)
	for _, existing := range s.storage.List(kind) {
		if existing.ID == id {
			problem.Invalid(w, problem.Unique("/id", body.Type))
			return
		}
		if locations.SamePath(existing.Path, clean) {
			problem.Invalid(w, problem.Unique("/path", body.Type))
			return
		}
	}
	if merr := os.MkdirAll(clean, 0o750); merr != nil {
		failure := problem.Rule("/path", "writable", map[string]any{"user": ""})
		failure.Detail = "Cannot create storage directory: " + merr.Error()
		problem.Invalid(w, failure)
		return
	}

	enabled := body.Enabled == nil || *body.Enabled
	paths := copyStoragePaths(s.cfg.StoragePaths(kind))
	if body.Default && enabled {
		for key, entry := range paths {
			entry.Default = false
			paths[key] = entry
		}
	}
	paths[id] = config.StoragePathConfig{
		DisplayName: body.DisplayName,
		Path:        clean,
		Enabled:     enabled,
		Default:     body.Default && enabled,
	}
	if serr := s.saveStoragePaths(kind, paths); serr != nil {
		slog.Error("save storage path", "type", kind, "id", id, "error", serr)
		taskError(w, http.StatusInternalServerError, "Failed to save the storage path")
		return
	}

	slog.Info("storage path added", "type", kind, "id", id, "path", clean,
		"by", auth.FromContext(r.Context()).Name)
	location, _ := s.storage.Get(kind, id)
	writeJSONStatus(w, http.StatusCreated, libraryPathResponse{
		Success:     true,
		Message:     "Storage path '" + body.DisplayName + "' added",
		StoragePath: s.storagePathDocument(r.Context(), &location),
	})
}

type updateLibraryPathRequest struct {
	DisplayName *string `json:"display_name"`
	Enabled     *bool   `json:"enabled"`
	Default     *bool   `json:"default"`
}

// @Summary		Rename, enable or disable a storage path, or make it the default
// @Description	Minimum role: operator. display_name, enabled and default only; the folder is the path's identity and never changes here. default true makes this path the one new items land in and clears the flag on every other path of the type; default false hands the default back to the built-in path. Items already made stay where they are. The built-in path (id builtin) takes default true alone. Switching a path off is refused while machines, provisioner families or templates live in it. The change is written into the configuration file and takes effect at once.
// @Tags			Storage Paths
// @Accept			json
// @Produce		json
// @Param			type	path		string						true	"machines, provisioners or templates"
// @Param			id		path		string						true	"Storage path id"
// @Param			body	body		updateLibraryPathRequest	true	"The members to change"
// @Success		200		{object}	libraryPathResponse	"Storage path updated"
// @Failure		400		{object}	problem.Body				"Unreadable body"
// @Failure		404		{object}	problem.Body				"Unknown type or storage path not found"
// @Failure		422		{object}	problem.Body				"Nothing to change, a change the built-in path does not take, an empty display_name, default on a disabled path, or a folder that cannot be reached"
// @Failure		409		{object}	problem.Body				"Items still live in the path"
// @Router			/api/storage/paths/{type}/{id} [put]
func (s *Server) handleUpdateLibraryPath(w http.ResponseWriter, r *http.Request) {
	if !locations.ValidKind(r.PathValue("type")) {
		problem.NotFound(w)
		return
	}
	kind := locations.Kind(r.PathValue("type"))
	id := r.PathValue("id")
	var body updateLibraryPathRequest
	if err := decodeBody(r, &body); err != nil {
		problem.BadRequest(w)
		return
	}
	if body.DisplayName == nil && body.Enabled == nil && body.Default == nil {
		problem.Invalid(w, problem.Required("/display_name"), problem.Required("/enabled"), problem.Required("/default"))
		return
	}
	location, found := s.storage.Get(kind, id)
	if !found {
		problem.NotFound(w)
		return
	}

	paths := copyStoragePaths(s.cfg.StoragePaths(kind))
	clearDefaults := func() {
		for key, entry := range paths {
			entry.Default = false
			paths[key] = entry
		}
	}
	if location.Builtin {
		if body.DisplayName != nil || body.Enabled != nil || body.Default == nil || !*body.Default {
			failure := problem.Enum("/default", "true")
			failure.Detail = "The built-in storage path takes default: true only"
			problem.Invalid(w, failure)
			return
		}
		clearDefaults()
	} else {
		entry := paths[id]
		if body.DisplayName != nil {
			if *body.DisplayName == "" {
				problem.Invalid(w, problem.Rule("/display_name", "minLength", map[string]any{"minLength": 1}))
				return
			}
			entry.DisplayName = *body.DisplayName
		}
		if body.Enabled != nil {
			if !*body.Enabled && entry.Enabled {
				count, cerr := s.storagePathItems(r.Context(), &location)
				if cerr != nil {
					taskError(w, http.StatusInternalServerError, "Failed to count the items in the storage path")
					return
				}
				if count > 0 {
					taskError(w, http.StatusConflict, strconv.Itoa(count)+
						" item(s) still live in this storage path — remove them before switching it off")
					return
				}
			}
			entry.Enabled = *body.Enabled
			if !entry.Enabled {
				entry.Default = false
			}
		}
		if body.Default != nil {
			if *body.Default && !entry.Enabled {
				failure := problem.Enum("/default", "false")
				failure.Detail = "A disabled storage path cannot be the default"
				problem.Invalid(w, failure)
				return
			}
			if *body.Default {
				clearDefaults()
			}
			entry.Default = *body.Default
		}
		if entry.Enabled {
			if merr := os.MkdirAll(entry.Path, 0o750); merr != nil {
				failure := problem.Rule("/enabled", "writable", map[string]any{"user": ""})
				failure.Detail = "Cannot reach the storage directory: " + merr.Error()
				problem.Invalid(w, failure)
				return
			}
		}
		paths[id] = entry
	}
	if serr := s.saveStoragePaths(kind, paths); serr != nil {
		slog.Error("save storage path", "type", kind, "id", id, "error", serr)
		taskError(w, http.StatusInternalServerError, "Failed to save the storage path")
		return
	}

	slog.Info("storage path updated", "type", kind, "id", id,
		"by", auth.FromContext(r.Context()).Name)
	updated, _ := s.storage.Get(kind, id)
	writeJSON(w, libraryPathResponse{
		Success:     true,
		Message:     "Storage path '" + updated.DisplayName + "' updated",
		StoragePath: s.storagePathDocument(r.Context(), &updated),
	})
}

type deleteLibraryPathResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// @Summary		Remove a storage path
// @Description	Minimum role: operator. Removes the entry from the configuration file; the folder and whatever is in it stay on disk untouched. Refused while machines, provisioner families or templates live in the path, so nothing can be orphaned: remove or delete them first. The built-in path is never removed. When the removed path was the default, the built-in path becomes the default.
// @Tags			Storage Paths
// @Produce		json
// @Param			type	path		string						true	"machines, provisioners or templates"
// @Param			id		path		string						true	"Storage path id"
// @Success		200		{object}	deleteLibraryPathResponse	"Storage path removed"
// @Failure		403		{object}	problem.Body				"The built-in path is never removed"
// @Failure		404		{object}	problem.Body				"Unknown type or storage path not found"
// @Failure		409		{object}	problem.Body				"Items still live in the path"
// @Router			/api/storage/paths/{type}/{id} [delete]
func (s *Server) handleDeleteLibraryPath(w http.ResponseWriter, r *http.Request) {
	if !locations.ValidKind(r.PathValue("type")) {
		problem.NotFound(w)
		return
	}
	kind := locations.Kind(r.PathValue("type"))
	id := r.PathValue("id")
	location, found := s.storage.Get(kind, id)
	if !found {
		problem.NotFound(w)
		return
	}
	if location.Builtin {
		problem.Detail(w, http.StatusForbidden, "The built-in storage path cannot be removed")
		return
	}
	count, err := s.storagePathItems(r.Context(), &location)
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to count the items in the storage path")
		return
	}
	if count > 0 {
		taskError(w, http.StatusConflict, strconv.Itoa(count)+
			" item(s) still live in this storage path — remove them before removing the path")
		return
	}

	paths := copyStoragePaths(s.cfg.StoragePaths(kind))
	delete(paths, id)
	if serr := s.saveStoragePaths(kind, paths); serr != nil {
		slog.Error("remove storage path", "type", kind, "id", id, "error", serr)
		taskError(w, http.StatusInternalServerError, "Failed to remove the storage path")
		return
	}
	slog.Info("storage path removed", "type", kind, "id", id, "path", location.Path,
		"by", auth.FromContext(r.Context()).Name)
	writeJSON(w, deleteLibraryPathResponse{
		Success: true,
		Message: "Storage path '" + location.DisplayName + "' removed; its folder stays on disk",
	})
}
