package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/Makr91/hyperweaver-agent/internal/assets"
	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// ---- SHI extras ----

// handleHCLDownload: POST /artifacts/hcl-download — the SHI download-portal
// flow (token exchange with rotation persisted, catalog lookup, verified
// streamed download into the kind's default location).
//
//	@Summary		Download a file from the HCL portal
//	@Description	Minimum role: operator. Queues an hcl_download task (SHI's HCLDownloader flow): exchanges the named hcl_download_portal_api_keys secret's refresh token (the ROTATED token is persisted back immediately — SHI's critical rule), looks the file up in the HCL catalog by EXACT name (the catalog's sha256 is authoritative and overwrites the expectation), streams the verified download into the kind's DEFAULT location (the built-in cache). Failures carry contextual guidance (expired key vs un-accepted HCL license); no auto-retry.
//	@Tags			Artifacts
//	@Accept			json
//	@Produce		json
//	@Param			body	body	assets.HCLDownloadMetadata	true	"HCL portal key, filename, role, and kind"
//	@Success		202	"HCL download task queued"
//	@Failure		400	"Invalid key_name/role/kind/filename"
//	@Failure		503	"Artifact storage is disabled"
//	@Router			/artifacts/hcl-download [post]
func (s *Server) handleHCLDownload(w http.ResponseWriter, r *http.Request) {
	var meta assets.HCLDownloadMetadata
	if err := decodeBody(r, &meta); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if err := meta.Validate(); err != nil {
		taskError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.queueArtifactTask(w, r, assets.OpHCLDownload, tasks.PriorityMedium, meta,
		"HCL download task queued successfully")
}

// registerArtifactRequest is POST /artifacts/register's body.
type registerArtifactRequest struct {
	Path string `json:"path"`
	// StoragePathID or a valid Type selects the destination location.
	StoragePathID string `json:"storage_path_id"`
	Type          string `json:"type"`
	// Role is required when the destination is an installer-family location.
	Role     string `json:"role"`
	Filename string `json:"filename"`
	Move     bool   `json:"move"`
}

// handleRegisterArtifact: POST /artifacts/register — copies (or moves) an
// agent-host file into a location and hashes it (SHI's add-file picker for
// Direct mode).
//
//	@Summary		Register an agent-host file
//	@Description	Minimum role: operator. SHI's add-file picker flow for Direct-mode installs: copies (move: true moves) the named agent-host file into a storage location — by id, or the type's default location — and hashes it. Synchronous.
//	@Tags			Artifacts
//	@Accept			json
//	@Produce		json
//	@Param			body	body	registerArtifactRequest	true	"Agent-host file path and destination"
//	@Success		201	"File registered and hashed ({success, artifact, message})"
//	@Failure		400	"Unusable path/filename, missing role, disabled location, or neither storage_path_id nor a valid type"
//	@Failure		404	"Storage location not found"
//	@Failure		503	"Artifact storage is disabled"
//	@Router			/artifacts/register [post]
func (s *Server) handleRegisterArtifact(w http.ResponseWriter, r *http.Request) {
	var body registerArtifactRequest
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	source, err := safepath.CleanAbs(body.Path)
	if err != nil {
		taskError(w, http.StatusBadRequest, "path is not usable")
		return
	}
	if info, serr := os.Stat(source); serr != nil || info.IsDir() {
		taskError(w, http.StatusBadRequest, "path does not name a file on the agent host")
		return
	}

	var location *assets.Location
	switch {
	case body.StoragePathID != "":
		location, err = s.assets.GetLocation(r.Context(), body.StoragePathID)
	case assets.ValidKind(body.Type):
		location, err = s.assets.DefaultLocation(r.Context(), body.Type)
	default:
		taskError(w, http.StatusBadRequest, "storage_path_id or a valid type is required")
		return
	}
	if err != nil {
		taskError(w, http.StatusNotFound, "Storage location not found")
		return
	}
	if !location.Enabled {
		taskError(w, http.StatusBadRequest, "Storage location is disabled")
		return
	}

	filename := body.Filename
	if filename == "" {
		filename = filepath.Base(source)
	}
	if !assets.ValidFilename(filename) {
		taskError(w, http.StatusBadRequest, "filename is not usable")
		return
	}
	if assets.RoleKeyed(location.Type) && !assets.ValidRole(body.Role) {
		taskError(w, http.StatusBadRequest, "role is required for "+location.Type+" locations")
		return
	}

	artifact, err := s.assets.Ingest(r.Context(), location, body.Role, filename, source, body.Move)
	if err != nil {
		slog.Error("artifact registration failed", "path", source, "error", err)
		taskError(w, http.StatusInternalServerError, "Registration failed: "+err.Error())
		return
	}
	slog.Info("artifact registered", "filename", artifact.Filename, "sha256", artifact.SHA256,
		"location", location.Name, "by", auth.FromContext(r.Context()).Name)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if werr := json.NewEncoder(w).Encode(map[string]any{
		"success":  true,
		"artifact": artifactJSON(artifact, location),
		"message":  "File registered and hashed successfully",
	}); werr != nil {
		slog.Error("write register response", "error", werr)
	}
}
