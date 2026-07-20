package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/assets"
	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// ---- transfers, downloads, uploads ----

// transferArtifactRequest is the POST /artifacts/{id}/move and
// /artifacts/{id}/copy body.
type transferArtifactRequest struct {
	DestinationID string `json:"destination_storage_location_id"`
}

// handleArtifactAction: POST /artifacts/{id}/{action} — move and copy share
// one pattern (separate literal patterns conflict with /artifacts/upload/
// {taskId} and panic ServeMux at registration).
//
//	@Summary		Move an artifact to another location
//	@Description	Minimum role: operator. Queues artifact_move: rename (copy+delete across volumes) into a SAME-TYPE destination; the row's location and path rewrite; both locations' stats refresh.
//	@Tags			Artifacts
//	@Accept			json
//	@Produce		json
//	@Param			id		path	int	true	"Artifact id"
//	@Param			body	body	transferArtifactRequest	true	"Destination storage location id"
//	@Success		202	"Move task queued"
//	@Failure		400	"Missing destination"
//	@Failure		404	"Artifact or storage location not found"
//	@Failure		503	"Artifact storage is disabled"
//	@Router			/artifacts/{id}/move [post]
func (s *Server) handleArtifactAction(w http.ResponseWriter, r *http.Request) {
	switch r.PathValue("action") {
	case "move":
		s.queueTransfer(w, r, assets.OpMove, "Artifact move task created successfully.")
	case "copy":
		s.queueTransfer(w, r, assets.OpCopy, "Artifact copy task created successfully.")
	default:
		taskError(w, http.StatusNotFound, "Unknown artifact action (move or copy)")
	}
}

// queueTransfer validates the destination and queues a same-type move or
// copy; this swag block documents the copy action (the move action rides
// handleArtifactAction, which shares this helper).
//
//	@Summary		Copy an artifact to another location
//	@Description	Minimum role: operator. Queues artifact_copy: duplicates the file into a SAME-TYPE destination and registers the copy as a new row.
//	@Tags			Artifacts
//	@Accept			json
//	@Produce		json
//	@Param			id		path	int	true	"Artifact id"
//	@Param			body	body	transferArtifactRequest	true	"Destination storage location id"
//	@Success		202	"Copy task queued"
//	@Failure		400	"Missing destination"
//	@Failure		404	"Artifact or storage location not found"
//	@Failure		503	"Artifact storage is disabled"
//	@Router			/artifacts/{id}/copy [post]
func (s *Server) queueTransfer(w http.ResponseWriter, r *http.Request, operation, message string) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		taskError(w, http.StatusNotFound, "Artifact not found")
		return
	}
	var body transferArtifactRequest
	if derr := decodeBody(r, &body); derr != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.DestinationID == "" {
		taskError(w, http.StatusBadRequest, "destination_storage_location_id is required")
		return
	}
	if _, gerr := s.assets.Get(r.Context(), id); errors.Is(gerr, assets.ErrNotFound) {
		taskError(w, http.StatusNotFound, "Artifact not found")
		return
	}
	if _, gerr := s.assets.GetLocation(r.Context(), body.DestinationID); errors.Is(gerr, assets.ErrLocationNotFound) {
		taskError(w, http.StatusNotFound, "Storage location not found")
		return
	}
	s.queueArtifactTask(w, r, operation, tasks.PriorityMedium,
		assets.TransferMetadata{ArtifactID: id, DestinationID: body.DestinationID}, message)
}

// downloadArtifactRequest is POST /artifacts/download's body.
type downloadArtifactRequest struct {
	URL           string `json:"url"`
	StoragePathID string `json:"storage_path_id"`
	// Role is required when the destination is an installer-family location.
	Role     string `json:"role"`
	Filename string `json:"filename"`
	// Checksum is the expected SHA-256 (64 hex chars).
	Checksum          string `json:"checksum"`
	ChecksumAlgorithm string `json:"checksum_algorithm"`
	OverwriteExisting bool   `json:"overwrite_existing"`
	// ResourceName names a custom_resource_url secret for HTTP Basic auth.
	ResourceName string `json:"resource_name"`
}

// handleArtifactDownloadFromURL: POST /artifacts/download (async task).
//
//	@Summary		Download a URL into a storage location
//	@Description	Minimum role: operator. Queues artifact_download: streamed with live progress ({downloaded_mb, total_mb, speed_mbps, eta_seconds} in progress_info), hashed DURING the stream, verified against checksum when given (mismatch discards the file — never promoted, no auto-retry). role is REQUIRED when the destination is an installer-family location. resource_name names a custom_resource_url secret whose Basic-auth pair authenticates the fetch.
//	@Tags			Artifacts
//	@Accept			json
//	@Produce		json
//	@Param			body	body	downloadArtifactRequest	true	"Download source URL and destination"
//	@Success		202	"Download task queued"
//	@Failure		400	"Invalid url/filename/checksum, missing role, disabled location, or non-sha256 algorithm"
//	@Failure		404	"Storage location not found"
//	@Failure		503	"Artifact storage is disabled"
//	@Router			/artifacts/download [post]
func (s *Server) handleArtifactDownloadFromURL(w http.ResponseWriter, r *http.Request) {
	var body downloadArtifactRequest
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.ChecksumAlgorithm != "" && body.ChecksumAlgorithm != "sha256" {
		taskError(w, http.StatusBadRequest, "checksum_algorithm must be sha256 (the system's one algorithm)")
		return
	}
	meta := assets.DownloadMetadata{
		URL: body.URL, LocationID: body.StoragePathID, Role: body.Role,
		Filename: body.Filename, Checksum: body.Checksum,
		OverwriteExisting: body.OverwriteExisting, ResourceName: body.ResourceName,
	}
	if err := meta.Validate(); err != nil {
		taskError(w, http.StatusBadRequest, err.Error())
		return
	}
	location, err := s.assets.GetLocation(r.Context(), meta.LocationID)
	if errors.Is(err, assets.ErrLocationNotFound) {
		taskError(w, http.StatusNotFound, "Storage location not found")
		return
	}
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to load storage location")
		return
	}
	if !location.Enabled {
		taskError(w, http.StatusBadRequest, "Storage location is disabled")
		return
	}
	if assets.RoleKeyed(location.Type) && !assets.ValidRole(meta.Role) {
		taskError(w, http.StatusBadRequest, "role is required for "+location.Type+" locations")
		return
	}
	s.queueArtifactTask(w, r, assets.OpDownload, tasks.PriorityMedium, meta,
		"Download task created for '"+meta.Filename+"'")
}

// prepareUploadRequest is POST /artifacts/upload/prepare's body.
type prepareUploadRequest struct {
	Filename      string `json:"filename"`
	Size          int64  `json:"size"`
	StoragePathID string `json:"storage_path_id"`
	// Role is required when the destination is an installer-family location.
	Role              string `json:"role"`
	Checksum          string `json:"checksum"`
	ChecksumAlgorithm string `json:"checksum_algorithm"`
	OverwriteExisting bool   `json:"overwrite_existing"`
}

// prepareUploadLocation is the destination summary in prepareUploadResponse.
type prepareUploadLocation struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Path string `json:"path"`
}

// prepareUploadResponse is POST /artifacts/upload/prepare's answer.
type prepareUploadResponse struct {
	Success         bool                  `json:"success"`
	TaskID          string                `json:"task_id"`
	UploadURL       string                `json:"upload_url"`
	ExpiresAt       string                `json:"expires_at"`
	StorageLocation prepareUploadLocation `json:"storage_location"`
}

// handlePrepareArtifactUpload: POST /artifacts/upload/prepare — mints the
// prepared task and the upload URL (zoneweaver's two-step upload).
//
//	@Summary		Prepare an artifact upload
//	@Description	Minimum role: operator. Mints an artifact_upload task in PREPARED status (the queue never dispatches it) and returns the upload URL — zoneweaver's two-step upload for large files. The prepared task dies on agent restart; size is capped by artifact_storage.max_upload_gb.
//	@Tags			Artifacts
//	@Accept			json
//	@Produce		json
//	@Param			body	body	prepareUploadRequest	true	"Upload filename, size, and destination"
//	@Success		200	{object}	prepareUploadResponse	"Upload prepared"
//	@Failure		400	"Missing fields, unusable filename, over the size cap, disabled location, or missing role"
//	@Failure		404	"Storage location not found"
//	@Failure		503	"Artifact storage is disabled"
//	@Router			/artifacts/upload/prepare [post]
func (s *Server) handlePrepareArtifactUpload(w http.ResponseWriter, r *http.Request) {
	var body prepareUploadRequest
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.Filename == "" || body.Size <= 0 || body.StoragePathID == "" {
		taskError(w, http.StatusBadRequest, "filename, size, and storage_path_id are required")
		return
	}
	if !assets.ValidFilename(body.Filename) {
		taskError(w, http.StatusBadRequest, "filename is not usable")
		return
	}
	if body.ChecksumAlgorithm != "" && body.ChecksumAlgorithm != "sha256" {
		taskError(w, http.StatusBadRequest, "checksum_algorithm must be sha256 (the system's one algorithm)")
		return
	}
	maxBytes := int64(s.cfg.ArtifactStorage.MaxUploadGB) << 30
	if body.Size > maxBytes {
		taskError(w, http.StatusBadRequest, fmt.Sprintf(
			"File size exceeds the %dGB upload limit", s.cfg.ArtifactStorage.MaxUploadGB))
		return
	}
	location, err := s.assets.GetLocation(r.Context(), body.StoragePathID)
	if errors.Is(err, assets.ErrLocationNotFound) {
		taskError(w, http.StatusNotFound, "Storage location not found")
		return
	}
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to load storage location")
		return
	}
	if !location.Enabled {
		taskError(w, http.StatusBadRequest, "Storage location is disabled")
		return
	}
	if assets.RoleKeyed(location.Type) && !assets.ValidRole(body.Role) {
		taskError(w, http.StatusBadRequest, "role is required for "+location.Type+" locations")
		return
	}

	raw, err := json.Marshal(assets.UploadMetadata{
		OriginalName: body.Filename, Size: body.Size, LocationID: location.ID,
		Role: body.Role, Checksum: body.Checksum, OverwriteExisting: body.OverwriteExisting,
	})
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to prepare upload")
		return
	}
	metadata := string(raw)
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: "artifact",
		Operation:   assets.OpUpload,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   auth.FromContext(r.Context()).Name,
		Metadata:    &metadata,
		Prepared:    true,
	})
	if err != nil {
		slog.Error("prepare artifact upload", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to prepare upload")
		return
	}
	writeJSON(w, prepareUploadResponse{
		Success:   true,
		TaskID:    task.ID,
		UploadURL: "/artifacts/upload/" + task.ID,
		ExpiresAt: time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339),
		StorageLocation: prepareUploadLocation{
			ID: location.ID, Name: location.Name, Path: location.Path,
		},
	})
}

// uploadCompleteFile is the landed-file summary in uploadCompleteResponse.
type uploadCompleteFile struct {
	Name          string `json:"name"`
	Size          int64  `json:"size"`
	FinalLocation string `json:"final_location"`
}

// uploadCompleteResponse is POST /artifacts/upload/{taskId}'s answer.
type uploadCompleteResponse struct {
	Success bool               `json:"success"`
	Message string             `json:"message"`
	TaskID  string             `json:"task_id"`
	File    uploadCompleteFile `json:"file"`
}

// handleUploadArtifactToTask: POST /artifacts/upload/{taskId} — streams the
// multipart file to its final location and flips the prepared task to
// pending; the artifact_upload executor hashes and registers it.
//
//	@Summary		Upload the file to a prepared task
//	@Description	Minimum role: operator. Streams the multipart "file" part to its final location path and flips the prepared task to pending — the artifact_upload executor then hashes, verifies the prepare's checksum (mismatch deletes the file and fails the task), and registers the row. Body capped by artifact_storage.max_upload_gb.
//	@Tags			Artifacts
//	@Accept			mpfd
//	@Produce		json
//	@Param			taskId	path		string	true	"Prepared upload task id"
//	@Param			file	formData	file	true	"The artifact file part"
//	@Success		202	{object}	uploadCompleteResponse	"File landed; processing task queued"
//	@Failure		400	"Task not prepared, wrong task type, malformed multipart body, file already exists, or no file part"
//	@Failure		404	"Upload task or storage location not found"
//	@Failure		503	"Artifact storage is disabled"
//	@Router			/artifacts/upload/{taskId} [post]
func (s *Server) handleUploadArtifactToTask(w http.ResponseWriter, r *http.Request) {
	task, err := s.tasks.Store().Get(r.Context(), r.PathValue("taskId"))
	if errors.Is(err, tasks.ErrNotFound) {
		taskError(w, http.StatusNotFound, "Upload task not found")
		return
	}
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to load upload task")
		return
	}
	if task.Operation != assets.OpUpload {
		taskError(w, http.StatusBadRequest, "Invalid task type for upload")
		return
	}
	if task.Status != tasks.StatusPrepared {
		taskError(w, http.StatusBadRequest, "Task is not in prepared state (current: "+task.Status+")")
		return
	}
	var meta assets.UploadMetadata
	if len(task.Metadata) == 0 || json.Unmarshal(task.Metadata, &meta) != nil {
		taskError(w, http.StatusInternalServerError, "Upload task metadata is unreadable")
		return
	}
	location, err := s.assets.GetLocation(r.Context(), meta.LocationID)
	if err != nil {
		taskError(w, http.StatusNotFound, "Storage location not found")
		return
	}
	if !location.Enabled {
		taskError(w, http.StatusBadRequest, "Storage location is disabled")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, int64(s.cfg.ArtifactStorage.MaxUploadGB)<<30)
	reader, err := r.MultipartReader()
	if err != nil {
		taskError(w, http.StatusBadRequest, "Request must be multipart/form-data")
		return
	}
	landed := false
	var size int64
	for {
		part, perr := reader.NextPart()
		if errors.Is(perr, io.EOF) {
			break
		}
		if perr != nil {
			taskError(w, http.StatusBadRequest, "Malformed multipart body: "+perr.Error())
			return
		}
		if part.FormName() != "file" {
			_, _ = io.Copy(io.Discard, part)
			_ = part.Close()
			continue
		}
		finalPath, written, lerr := assets.LandUpload(location, meta.Role, meta.OriginalName, part, meta.OverwriteExisting)
		_ = part.Close()
		if lerr != nil {
			taskError(w, http.StatusBadRequest, "File upload failed: "+lerr.Error())
			return
		}
		meta.FinalPath = finalPath
		size = written
		landed = true
		break
	}
	if !landed {
		taskError(w, http.StatusBadRequest, `multipart body carries no "file" part`)
		return
	}

	meta.Size = size
	meta.UploadCompleted = true
	raw, err := json.Marshal(meta)
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to update upload task")
		return
	}
	if uerr := s.tasks.Store().UpdateMetadata(r.Context(), task.ID, string(raw)); uerr != nil {
		taskError(w, http.StatusInternalServerError, "Failed to update upload task")
		return
	}
	if ok, qerr := s.tasks.Store().Requeue(r.Context(), task.ID); qerr != nil || !ok {
		taskError(w, http.StatusInternalServerError, "Failed to queue upload processing")
		return
	}

	slog.Info("artifact upload landed", "filename", meta.OriginalName, "task_id", task.ID,
		"by", auth.FromContext(r.Context()).Name)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	if werr := json.NewEncoder(w).Encode(uploadCompleteResponse{
		Success: true,
		Message: "Upload completed for '" + meta.OriginalName + "'",
		TaskID:  task.ID,
		File: uploadCompleteFile{
			Name: meta.OriginalName, Size: size, FinalLocation: meta.FinalPath,
		},
	}); werr != nil {
		slog.Error("write upload response", "error", werr)
	}
}

// handleDownloadArtifactFile: GET /artifacts/{id}/download — streams the
// file to the client.
//
//	@Summary		Download an artifact file
//	@Description	Minimum role: viewer. Streams the file (Content-Disposition attachment); refreshes last_verified.
//	@Tags			Artifacts
//	@Produce		octet-stream
//	@Param			id	path	int	true	"Artifact id"
//	@Success		200	{file}	binary	"The file"
//	@Failure		404	"Artifact not found, expectation-only, or file gone from disk"
//	@Failure		503	"Artifact storage is disabled"
//	@Router			/artifacts/{id}/download [get]
func (s *Server) handleDownloadArtifactFile(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		taskError(w, http.StatusNotFound, "Artifact not found")
		return
	}
	artifact, err := s.assets.Get(r.Context(), id)
	if errors.Is(err, assets.ErrNotFound) {
		taskError(w, http.StatusNotFound, "Artifact not found")
		return
	}
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to load artifact")
		return
	}
	if artifact.Path == "" {
		taskError(w, http.StatusNotFound, "Artifact has no file (expectation only)")
		return
	}
	file, err := os.Open(filepath.Clean(artifact.Path))
	if err != nil {
		taskError(w, http.StatusNotFound, "Artifact file not found on disk")
		return
	}
	defer func() {
		_ = file.Close()
	}()
	info, err := file.Stat()
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to read artifact file")
		return
	}

	w.Header().Set("Content-Disposition", `attachment; filename="`+artifact.Filename+`"`)
	w.Header().Set("Content-Type", artifact.MimeType())
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	if _, cerr := io.Copy(w, file); cerr != nil {
		slog.Warn("artifact stream interrupted", "id", id, "error", cerr)
		return
	}
	_ = s.assets.TouchVerified(r.Context(), artifact.ID)
}
