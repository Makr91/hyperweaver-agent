package server

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/Makr91/hyperweaver-agent/internal/assets"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// handleScanArtifacts: POST /artifacts/scan (async task).
//
//	@Summary		Scan storage locations
//	@Description	Minimum role: operator. Queues artifact_scan over one location (storage_path_id), one type, or every enabled location: new files hashed and registered, vanished files marked missing (expectation rows always survive as file_exists:false; remove_orphaned deletes expectation-less rows), verify_checksums re-hashes every present file — the task FAILS when any file mismatches its expectation. Automatic startup/periodic scans run agent-side without task rows.
//	@Tags			Artifacts
//	@Accept			json
//	@Produce		json
//	@Param			body	body	assets.ScanTaskMetadata	false	"Scan scope and options"
//	@Success		202	"Scan task queued"
//	@Failure		400	"Invalid type"
//	@Failure		404	"Storage location not found"
//	@Failure		503	"Artifact storage is disabled"
//	@Router			/artifacts/scan [post]
func (s *Server) handleScanArtifacts(w http.ResponseWriter, r *http.Request) {
	var meta assets.ScanTaskMetadata
	if r.ContentLength > 0 {
		if err := decodeBody(r, &meta); err != nil {
			taskError(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
	}
	message := "Scan task created for all storage locations"
	if meta.LocationID != "" {
		location, err := s.assets.GetLocation(r.Context(), meta.LocationID)
		if errors.Is(err, assets.ErrLocationNotFound) {
			taskError(w, http.StatusNotFound, "Storage location not found")
			return
		}
		if err != nil {
			taskError(w, http.StatusInternalServerError, "Failed to load storage location")
			return
		}
		message = "Scan task created for storage location '" + location.Name + "'"
	} else if meta.Type != "" {
		if !assets.ValidKind(meta.Type) {
			taskError(w, http.StatusBadRequest, "type must be one of iso, image, installer, fixpack, hotfix")
			return
		}
		message = "Scan task created for " + meta.Type + " locations"
	}
	s.queueArtifactTask(w, r, assets.OpScan, tasks.PriorityBackground, meta, message)
}

// deleteArtifactFilesRequest is DELETE /artifacts/files's body.
type deleteArtifactFilesRequest struct {
	ArtifactIDs []int64 `json:"artifact_ids"`
	// DeleteFiles also removes the files from disk (default true).
	DeleteFiles *bool `json:"delete_files"`
	// Force keeps going past individual file errors.
	Force bool `json:"force"`
}

// handleDeleteArtifactFiles: DELETE /artifacts/files (batch, async task).
//
//	@Summary		Delete artifacts (batch)
//	@Description	Minimum role: operator. Queues artifact_delete_file over the named rows; delete_files (default true) removes the files from disk too; force keeps going past individual file errors. Location stats refresh.
//	@Tags			Artifacts
//	@Accept			json
//	@Produce		json
//	@Param			body	body	deleteArtifactFilesRequest	true	"Artifact ids and deletion options"
//	@Success		202	"Deletion task queued"
//	@Failure		400	"Empty artifact_ids"
//	@Failure		503	"Artifact storage is disabled"
//	@Router			/artifacts/files [delete]
func (s *Server) handleDeleteArtifactFiles(w http.ResponseWriter, r *http.Request) {
	var body deleteArtifactFilesRequest
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if len(body.ArtifactIDs) == 0 {
		taskError(w, http.StatusBadRequest, "artifact_ids array is required and must not be empty")
		return
	}
	meta := assets.DeleteFilesMetadata{
		ArtifactIDs: body.ArtifactIDs,
		DeleteFiles: body.DeleteFiles == nil || *body.DeleteFiles,
		Force:       body.Force,
	}
	s.queueArtifactTask(w, r, assets.OpDeleteFiles, tasks.PriorityMedium, meta,
		fmt.Sprintf("Deletion task created for %d artifact(s)", len(body.ArtifactIDs)))
}
