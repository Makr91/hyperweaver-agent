package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/assets"
	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// The registries a missing artifact can be fetched from.
const (
	artifactSourceBoxVault = "boxvault"
	artifactSourceHCL      = "hcl"
	artifactSourceCustom   = "custom"
)

func (s *Server) registrySourceForURL(raw string) *machines.TemplateSource {
	for _, source := range s.templateSources() {
		if source.Enabled && strings.HasPrefix(raw, strings.TrimRight(source.URL, "/")+"/") {
			return &source
		}
	}
	return nil
}

// artifactSource answers where a missing row's file can be fetched from: boxvault for a source_url under a configured box registry, hcl for the HCL portal and for a bundled expectation with no URL, custom for any other URL; empty for a present file or a row with nothing to fetch.
func (s *Server) artifactSource(a *assets.Artifact) string {
	if a.Exists && a.Path != "" {
		return ""
	}
	switch {
	case a.SourceURL == "":
		if a.ExpectedSHA256 != "" {
			return artifactSourceHCL
		}
		return ""
	case s.registrySourceForURL(a.SourceURL) != nil:
		return artifactSourceBoxVault
	case strings.Contains(a.SourceURL, "hcltechsw.com"):
		return artifactSourceHCL
	default:
		return artifactSourceCustom
	}
}

type fetchArtifactResponse struct {
	Success    bool   `json:"success"`
	TaskID     string `json:"task_id"`
	ArtifactID int64  `json:"artifact_id"`
	Filename   string `json:"filename"`
	Source     string `json:"source"`
	Status     string `json:"status"`
}

// fetchArtifact: POST /api/artifacts/{id}/fetch.
//
//	@Summary		Fetch a missing artifact from its source
//	@Description	Minimum role: operator. Queues the download of a known row whose file is not on this host, from the source the row names: boxvault queues artifact_registry_download as the signed-in person for the file its source_url names on the configured box registry; hcl queues hcl_download under the first hcl_download_portal_api_keys secret; custom queues artifact_download of the source_url. The file lands in the row's own location under its role, the row's expected sha256 verified during the stream, and the task reports progress as every other download does. No body.
//	@Tags			Artifacts
//	@Produce		json
//	@Param			id	path	int	true	"Artifact id"
//	@Success		202	{object}	fetchArtifactResponse	"Download queued"
//	@Failure		400	"The row names no source the agent can fetch from, or no HCL portal key is stored"
//	@Failure		404	"Artifact not found"
//	@Failure		409	"The file is already on this host"
//	@Failure		503	"Artifact storage is disabled"
//	@Router			/api/artifacts/{id}/fetch [post]
func (s *Server) fetchArtifact(w http.ResponseWriter, r *http.Request) {
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
	if artifact.Exists && artifact.Path != "" {
		taskError(w, http.StatusConflict, artifact.Filename+" is already on this host")
		return
	}
	location, err := s.assets.GetLocation(r.Context(), artifact.LocationID)
	if err != nil || !location.Enabled {
		taskError(w, http.StatusBadRequest, "The artifact's storage location is missing or disabled")
		return
	}

	source := s.artifactSource(artifact)
	var operation string
	var metadata any
	switch source {
	case artifactSourceBoxVault:
		registry := s.registrySourceForURL(artifact.SourceURL)
		meta, ok := assets.ParseRegistryFileURL(artifact.SourceURL)
		if !ok {
			taskError(w, http.StatusBadRequest, "The artifact's source_url is not a registry file download")
			return
		}
		meta.SourceName = registry.ID
		meta.Kind = artifact.Kind
		meta.Role = artifact.Role
		meta.LocationID = artifact.LocationID
		meta.Checksum = artifact.ExpectedSHA256
		meta.ChecksumAlgorithm = assets.AlgorithmSHA256
		meta.OverwriteExisting = true
		operation, metadata = assets.OpRegistryDownload, meta
	case artifactSourceHCL:
		keys := s.secrets.Get().HCLDownloadPortalAPIKeys
		if len(keys) == 0 {
			taskError(w, http.StatusBadRequest, "No hcl_download_portal_api_keys secret is stored to fetch from the HCL portal")
			return
		}
		operation, metadata = assets.OpHCLDownload, assets.HCLDownloadMetadata{
			KeyName: keys[0].Name, Filename: artifact.Filename, Role: artifact.Role,
			Kind: artifact.Kind, LocationID: artifact.LocationID,
		}
	case artifactSourceCustom:
		operation, metadata = assets.OpDownload, assets.DownloadMetadata{
			URL: artifact.SourceURL, LocationID: artifact.LocationID, Role: artifact.Role,
			Filename: artifact.Filename, Checksum: artifact.ExpectedSHA256,
			ChecksumAlgorithm: assets.AlgorithmSHA256, OverwriteExisting: true,
		}
	default:
		taskError(w, http.StatusBadRequest, artifact.Filename+" names no source the agent can fetch it from")
		return
	}

	raw, err := json.Marshal(metadata)
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to queue the download")
		return
	}
	metadataStr := string(raw)
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: "artifact",
		Operation:   operation,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   auth.FromContext(r.Context()).Name,
		Metadata:    &metadataStr,
	})
	if err != nil {
		slog.Error("queue artifact fetch", "artifact", artifact.ID, "operation", operation, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue the download")
		return
	}
	writeJSONStatus(w, http.StatusAccepted, fetchArtifactResponse{
		Success:    true,
		TaskID:     task.ID,
		ArtifactID: artifact.ID,
		Filename:   artifact.Filename,
		Source:     source,
		Status:     tasks.StatusPending,
	})
}
