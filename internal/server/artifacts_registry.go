package server

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/Makr91/hyperweaver-agent/internal/assets"
	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/problem"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

type registrySourceSummary struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

type registryDownloadsResponse struct {
	Source    registrySourceSummary `json:"source"`
	Downloads []any                 `json:"downloads"`
}

// handleRegistryDownloads: GET /api/artifacts/registry/{sourceName}/downloads.
//
//	@Summary		List a box registry's download files
//	@Description	Minimum role: viewer. The download products of one configured box registry the caller may reach, read as the person under the registry ladder: the x-registry-token request header first, the token of the account the calling key's SSO login minted it for next, the bound account's token after, the registry's own auth_token last. One read of the registry's /api/downloads/discover, every download, release, patch and file as the registry answers the caller under its own visibility, the members as the registry names them in snake_case, each download carrying its organization; sha256 is the registry's own member and empty while it lists none. A registry that refuses the credential answers 401 with the authentication problem type, as the templates read does.
//	@Tags			Artifacts
//	@Produce		json
//	@Param			sourceName	path	string	true	"The configured template source's id"
//	@Success		200	{object}	registryDownloadsResponse	"The source and its downloads"
//	@Failure		401	{object}	problem.Body	"The registry refused the credential"
//	@Failure		404	"Source not found or disabled"
//	@Failure		502	"Registry unreachable or answered an error"
//	@Failure		503	"Artifact storage is disabled"
//	@Router			/api/artifacts/registry/{sourceName}/downloads [get]
func (s *Server) handleRegistryDownloads(w http.ResponseWriter, r *http.Request) {
	source := s.findRegistrySource(r.PathValue("sourceName"))
	if source == nil {
		taskError(w, http.StatusNotFound, "Template source not found or disabled")
		return
	}
	decoded, status, err := registryJSON(r.Context(), source,
		r.Header.Get("x-registry-token"), auth.FromContext(r.Context()).Name, "/api/downloads/discover", false)
	if err != nil {
		slog.Error("registry downloads failed", "source", source.Name, "error", err)
		taskError(w, http.StatusBadGateway, "Failed to retrieve data from remote source: "+err.Error())
		return
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		problem.Detail(w, http.StatusUnauthorized, fmt.Sprintf("The registry %s refused the credential (HTTP %d)", source.Name, status))
		return
	}
	if status != http.StatusOK {
		taskError(w, http.StatusBadGateway, fmt.Sprintf("Remote source answered HTTP %d", status))
		return
	}
	downloads, _ := decoded.([]any)
	if downloads == nil {
		downloads = []any{}
	}
	writeJSON(w, registryDownloadsResponse{
		Source:    registrySourceSummary{ID: source.ID, Name: source.Name, URL: source.URL},
		Downloads: downloads,
	})
}

// handleRegistryDownload: POST /api/artifacts/registry-download.
//
//	@Summary		Download a registry file into a storage location
//	@Description	Minimum role: operator. Queues artifact_registry_download: the host fetches the named file of a box registry's download product as the person who queued it, the token of the account the key stands for before the bound account's before the registry's own key, streams it into the location storage_path_id names, one of the kind's type, or the kind's default location while it is absent, under the role, with the download progress_info of every other download, verifies checksum under checksum_algorithm during the stream when given (a mismatch discards the file), and registers the row with the given checksum beside the agent's sha256, a sha256 also the row's expectation. source_name, organization, download, release, patch, filename, kind and role are required; kind interim-fix is read as hotfix.
//	@Tags			Artifacts
//	@Accept			json
//	@Produce		json
//	@Param			body	body	assets.RegistryDownloadMetadata	true	"The registry file and its destination"
//	@Success		202	"Registry download task queued"
//	@Failure		400	"Missing or unusable member, disabled location, or a location of another type"
//	@Failure		404	"Source or storage location not found"
//	@Failure		503	"Artifact storage is disabled"
//	@Router			/api/artifacts/registry-download [post]
func (s *Server) handleRegistryDownload(w http.ResponseWriter, r *http.Request) {
	var meta assets.RegistryDownloadMetadata
	if err := decodeBody(r, &meta); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if err := meta.Validate(); err != nil {
		taskError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.findRegistrySource(meta.SourceName) == nil {
		taskError(w, http.StatusNotFound, "Template source not found or disabled")
		return
	}
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
		if !location.Enabled {
			taskError(w, http.StatusBadRequest, "Storage location is disabled")
			return
		}
		if location.Type != meta.Kind {
			taskError(w, http.StatusBadRequest, "storage_path_id names a "+location.Type+" location, not "+meta.Kind)
			return
		}
	}
	s.queueArtifactTask(w, r, assets.OpRegistryDownload, tasks.PriorityMedium, meta,
		"Registry download task created for '"+meta.Filename+"'")
}
