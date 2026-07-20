package server

import (
	"log/slog"
	"net/http"

	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// mediaEntry is one medium row in GET /media's inventory.
type mediaEntry struct {
	// The medium file's agent-host location
	Path   string `json:"path"`
	Format string `json:"format"`
	// Logical capacity in bytes
	SizeBytes int64 `json:"size_bytes"`
	// template | blank (agent-created) | clone (data-complete clone media), null = unstamped/foreign
	SourceStamp *string `json:"source_stamp"`
	// Machine names holding the medium (empty = unattached)
	InUseBy []string `json:"in_use_by"`
}

// mediaListResponse is GET /media's answer.
type mediaListResponse struct {
	Media []mediaEntry `json:"media"`
	Total int          `json:"total"`
}

// GET /media — the host's disk-medium inventory (typed disk spec, converged
// sync 2026-07-17): every medium VirtualBox's media registry knows, with its
// provenance stamp (the hyperweaver:source property, .hw-source sidecar
// fallback; null = unstamped/foreign — the agent never created it and delete
// preserves it) and the machines holding it. Viewer-level like every GET
// list via the central policy; no capability token of its own.
//
//	@Summary		List the host's disk media
//	@Description	Minimum role: viewer (an ordinary GET list — no capability token of its own). The typed disk spec's media inventory (converged, sync 2026-07-17): every disk medium VirtualBox's media registry knows (`VBoxManage list hdds --long`), each with its PROVENANCE STAMP — source_stamp is the hyperweaver:source medium property (the .hw-source sidecar as fallback) the agent writes on media it CREATES (template = a box clone, blank = a fresh VDI); null = unstamped/foreign, a medium the agent never made and the delete flow always preserves. in_use_by names the machines holding the medium (the image attach pre-check's same data — a typed image attach refuses a medium another machine holds unless the entry carries force: true).
//	@Tags			Machine Management
//	@Produce		json
//	@Success		200	{object}	mediaListResponse	"The media inventory"
//	@Failure		500	"VBoxManage list hdds failed"
//	@Failure		503	"VirtualBox is not installed"
//	@Router			/media [get]
func (s *Server) handleListMedia(w http.ResponseWriter, r *http.Request) {
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}
	hdds, err := vbox.ListHDDs(r.Context(), exe)
	if err != nil {
		slog.Error("list hdds", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to list media")
		return
	}

	media := make([]mediaEntry, 0, len(hdds))
	for i := range hdds {
		var stamp *string
		if value := machines.MediumSourceStamp(r.Context(), exe, hdds[i].Path); value != "" {
			stamp = &value
		}
		inUseBy := hdds[i].InUseBy
		if inUseBy == nil {
			inUseBy = []string{}
		}
		media = append(media, mediaEntry{
			Path:        hdds[i].Path,
			Format:      hdds[i].Format,
			SizeBytes:   hdds[i].SizeBytes,
			SourceStamp: stamp,
			InUseBy:     inUseBy,
		})
	}
	writeJSON(w, mediaListResponse{
		Media: media,
		Total: len(media),
	})
}
