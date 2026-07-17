package server

import (
	"log/slog"
	"net/http"

	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// GET /media — the host's disk-medium inventory (typed disk spec, converged
// sync 2026-07-17): every medium VirtualBox's media registry knows, with its
// provenance stamp (the hyperweaver:source property, .hw-source sidecar
// fallback; null = unstamped/foreign — the agent never created it and delete
// preserves it) and the machines holding it. Viewer-level like every GET
// list via the central policy; no capability token of its own.
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

	media := make([]map[string]any, 0, len(hdds))
	for i := range hdds {
		var stamp any
		if value := machines.MediumSourceStamp(r.Context(), exe, hdds[i].Path); value != "" {
			stamp = value
		}
		inUseBy := hdds[i].InUseBy
		if inUseBy == nil {
			inUseBy = []string{}
		}
		media = append(media, map[string]any{
			"path":         hdds[i].Path,
			"format":       hdds[i].Format,
			"size_bytes":   hdds[i].SizeBytes,
			"source_stamp": stamp,
			"in_use_by":    inUseBy,
		})
	}
	writeJSON(w, map[string]any{
		"media": media,
		"total": len(media),
	})
}
