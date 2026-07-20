package server

import "net/http"

// monitoringCollectRequest is POST /monitoring/collect's optional body.
type monitoringCollectRequest struct {
	// network | storage | all (default all) — echoed for contract parity
	Type string `json:"type"`
}

// monitoringCollectResponse is POST /monitoring/collect's answer.
type monitoringCollectResponse struct {
	Success bool   `json:"success"`
	Type    string `json:"type"`
	// Per-family outcomes (collected | sampled | failed: ...)
	Results map[string]string `json:"results"`
}

// @Summary		Trigger immediate collection
// @Description	Minimum role: operator. One collection pass over every telemetry family this host has (cpu, memory, network); samples persist when storage is enabled. The type field is accepted for contract parity — there is no illumos storage family to exclude here.
// @Tags			Host Monitoring
// @Accept			json
// @Produce		json
// @Param			request	body		monitoringCollectRequest	false	"Collection type (contract parity)"
// @Success		200		{object}	monitoringCollectResponse	"Collection triggered"
// @Router			/monitoring/collect [post]
func (s *Server) handleMonitoringCollect(w http.ResponseWriter, r *http.Request) {
	var body monitoringCollectRequest
	if err := decodeBody(r, &body); err != nil {
		errorResponse(w, http.StatusBadRequest, "Failed to trigger collection", "Invalid JSON body")
		return
	}
	collectionType := body.Type
	if collectionType == "" {
		collectionType = "all"
	}

	// One collection pass covers every family this host has; the type is
	// echoed for contract parity (there is no illumos storage family to
	// exclude here).
	results := s.monitor.CollectOnce(r.Context())
	writeJSON(w, monitoringCollectResponse{
		Success: true,
		Type:    collectionType,
		Results: results,
	})
}
