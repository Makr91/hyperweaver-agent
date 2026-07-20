package server

import (
	"net/http"
	"strconv"
	"time"
)

// lowSwapHost is one host row in the low-swap listing.
type lowSwapHost struct {
	Host string `json:"host"`
	// Total swap in bytes
	SwapTotalBytes uint64 `json:"swap_total_bytes"`
	// Swap bytes in use
	SwapUsedBytes      uint64    `json:"swap_used_bytes"`
	SwapUtilizationPct float64   `json:"swap_utilization_pct"`
	LastChecked        time.Time `json:"last_checked"`
}

// lowSwapHostsResponse is GET /monitoring/hosts/low-swap's answer.
type lowSwapHostsResponse struct {
	HostsWithLowSwap []lowSwapHost `json:"hostsWithLowSwap"`
	TotalCount       int           `json:"totalCount"`
	Threshold        float64       `json:"threshold"`
}

// handleLowSwapHosts mirrors GET /monitoring/hosts/low-swap for the
// single-host case: this host appears in the list when its live swap
// utilization exceeds the threshold.
//
//	@Summary		Hosts above the swap-utilization threshold
//	@Description	Minimum role: viewer. Single-host agent: this host appears in the list when its live swap utilization exceeds the threshold.
//	@Tags			Swap Management
//	@Produce		json
//	@Param			threshold	query	number	false	"Utilization threshold percentage"	default(50)
//	@Success		200	{object}	lowSwapHostsResponse	"Hosts with low swap space"
//	@Router			/monitoring/hosts/low-swap [get]
func (s *Server) handleLowSwapHosts(w http.ResponseWriter, r *http.Request) {
	threshold := 50.0
	if raw := r.URL.Query().Get("threshold"); raw != "" {
		if parsed, err := strconv.ParseFloat(raw, 64); err == nil {
			threshold = parsed
		}
	}

	sample, err := s.monitor.Sampler().SampleMemory(r.Context())
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to get hosts with low swap", err.Error())
		return
	}

	hosts := []lowSwapHost{}
	if sample.SwapUtilizationPct > threshold {
		hosts = append(hosts, lowSwapHost{
			Host:               sample.Host,
			SwapTotalBytes:     sample.SwapTotalBytes,
			SwapUsedBytes:      sample.SwapUsedBytes,
			SwapUtilizationPct: sample.SwapUtilizationPct,
			LastChecked:        sample.ScanTimestamp,
		})
	}
	writeJSON(w, lowSwapHostsResponse{
		HostsWithLowSwap: hosts,
		TotalCount:       len(hosts),
		Threshold:        threshold,
	})
}
