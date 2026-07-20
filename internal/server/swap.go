package server

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/shirou/gopsutil/v4/mem"
)

// Swap endpoints (Agent API v1 Swap Management group) — Mark's ruling,
// 2026-07-05: the Go agent serves the swap INFORMATION zoneweaver serves
// ("zoneweaver has it, why can't the go agent have it?"). Read-only port of
// SwapController.js: GET /system/swap/summary and GET /system/swap/areas,
// response shapes mirrored. Deliberately NOT ported: POST add / DELETE
// remove (OmniOS `swap -a`/`swap -d` semantics — Windows pagefiles and
// macOS dynamic swap have no analog) and the low-swap monitoring endpoint
// (reads the telemetry database; that surface arrives with the Go agent's
// monitoring phase). Advertised by the `swap` capability token.

// swapDevice is one live swap area, gathered from gopsutil (the Node agent
// reads its collector's swap_areas table; this agent reads the OS live).
type swapDevice struct {
	path      string
	sizeBytes uint64
	usedBytes uint64
}

// swapDevices lists the live swap areas. Platforms where gopsutil cannot
// enumerate devices (or none are configured) degrade to a single synthetic
// entry from the aggregate numbers, so the summary's area list is never
// silently empty while swap exists.
func swapDevices(total, used uint64) []swapDevice {
	devices, err := mem.SwapDevices()
	if err == nil && len(devices) > 0 {
		out := make([]swapDevice, 0, len(devices))
		for _, d := range devices {
			out = append(out, swapDevice{
				path:      d.Name,
				sizeBytes: d.UsedBytes + d.FreeBytes,
				usedBytes: d.UsedBytes,
			})
		}
		return out
	}
	if total == 0 {
		return []swapDevice{}
	}
	return []swapDevice{{path: "swap", sizeBytes: total, usedBytes: used}}
}

func utilizationPct(used, total uint64) float64 {
	if total == 0 {
		return 0
	}
	raw := float64(used) / float64(total) * 100
	// Two decimals, matching the Node payload.
	return float64(int(raw*100+0.5)) / 100
}

// swapSummaryArea is one live swap area in the summary's per-area breakdown.
type swapSummaryArea struct {
	Path string  `json:"path"`
	Pool *string `json:"pool"`
	// Area size in bytes
	SizeBytes uint64 `json:"sizeBytes"`
	// Bytes in use
	UsedBytes   uint64  `json:"usedBytes"`
	Utilization float64 `json:"utilization"`
}

// swapRecommendation is one platform-neutral recommendation entry (the >50%
// utilization alert is the only rule this agent emits).
type swapRecommendation struct {
	Type     string `json:"type"`
	Category string `json:"category"`
	Message  string `json:"message"`
	Action   string `json:"action"`
}

// swapPoolDistribution is the pool-distribution object, always empty on this
// host — pools are a ZFS concept with no VirtualBox-host analog.
type swapPoolDistribution struct{}

// swapSummaryResponse is GET /system/swap/summary's answer. The swap size
// fields are plain numbers in BYTES (the converged wire — no formatted GB
// strings, no unit division).
type swapSummaryResponse struct {
	Host                 string               `json:"host"`
	TotalSwapBytes       uint64               `json:"totalSwapBytes"`
	UsedSwapBytes        uint64               `json:"usedSwapBytes"`
	FreeSwapBytes        uint64               `json:"freeSwapBytes"`
	OverallUtilization   float64              `json:"overallUtilization"`
	SwapAreaCount        int                  `json:"swapAreaCount"`
	SwapAreas            []swapSummaryArea    `json:"swapAreas"`
	PoolDistribution     swapPoolDistribution `json:"poolDistribution"`
	Recommendations      []swapRecommendation `json:"recommendations"`
	LastScanned          string               `json:"lastScanned"`
	MemoryStatsReference any                  `json:"memoryStatsReference"`
}

// handleSwapSummary mirrors GET /system/swap/summary: aggregate swap figures,
// the per-area breakdown, and the platform-neutral recommendation rule (the
// >50% utilization alert). Pool analysis fields stay in the shape but empty —
// pools are a ZFS concept with no VirtualBox-host analog.
//
//	@Summary		Swap configuration summary
//	@Description	Minimum role: viewer. Aggregate swap figures (the swap size fields are plain numbers in BYTES — totalSwapBytes/usedSwapBytes/freeSwapBytes, per-area sizeBytes/usedBytes), per-area breakdown, and utilization recommendations (Node-agent shape). Pool fields are present but empty — ZFS pools have no analog on this host. Read live from the OS; lastScanned is the request time.
//	@Tags			Swap Management
//	@Produce		json
//	@Success		200	{object}	swapSummaryResponse	"Swap summary"
//	@Router			/system/swap/summary [get]
func (s *Server) handleSwapSummary(w http.ResponseWriter, _ *http.Request) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	swap, err := mem.SwapMemory()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to get swap summary", err.Error())
		return
	}

	devices := swapDevices(swap.Total, swap.Used)
	overall := utilizationPct(swap.Used, swap.Total)

	areas := make([]swapSummaryArea, 0, len(devices))
	for _, d := range devices {
		areas = append(areas, swapSummaryArea{
			Path:        d.path,
			Pool:        nil,
			SizeBytes:   d.sizeBytes,
			UsedBytes:   d.usedBytes,
			Utilization: utilizationPct(d.usedBytes, d.sizeBytes),
		})
	}

	recommendations := []swapRecommendation{}
	if overall > 50 {
		recommendations = append(recommendations, swapRecommendation{
			Type:     "alert",
			Category: "utilization",
			Message: fmt.Sprintf("Swap utilization is %.1f%% which exceeds the 50%% threshold.",
				overall),
			Action: "Consider adding more swap space",
		})
	}

	writeJSON(w, swapSummaryResponse{
		Host:                 hostname,
		TotalSwapBytes:       swap.Total,
		UsedSwapBytes:        swap.Used,
		FreeSwapBytes:        swap.Free,
		OverallUtilization:   overall,
		SwapAreaCount:        len(areas),
		SwapAreas:            areas,
		PoolDistribution:     swapPoolDistribution{},
		Recommendations:      recommendations,
		LastScanned:          time.Now().UTC().Format(time.RFC3339),
		MemoryStatsReference: nil,
	})
}

// swapAreaRow is one row in the swap-areas listing.
type swapAreaRow struct {
	Host           string  `json:"host"`
	Swapfile       string  `json:"swapfile"`
	SizeBytes      uint64  `json:"size_bytes"`
	UsedBytes      uint64  `json:"used_bytes"`
	FreeBytes      uint64  `json:"free_bytes"`
	UtilizationPct float64 `json:"utilization_pct"`
	ScanTimestamp  string  `json:"scan_timestamp"`
}

// swapAreasPagination is the swap-areas listing's pagination envelope.
type swapAreasPagination struct {
	Limit   int  `json:"limit"`
	Offset  int  `json:"offset"`
	HasMore bool `json:"hasMore"`
}

// swapAreasResponse is GET /system/swap/areas' answer.
type swapAreasResponse struct {
	SwapAreas  []swapAreaRow       `json:"swapAreas"`
	TotalCount int                 `json:"totalCount"`
	Pagination swapAreasPagination `json:"pagination"`
}

// handleSwapAreas mirrors GET /system/swap/areas: the row-per-area listing
// with the Node payload's pagination envelope. Rows are read live (this
// agent has no collector table); the zvol pool filter has no meaning here
// and is ignored.
//
//	@Summary		List swap areas
//	@Description	Minimum role: viewer. Row-per-area listing with the Node payload's pagination envelope, read live from the OS. The zvol pool filter has no meaning on this agent and is ignored.
//	@Tags			Swap Management
//	@Produce		json
//	@Param			limit	query	int	false	"Page size"	default(100)
//	@Param			offset	query	int	false	"Page offset"	default(0)
//	@Success		200	{object}	swapAreasResponse	"Swap areas"
//	@Router			/system/swap/areas [get]
func (s *Server) handleSwapAreas(w http.ResponseWriter, r *http.Request) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	swap, err := mem.SwapMemory()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to list swap areas", err.Error())
		return
	}

	limit := 100
	offset := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, perr := strconv.Atoi(raw); perr == nil && parsed > 0 {
			limit = parsed
		}
	}
	if raw := r.URL.Query().Get("offset"); raw != "" {
		if parsed, perr := strconv.Atoi(raw); perr == nil && parsed >= 0 {
			offset = parsed
		}
	}

	devices := swapDevices(swap.Total, swap.Used)
	now := time.Now().UTC().Format(time.RFC3339)
	rows := make([]swapAreaRow, 0, len(devices))
	for _, d := range devices {
		rows = append(rows, swapAreaRow{
			Host:           hostname,
			Swapfile:       d.path,
			SizeBytes:      d.sizeBytes,
			UsedBytes:      d.usedBytes,
			FreeBytes:      d.sizeBytes - d.usedBytes,
			UtilizationPct: utilizationPct(d.usedBytes, d.sizeBytes),
			ScanTimestamp:  now,
		})
	}

	total := len(rows)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}

	writeJSON(w, swapAreasResponse{
		SwapAreas:  rows[offset:end],
		TotalCount: total,
		Pagination: swapAreasPagination{
			Limit:   limit,
			Offset:  offset,
			HasMore: total > offset+limit,
		},
	})
}
