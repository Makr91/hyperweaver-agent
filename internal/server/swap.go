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

func gbString(bytes uint64) string {
	return fmt.Sprintf("%.2f", float64(bytes)/(1024*1024*1024))
}

func utilizationPct(used, total uint64) float64 {
	if total == 0 {
		return 0
	}
	raw := float64(used) / float64(total) * 100
	// Two decimals, matching the Node payload.
	return float64(int(raw*100+0.5)) / 100
}

// handleSwapSummary mirrors GET /system/swap/summary: aggregate swap figures,
// the per-area breakdown, and the platform-neutral recommendation rule (the
// >50% utilization alert). Pool analysis fields stay in the shape but empty —
// pools are a ZFS concept with no VirtualBox-host analog.
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

	areas := make([]map[string]any, 0, len(devices))
	for _, d := range devices {
		areas = append(areas, map[string]any{
			"path":        d.path,
			"pool":        nil,
			"sizeGB":      gbString(d.sizeBytes),
			"usedGB":      gbString(d.usedBytes),
			"utilization": utilizationPct(d.usedBytes, d.sizeBytes),
		})
	}

	recommendations := []map[string]any{}
	if overall > 50 {
		recommendations = append(recommendations, map[string]any{
			"type":     "alert",
			"category": "utilization",
			"message": fmt.Sprintf("Swap utilization is %.1f%% which exceeds the 50%% threshold.",
				overall),
			"action": "Consider adding more swap space",
		})
	}

	writeJSON(w, map[string]any{
		"host":                 hostname,
		"totalSwapGB":          gbString(swap.Total),
		"usedSwapGB":           gbString(swap.Used),
		"freeSwapGB":           gbString(swap.Free),
		"overallUtilization":   overall,
		"swapAreaCount":        len(areas),
		"swapAreas":            areas,
		"poolDistribution":     map[string]any{},
		"recommendations":      recommendations,
		"lastScanned":          time.Now().UTC().Format(time.RFC3339),
		"memoryStatsReference": nil,
	})
}

// handleSwapAreas mirrors GET /system/swap/areas: the row-per-area listing
// with the Node payload's pagination envelope. Rows are read live (this
// agent has no collector table); the zvol pool filter has no meaning here
// and is ignored.
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
	rows := make([]map[string]any, 0, len(devices))
	for _, d := range devices {
		rows = append(rows, map[string]any{
			"host":            hostname,
			"swapfile":        d.path,
			"size_bytes":      d.sizeBytes,
			"used_bytes":      d.usedBytes,
			"free_bytes":      d.sizeBytes - d.usedBytes,
			"utilization_pct": utilizationPct(d.usedBytes, d.sizeBytes),
			"scan_timestamp":  now,
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

	writeJSON(w, map[string]any{
		"swapAreas":  rows[offset:end],
		"totalCount": total,
		"pagination": map[string]any{
			"limit":   limit,
			"offset":  offset,
			"hasMore": total > offset+limit,
		},
	})
}
