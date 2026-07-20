package server

import (
	"net/http"
	"strconv"
	"time"
)

// Host telemetry endpoints (/monitoring/*, the `monitoring` capability
// token) — the Node agent's Host Monitoring group, reshaped per Mark's
// 2026-07-05 ruling: always-on REALTIME sampling; monitoring.storage_enabled
// adds stored history (per-datatype database files) behind the same
// endpoints. Illumos-only monitoring families (ZFS pools/datasets/ARC,
// zpool-iostat disk IO, netstat routes) have no analog on this host and are
// deliberately absent.

// monitoringQuery carries the common history query parameters.
type monitoringQuery struct {
	limit int
	since *time.Time
}

func parseMonitoringQuery(r *http.Request) monitoringQuery {
	q := monitoringQuery{limit: 100}
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			q.limit = parsed
		}
	}
	if raw := r.URL.Query().Get("since"); raw != "" {
		if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
			q.since = &parsed
		}
	}
	return q
}

// monitoringSamplingMeta is the time-series sampling metadata block (the
// MonitoringSampling contract): this agent never downsamples, so applied is
// always false — strategy names which mode answered (realtime = single live
// sample, stored = database rows).
type monitoringSamplingMeta struct {
	Applied         bool   `json:"applied"`
	Strategy        string `json:"strategy"`
	SamplesReturned int    `json:"samplesReturned"`
}

// samplingMeta builds the sampling metadata block.
func samplingMeta(strategy string, returned int) monitoringSamplingMeta {
	return monitoringSamplingMeta{
		Applied:         false,
		Strategy:        strategy,
		SamplesReturned: returned,
	}
}

// queryTimeSince answers the milliseconds spent serving the request — the
// listings' queryTime field (a plain number).
func queryTimeSince(start time.Time) int64 {
	return time.Since(start).Milliseconds()
}
