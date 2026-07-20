package server

import (
	"net/http"
	"strconv"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/monitoring"
)

// monitoringPagination is the monitoring listings' pagination envelope.
type monitoringPagination struct {
	Limit   int  `json:"limit"`
	Offset  int  `json:"offset"`
	HasMore bool `json:"hasMore"`
}

// monitoringInterfacesResponse is GET /monitoring/network/interfaces' answer.
type monitoringInterfacesResponse struct {
	Interfaces []monitoring.Interface `json:"interfaces"`
	TotalCount int                    `json:"totalCount"`
	Pagination monitoringPagination   `json:"pagination"`
}

// @Summary		Network interfaces
// @Description	Minimum role: viewer. Live configuration view (name, MTU, state, MAC, addresses). dladm-only fields (over, speed, vid, zone) have no analog and are absent.
// @Tags			Host Monitoring
// @Produce		json
// @Param			limit	query	int		false	"Maximum rows"	default(100)
// @Param			offset	query	int		false	"Page offset"	default(0)
// @Param			state	query	string	false	"Filter by state (up | down)"
// @Param			link	query	string	false	"Filter by interface name"
// @Success		200	{object}	monitoringInterfacesResponse	"Network interfaces"
// @Failure		500	{object}	wrappedError					"Failed to get network interfaces"
// @Router			/monitoring/network/interfaces [get]
func (s *Server) handleMonitoringInterfaces(w http.ResponseWriter, r *http.Request) {
	q := parseMonitoringQuery(r)
	interfaces, err := s.monitor.Sampler().Interfaces(r.Context())
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to get network interfaces", err.Error())
		return
	}

	if state := r.URL.Query().Get("state"); state != "" {
		filtered := interfaces[:0]
		for _, iface := range interfaces {
			if iface.State == state {
				filtered = append(filtered, iface)
			}
		}
		interfaces = filtered
	}
	if link := r.URL.Query().Get("link"); link != "" {
		filtered := interfaces[:0]
		for _, iface := range interfaces {
			if iface.Link == link {
				filtered = append(filtered, iface)
			}
		}
		interfaces = filtered
	}

	total := len(interfaces)
	offset := 0
	if raw := r.URL.Query().Get("offset"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 0 {
			offset = parsed
		}
	}
	if offset > total {
		offset = total
	}
	end := offset + q.limit
	if end > total {
		end = total
	}

	writeJSON(w, monitoringInterfacesResponse{
		Interfaces: interfaces[offset:end],
		TotalCount: total,
		Pagination: monitoringPagination{
			Limit:   q.limit,
			Offset:  offset,
			HasMore: total > end,
		},
	})
}

// networkUsageMetadata is the network-usage listing's interface roster.
type networkUsageMetadata struct {
	ActiveInterfacesCount int      `json:"activeInterfacesCount"`
	InterfaceList         []string `json:"interfaceList"`
}

// networkUsageResponse is GET /monitoring/network/usage's answer.
type networkUsageResponse struct {
	Usage         []monitoring.NetworkSample `json:"usage"`
	TotalCount    int                        `json:"totalCount"`
	ReturnedCount int                        `json:"returnedCount"`
	Sampling      monitoringSamplingMeta     `json:"sampling"`
	Metadata      networkUsageMetadata       `json:"metadata"`
	// Milliseconds spent serving the request
	QueryTime int64 `json:"queryTime"`
}

// @Summary		Network usage
// @Description	Minimum role: viewer. Per-interface counters with computed rates. Realtime mode: one live observation per interface; storage mode: stored samples, newest first.
// @Tags			Host Monitoring
// @Produce		json
// @Param			limit	query	int		false	"Maximum samples"	default(100)
// @Param			since	query	string	false	"Stored samples at or after this time (storage mode)"
// @Param			link	query	string	false	"Filter by interface name"
// @Success		200	{object}	networkUsageResponse	"Network usage"
// @Failure		500	{object}	wrappedError			"Failed to get network usage"
// @Router			/monitoring/network/usage [get]
func (s *Server) handleMonitoringNetworkUsage(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	q := parseMonitoringQuery(r)
	link := r.URL.Query().Get("link")

	var samples []monitoring.NetworkSample
	var strategy string
	if s.monitor.StorageEnabled() {
		stored, err := s.monitor.Store().NetworkHistory(r.Context(),
			&monitoring.HistoryFilter{Since: q.since, Link: link, Limit: q.limit})
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, "Failed to get network usage", err.Error())
			return
		}
		samples, strategy = stored, "stored"
	} else {
		live, err := s.monitor.Sampler().SampleNetwork(r.Context())
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, "Failed to get network usage", err.Error())
			return
		}
		if link != "" {
			filtered := live[:0]
			for i := range live {
				if live[i].Link == link {
					filtered = append(filtered, live[i])
				}
			}
			live = filtered
		}
		samples, strategy = live, "realtime"
	}

	interfaceSet := map[string]bool{}
	for i := range samples {
		interfaceSet[samples[i].Link] = true
	}
	interfaceList := make([]string, 0, len(interfaceSet))
	for name := range interfaceSet {
		interfaceList = append(interfaceList, name)
	}

	writeJSON(w, networkUsageResponse{
		Usage:         samples,
		TotalCount:    len(samples),
		ReturnedCount: len(samples),
		Sampling:      samplingMeta(strategy, len(samples)),
		Metadata: networkUsageMetadata{
			ActiveInterfacesCount: len(interfaceList),
			InterfaceList:         interfaceList,
		},
		QueryTime: queryTimeSince(start),
	})
}
