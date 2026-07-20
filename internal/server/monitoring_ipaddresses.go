package server

import (
	"net/http"
	"strconv"
	"strings"
)

// monitoringIPAddress is one live IP-address assignment row.
type monitoringIPAddress struct {
	AddrObj   string `json:"addrobj"`
	Interface string `json:"interface"`
	Addr      string `json:"addr"`
	IPVersion string `json:"ip_version"`
	State     string `json:"state"`
	Source    string `json:"source"`
}

// monitoringIPPage is the IP listing's pagination block.
type monitoringIPPage struct {
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

// monitoringIPAddressesResponse is GET /monitoring/network/ipaddresses'
// answer.
type monitoringIPAddressesResponse struct {
	Addresses  []monitoringIPAddress `json:"addresses"`
	Returned   int                   `json:"returned"`
	Pagination monitoringIPPage      `json:"pagination"`
}

// @Summary		IP address assignments
// @Description	Minimum role: viewer. Live view derived from the interface list (the reduced live shape — this agent has no ipadm address-object database).
// @Tags			Host Monitoring
// @Produce		json
// @Param			limit		query	int		false	"Maximum rows"	default(100)
// @Param			offset		query	int		false	"Page offset"	default(0)
// @Param			interface	query	string	false	"Filter by interface name"
// @Param			ip_version	query	string	false	"Filter by IP version (v4 | v6)"
// @Success		200	{object}	monitoringIPAddressesResponse	"IP addresses"
// @Failure		500	{object}	wrappedError					"Failed to get IP addresses"
// @Router			/monitoring/network/ipaddresses [get]
func (s *Server) handleMonitoringIPAddresses(w http.ResponseWriter, r *http.Request) {
	q := parseMonitoringQuery(r)
	interfaces, err := s.monitor.Sampler().Interfaces(r.Context())
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to get IP addresses", err.Error())
		return
	}

	wantVersion := r.URL.Query().Get("ip_version")
	wantInterface := r.URL.Query().Get("interface")
	addresses := []monitoringIPAddress{}
	for _, iface := range interfaces {
		if wantInterface != "" && iface.Link != wantInterface {
			continue
		}
		for _, addr := range iface.Addresses {
			ipVersion := "v4"
			if strings.Contains(addr, ":") {
				ipVersion = "v6"
			}
			if wantVersion != "" && ipVersion != wantVersion {
				continue
			}
			state := "ok"
			if iface.State != "up" {
				state = "down"
			}
			addresses = append(addresses, monitoringIPAddress{
				AddrObj:   iface.Link + "/" + ipVersion,
				Interface: iface.Link,
				Addr:      addr,
				IPVersion: ipVersion,
				State:     state,
				Source:    "live",
			})
		}
	}

	total := len(addresses)
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

	writeJSON(w, monitoringIPAddressesResponse{
		Addresses: addresses[offset:end],
		Returned:  end - offset,
		Pagination: monitoringIPPage{
			Limit:  q.limit,
			Offset: offset,
		},
	})
}
