package server

import (
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// handleMachineConfig: the live configuration document (VirtualBox's
// machinereadable view on this agent) plus nat_forwards — the configuration's
// Forwarding(N) rules parsed into structured rows.
//
//	@Summary		Machine configuration
//	@Description	Minimum role: viewer. The live configuration document (VBoxManage showvminfo --machinereadable view on this agent), falling back to the last reconciled copy. nat_forwards serves the configuration's Forwarding(N) NAT port-forward rules as structured rows {name, protocol, host_ip, host_port, guest_ip, guest_port} — empty host/guest IPs are legal, adapter appears only when the machinereadable key names one, and unparseable entries are skipped.
//	@Tags			Machine Management
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{object}	map[string]interface{}	"Machine configuration"
//	@Failure		404	"Machine not found"
//	@Router			/machines/{machineName}/config [get]
func (s *Server) handleMachineConfig(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}

	exe := machines.VBoxManagePath(r.Context())
	if exe != "" {
		if info, err := vbox.ShowVMInfo(r.Context(), exe, machine.VBoxTarget()); err == nil {
			writeJSON(w, map[string]any{
				"machine_name":  machine.Name,
				"configuration": info.Raw,
				"nat_forwards":  parseNATForwards(info.Raw),
			})
			return
		}
	}

	var configuration json.RawMessage
	if machine.Configuration != nil {
		configuration = machine.Configuration
	} else {
		configuration = json.RawMessage("{}")
	}
	// The reconciled copy's string values carry the same machinereadable keys
	// — the derived rows stay available when the live probe is unreachable.
	flat := map[string]string{}
	for key, value := range machines.ParseConfiguration(machine) {
		if text, ok := value.(string); ok {
			flat[key] = text
		}
	}
	writeJSON(w, map[string]any{
		"machine_name":  machine.Name,
		"configuration": configuration,
		"nat_forwards":  parseNATForwards(flat),
	})
}

// natForwardRule is one parsed NAT port-forward rule — GET
// /machines/{machineName}/config's nat_forwards row, derived from the
// machinereadable Forwarding(N) keys.
type natForwardRule struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	// Host bind address ("" = every host address)
	HostIP   string `json:"host_ip"`
	HostPort int    `json:"host_port"`
	// Guest target address ("" = the adapter's guest address)
	GuestIP   string `json:"guest_ip"`
	GuestPort int    `json:"guest_port"`
	// NAT adapter number — present only when the machinereadable key names one (the flat Forwarding(N) form does not)
	Adapter *int `json:"adapter,omitempty"`
}

// natForwardKeyPattern matches the machinereadable NAT-forward keys: an
// optional nic<N>- adapter qualifier (the per-NIC naming, when VBoxManage
// emits one) around the flat Forwarding(<index>) form.
var natForwardKeyPattern = regexp.MustCompile(`^(?:nic(\d+)-)?Forwarding\((\d+)\)$`)

// parseNATForwards derives the structured nat_forwards rows from a
// machinereadable configuration map: every Forwarding(N) value
// ("name,proto,hostip,hostport,guestip,guestport" — empty host/guest IPs are
// legal) becomes one row; unparseable entries are skipped, never fatal. Rows
// order by adapter then rule index (map iteration alone would be random).
func parseNATForwards(raw map[string]string) []natForwardRule {
	type indexedRule struct {
		adapter int
		index   int
		rule    natForwardRule
	}
	rows := []indexedRule{}
	for key, value := range raw {
		match := natForwardKeyPattern.FindStringSubmatch(key)
		if match == nil {
			continue
		}
		index, ierr := strconv.Atoi(match[2])
		if ierr != nil {
			continue
		}
		parts := strings.Split(value, ",")
		if len(parts) != 6 {
			continue
		}
		hostPort, herr := strconv.Atoi(parts[3])
		guestPort, gerr := strconv.Atoi(parts[5])
		if herr != nil || gerr != nil {
			continue
		}
		row := indexedRule{index: index, rule: natForwardRule{
			Name:      parts[0],
			Protocol:  parts[1],
			HostIP:    parts[2],
			HostPort:  hostPort,
			GuestIP:   parts[4],
			GuestPort: guestPort,
		}}
		if match[1] != "" {
			if adapter, aerr := strconv.Atoi(match[1]); aerr == nil {
				row.adapter = adapter
				row.rule.Adapter = &adapter
			}
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].adapter != rows[j].adapter {
			return rows[i].adapter < rows[j].adapter
		}
		return rows[i].index < rows[j].index
	})
	out := make([]natForwardRule, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.rule)
	}
	return out
}
