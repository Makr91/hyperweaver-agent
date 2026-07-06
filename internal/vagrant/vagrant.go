// Package vagrant reads vagrant's global-status cache — DISCOVERY ONLY
// (Mark's provisioning-engine ruling: the agent recreates zoneweaver's
// mechanisms and never executes vagrant; externally-created vagrant projects
// are recognized so their VMs reconcile as the user's own). Callers supply
// the vagrant path from the prerequisite detector, which has already
// validated it through safepath.
package vagrant

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/procattr"
)

// Machine is one entry from `vagrant global-status --machine-readable`.
type Machine struct {
	// ID is vagrant's machine id (the 7-hex-char global-status id).
	ID string
	// Provider is the backing provider (virtualbox).
	Provider string
	// State is vagrant's cached state (running | poweroff | saved | aborted...).
	// VirtualBox remains authoritative — this cache lags reality (SHI rule).
	State string
	// Home is the directory holding the machine's Vagrantfile.
	Home string
}

// vagrantComma is vagrant's machine-readable escape for commas in data.
const vagrantComma = "%!(VAGRANT_COMMA)"

// GlobalStatus lists vagrant's known machines. prune drops stale cache
// entries first (SHI runs it before every start so deleted VMs are not
// resurrected under old ids).
func GlobalStatus(ctx context.Context, vagrantExe string, prune bool) ([]Machine, error) {
	args := []string{"global-status", "--machine-readable"}
	if prune {
		args = append(args, "--prune")
	}
	cmd := exec.CommandContext(ctx, vagrantExe, args...)
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("vagrant global-status: %w", err)
	}
	return parseGlobalStatus(string(out)), nil
}

// parseGlobalStatus reads the machine-readable CSV (timestamp,target,type,
// data...) — SHI's parse: machine-id opens a machine, the following
// provider-name/machine-home/state rows fill it.
func parseGlobalStatus(raw string) []Machine {
	machines := []Machine{}
	var current *Machine
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Split(strings.TrimSpace(line), ",")
		if len(fields) < 4 {
			continue
		}
		kind := fields[2]
		data := strings.ReplaceAll(strings.Join(fields[3:], ","), vagrantComma, ",")
		switch kind {
		case "machine-id":
			machines = append(machines, Machine{ID: data})
			current = &machines[len(machines)-1]
		case "provider-name":
			if current != nil {
				current.Provider = data
			}
		case "machine-home":
			if current != nil {
				current.Home = data
			}
		case "state":
			if current != nil {
				current.State = data
			}
		}
	}
	return machines
}
