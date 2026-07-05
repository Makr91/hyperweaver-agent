// Package vbox shells out to VBoxManage for VirtualBox machine queries —
// the seed of the provisioning engine's hypervisor layer. Callers supply the
// VBoxManage path from the prerequisite detector, which has already
// validated it through safepath.
package vbox

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/procattr"
)

// vmLinePattern matches the `"VM name" {uuid}` lines VBoxManage list emits.
var vmLinePattern = regexp.MustCompile(`^"(?P<name>.+)" \{[0-9a-fA-F-]{36}\}$`)

// ListVMs returns the names of all registered VirtualBox machines.
func ListVMs(ctx context.Context, vboxManage string) ([]string, error) {
	return list(ctx, vboxManage, "vms")
}

// ListRunningVMs returns the names of the currently running machines.
func ListRunningVMs(ctx context.Context, vboxManage string) ([]string, error) {
	return list(ctx, vboxManage, "runningvms")
}

func list(ctx context.Context, vboxManage, subset string) ([]string, error) {
	cmd := exec.CommandContext(ctx, vboxManage, "list", subset)
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("VBoxManage list %s: %w", subset, err)
	}

	names := []string{}
	for _, line := range strings.Split(string(out), "\n") {
		if match := vmLinePattern.FindStringSubmatch(strings.TrimSpace(line)); match != nil {
			names = append(names, match[1])
		}
	}
	return names, nil
}
