package machines

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/Makr91/hyperweaver-agent/internal/ansiblehost"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// The WSL-scoped forward names, one per mechanism — added just-in-time bound
// to the WSL gateway address ONLY (a host-internal adapter; the LAN never
// sees the listener) and removed after the run. The create-time loopback
// rule is untouched.
const (
	wslRuleSSH   = "hw-wsl-ssh"
	wslRuleWinRM = "hw-wsl-winrm"
)

// wslReachableTransport rewrites a 127.0.0.1 forward target for a WSL
// control node: NAT-mode WSL2 shares no loopback with the Windows host and
// the create-time forwards bind 127.0.0.1 (runtime-proven 2026-07-19 on
// Mark's host), so the agent hot-adds a twin rule on the SAME host port
// bound to the WSL gateway address, answers that address as the dial target,
// and the returned cleanup deletes the rule (Background context — cleanup
// survives a cancelled run). A non-WSL runner or a non-loopback target
// passes through untouched with a no-op cleanup.
func (e *executors) wslReachableTransport(ctx context.Context, runner *ansiblehost.Runner,
	machineName, ip string, port, guestPort int, ruleName string, out *tasks.OutputWriter,
) (dialIP string, cleanup func(), err error) {
	noop := func() {}
	if !runner.WSL() || ip != "127.0.0.1" {
		return ip, noop, nil
	}
	gateway, err := ansiblehost.WSLHostIP(ctx)
	if err != nil {
		return "", noop, fmt.Errorf("the WSL control node cannot reach 127.0.0.1 forwards and the WSL gateway did not resolve: %w", err)
	}
	machine, err := e.store.Get(ctx, machineName)
	if err != nil {
		return "", noop, err
	}
	vboxExe := VBoxManagePath(ctx)
	if vboxExe == "" {
		return "", noop, errors.New("VirtualBox is not installed")
	}
	target := machine.VBoxTarget()

	// A stale twin from an earlier run (crash, WSL subnet change at reboot)
	// dies first — tolerantly, absence is the normal case.
	if derr := vbox.ControlVMNatPFDelete(ctx, vboxExe, target, ruleName); derr == nil {
		out.Write("stdout", "Replaced a stale "+ruleName+" forward\n")
	}
	rule := fmt.Sprintf("%s,tcp,%s,%d,,%d", ruleName, gateway, port, guestPort)
	if aerr := vbox.ControlVMNatPF(ctx, vboxExe, target, rule); aerr != nil {
		return "", noop, fmt.Errorf("add the WSL-scoped forward %s: %w", rule, aerr)
	}
	out.Write("stdout", "WSL control node dials "+gateway+":"+strconv.Itoa(port)+
		" — a run-scoped forward bound to the WSL gateway (host-internal; the loopback rule is untouched)\n")
	cleanup = func() {
		if derr := vbox.ControlVMNatPFDelete(context.Background(), vboxExe, target, ruleName); derr != nil {
			out.Write("stderr", "remove the WSL-scoped forward "+ruleName+": "+derr.Error()+"\n")
		}
	}
	return gateway, cleanup, nil
}

// wslWinRMGuestPort answers the guest port a WSL-scoped winrm twin forwards
// to — the document's ruled winrm port, 5985 absent one.
func wslWinRMGuestPort(meta *provisionTaskMetadata) int {
	if meta.WinRM != nil && meta.WinRM.Port > 0 {
		return meta.WinRM.Port
	}
	return 5985
}
