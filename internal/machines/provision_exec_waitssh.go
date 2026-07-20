package machines

import (
	"context"
	"fmt"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/sshrun"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// waitSSH executes machine_wait_ssh: poll until the guest answers over SSH
// (config timeouts; the document's settings.setup_wait wins when larger).
// The SAME op branches on its own metadata (zoneweaver's shipped winrm
// shape, sync 2026-07-17: W-Q1..W-Q5): communicator winrm polls host-ansible
// win_ping instead of the SSH loop — same timeout config, same
// setup_wait-larger-wins rule, same poll interval.
func (e *executors) waitSSH(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	meta, err := readProvisionMetadata(task)
	if err != nil {
		return err
	}
	timeout := e.env.SSHTimeout
	if timeout <= 0 {
		timeout = 300 * time.Second
	}
	if machine, gerr := e.store.Get(ctx, task.MachineName); gerr == nil {
		settings := ParseConfiguration(machine).Section("settings")
		if wait := intOr(settings["setup_wait"], 0); wait > 0 {
			if document := time.Duration(wait) * time.Second; document > timeout {
				timeout = document
			}
		}
	}
	interval := e.env.SSHPollInterval
	if interval <= 0 {
		interval = 10 * time.Second
	}

	if meta.Communicator == "winrm" {
		e.taskProgress(task, 10, "waiting_for_winrm")
		out.Write("stdout", fmt.Sprintf("Waiting for WinRM on %s:%d (timeout %ds)\n",
			meta.IP, meta.Port, int(timeout.Seconds())))
		elapsed, werr := e.waitWinRM(ctx, task, meta, timeout, interval, out)
		if werr != nil {
			return werr
		}
		e.taskProgress(task, 100, "completed")
		out.Write("stdout", fmt.Sprintf("WinRM available on %s (%s:%d) after %ds\n",
			task.MachineName, meta.IP, meta.Port, int(elapsed.Seconds())))
		return nil
	}

	e.taskProgress(task, 10, "waiting_for_ssh")
	out.Write("stdout", fmt.Sprintf("Waiting for SSH on %s:%d (timeout %ds)\n",
		meta.IP, meta.Port, int(timeout.Seconds())))
	elapsed, err := sshrun.WaitForSSH(ctx, meta.IP, meta.Port, meta.Credentials,
		e.machineWorkdir(task.MachineName), e.env.ProvisionKeyPath, timeout, interval, out.Write)
	if err != nil {
		// Tier 3 (Mark's three-tier ruling, sync 2026-07-17 — RECOVERY ONLY):
		// one QGA key recovery, one more wait round; keyrotate_exec.go owns it.
		elapsed, err = e.rewaitAfterKeyRecovery(ctx, task, meta, timeout, interval, out, err)
	}
	if err != nil {
		return err
	}
	e.taskProgress(task, 100, "completed")
	out.Write("stdout", fmt.Sprintf("SSH available on %s (%s:%d) after %ds\n",
		task.MachineName, meta.IP, meta.Port, int(elapsed.Seconds())))
	return nil
}
