package machines

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/qga"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
	"github.com/Makr91/hyperweaver-agent/internal/sshrun"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// The key-rotation executor (key_rotate proposal, sync 2026-07-17): when the
// document sets settings.vagrant_ssh_insert_key, the box rotates its own SSH
// key at build (Hosts.rb's insert-key flow) and the provision walk queues ONE
// machine_key_rotate child AFTER the syncback bracket to adopt that rotated
// private key into the working copy — SFTP-read /home/<user>/.ssh/id_ssh_rsa,
// land it at settings.vagrant_user_private_key_path (0600), then strip the
// bootstrap pubkey line from the guest file (Hosts.rb:706's exact hack). The
// child NEVER carries final: the whole-walk stamp stays on the document
// walk's last task. This file also owns TIER 3 of Mark's three-tier ruling
// (sync 2026-07-17) — the RECOVERY-ONLY QGA key fetch waitSSH falls back to
// when both known keys were rejected; tiers 1/2 live in sshrun's resolver.

// OpKeyRotate is the machine_key_rotate operation.
const OpKeyRotate = "machine_key_rotate"

// keyRotateMetadata is the child's own extra beyond the transport triple —
// key_path carries settings.vagrant_user_private_key_path at planning time.
type keyRotateMetadata struct {
	KeyPath string `json:"key_path"`
}

// keyRotate executes machine_key_rotate.
func (e *executors) keyRotate(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	meta, err := readProvisionMetadata(task)
	if err != nil {
		return err
	}
	var extra keyRotateMetadata
	if len(task.Metadata) > 0 {
		// Tolerant second decode: readProvisionMetadata already validated the
		// document; this only lifts the key_path field out of it.
		_ = json.Unmarshal(task.Metadata, &extra)
	}
	keyPath := extra.KeyPath
	if keyPath == "" {
		keyPath = meta.Credentials.SSHKeyPath
	}
	if keyPath == "" {
		out.Write("stdout", "Key rotation skipped: no vagrant_user_private_key_path to rotate into\n")
		e.taskProgress(task, 100, "completed")
		return nil
	}
	username := meta.Credentials.Username
	if username == "" {
		username = "root"
	}
	remote := "/home/" + username + "/.ssh/id_ssh_rsa"
	workdir := e.machineWorkdir(task.MachineName)

	e.taskProgress(task, 15, "fetching_rotated_key")
	out.Write("stdout", "Fetching rotated key "+remote+" from the guest\n")
	raw, derr := sshrun.DownloadFile(ctx, meta.IP, meta.Port, meta.Credentials,
		remote, workdir, e.env.ProvisionKeyPath)
	if errors.Is(derr, os.ErrNotExist) {
		// The box built without rotation — a narrated skip, the task SUCCEEDS.
		out.Write("stdout", "Key rotation skipped: "+remote+" does not exist in the guest (box built without rotation)\n")
		e.taskProgress(task, 100, "completed")
		return nil
	}
	if derr != nil {
		return fmt.Errorf("fetch rotated key %s: %w", remote, derr)
	}

	e.taskProgress(task, 55, "landing_key")
	local := rotatedKeyDestination(keyPath, workdir)
	if werr := safepath.WriteFile(local, raw, 0o600); werr != nil {
		return fmt.Errorf("land rotated key at %s: %w", local, werr)
	}
	out.Write("stdout", "Rotated key landed at "+local+" (0600)\n")

	// Strip the bootstrap pubkey line from the GUEST's file — Hosts.rb:706's
	// exact hack. A strip failure fails the task HONESTLY (zoneweaver's
	// shipped behavior, converged 2026-07-17); the landed key stays — the next
	// connect still rides it, and the whole-walk stamp never sat on this child.
	e.taskProgress(task, 80, "stripping_bootstrap_key")
	if serr := sshrun.Run(ctx, meta.IP, meta.Port, meta.Credentials,
		"sed -i '/vagrantup/d' "+remote, workdir, e.env.ProvisionKeyPath,
		time.Minute, out.Write); serr != nil {
		out.Write("stderr", "Bootstrap key strip failed (rotated key already landed at "+local+")\n")
		return fmt.Errorf("strip bootstrap key from %s: %w", remote, serr)
	}

	e.taskProgress(task, 100, "completed")
	out.Write("stdout", "Key rotation complete for "+task.MachineName+"\n")
	return nil
}

// rotatedKeyDestination resolves the working-copy landing path for a rotated
// key — the same relative-against-workdir rule sshrun's tier-1 resolution
// reads it back with (a mismatch would land the key where tier 1 never
// looks).
func rotatedKeyDestination(keyPath, workdir string) string {
	local := filepath.FromSlash(keyPath)
	if !filepath.IsAbs(local) {
		local = filepath.Join(workdir, local)
	}
	return local
}

// rewaitAfterKeyRecovery is waitSSH's tier-3 hook (Mark's three-tier ruling,
// sync 2026-07-17 — RECOVERY ONLY, machines layer, never sshrun): when the
// SSH wait exhausts on key auth and the guest-agent channel is enabled,
// recover the rotated key over QGA ONCE and run one more WaitForSSH round.
// Password credentials pass the original error through untouched (a document
// password is its own auth); a disabled/unavailable channel appends the
// ruled no-transport message to the original error.
func (e *executors) rewaitAfterKeyRecovery(ctx context.Context, task *tasks.Task,
	meta *provisionTaskMetadata, timeout, interval time.Duration,
	out *tasks.OutputWriter, waitErr error,
) (time.Duration, error) {
	if meta.Credentials.Password != "" {
		return 0, waitErr
	}
	noTransport := fmt.Errorf("%w — both known keys were rejected and no SSH-free transport exists — re-provision the machine or supply the key", waitErr)
	if !e.env.GuestAgentEnabled {
		return 0, noTransport
	}
	machine, gerr := e.store.Get(ctx, task.MachineName)
	if gerr != nil {
		out.Write("stderr", "Guest-agent recovery unavailable (machine row unreadable): "+gerr.Error()+"\n")
		return 0, noTransport
	}
	keyPath := meta.Credentials.SSHKeyPath
	if keyPath == "" {
		// Recovery lands the key at the working-copy path — no named path, no
		// landing spot: honestly unavailable.
		out.Write("stderr", "Guest-agent recovery unavailable: the document names no vagrant_user_private_key_path to recover into\n")
		return 0, noTransport
	}
	workdir := e.machineWorkdir(task.MachineName)
	pipeWorkdir := workdir
	if machine.Home != nil && *machine.Home != "" {
		pipeWorkdir = *machine.Home
	}
	local := rotatedKeyDestination(keyPath, workdir)

	out.Write("stdout", "SSH wait exhausted — attempting key recovery over the guest-agent channel (tier 3, recovery only)\n")
	if rerr := e.recoverKeyViaQGA(ctx, machine, pipeWorkdir, local, out); rerr != nil {
		return 0, fmt.Errorf("%w — guest-agent key recovery failed (%w) — re-provision the machine or supply the key", waitErr, rerr)
	}
	out.Write("stdout", "Recovered key landed at "+local+" — retrying the SSH wait once\n")
	return sshrun.WaitForSSH(ctx, meta.IP, meta.Port, meta.Credentials,
		workdir, e.env.ProvisionKeyPath, timeout, interval, out.Write)
}

// recoverKeyViaQGA pulls /home/<vagrant_user>/.ssh/id_ssh_rsa over the QGA
// channel and lands it at keyPath (0600). qga exposes ONE generic primitive
// (qga.Do), which carries both halves of the exec conversation: guest-exec
// with capture-output starts the cat, guest-exec-status polls until exit and
// answers the base64 out-data — output collection needs nothing beyond the
// existing package.
func (e *executors) recoverKeyViaQGA(ctx context.Context, machine *Machine,
	workdir, keyPath string, out *tasks.OutputWriter,
) error {
	username := ExtractCredentials(ParseConfiguration(machine).Section("settings")).Username
	if username == "" {
		return errors.New("the document names no vagrant_user to read the key for")
	}
	pipe := qga.PipePath(workdir, machine.Name)
	remote := "/home/" + username + "/.ssh/id_ssh_rsa"

	execCtx, cancelExec := context.WithTimeout(ctx, 10*time.Second)
	defer cancelExec()
	started, err := qga.Do(execCtx, pipe, "guest-exec", map[string]any{
		"path":           "/bin/cat",
		"arg":            []string{remote},
		"capture-output": true,
	})
	if err != nil {
		return fmt.Errorf("guest-exec cat %s: %w", remote, err)
	}
	var process struct {
		PID int `json:"pid"`
	}
	if uerr := json.Unmarshal(started, &process); uerr != nil {
		return fmt.Errorf("parse guest-exec answer: %w", uerr)
	}

	// cat finishes in milliseconds; the bound only bites dead channels.
	deadline := time.Now().Add(30 * time.Second)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("guest-exec pid %d did not exit within 30s", process.PID)
		}
		pollCtx, cancelPoll := context.WithTimeout(ctx, 10*time.Second)
		answer, perr := qga.Do(pollCtx, pipe, "guest-exec-status", map[string]any{"pid": process.PID})
		cancelPoll()
		if perr != nil {
			return fmt.Errorf("guest-exec-status: %w", perr)
		}
		var status struct {
			Exited   bool   `json:"exited"`
			ExitCode int    `json:"exitcode"`
			OutData  string `json:"out-data"`
			ErrData  string `json:"err-data"`
		}
		if uerr := json.Unmarshal(answer, &status); uerr != nil {
			return fmt.Errorf("parse guest-exec-status answer: %w", uerr)
		}
		if !status.Exited {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
			continue
		}
		if status.ExitCode != 0 {
			detail := ""
			if raw, derr := base64.StdEncoding.DecodeString(status.ErrData); derr == nil && len(raw) > 0 {
				detail = ": " + strings.TrimSpace(string(raw))
			}
			return fmt.Errorf("guest cat %s exited %d%s", remote, status.ExitCode, detail)
		}
		raw, derr := base64.StdEncoding.DecodeString(status.OutData)
		if derr != nil {
			return fmt.Errorf("decode recovered key bytes: %w", derr)
		}
		if len(raw) == 0 {
			return fmt.Errorf("guest %s is empty — nothing to recover", remote)
		}
		if werr := safepath.WriteFile(keyPath, raw, 0o600); werr != nil {
			return fmt.Errorf("land recovered key at %s: %w", keyPath, werr)
		}
		out.Write("stdout", "Guest-agent recovery: "+remote+" → "+keyPath+" (0600)\n")
		return nil
	}
}
