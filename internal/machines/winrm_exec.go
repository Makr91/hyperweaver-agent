package machines

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/ansiblehost"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// errWinRMNeedsAnsible is the honest gate on every winrm mechanism: the
// agent host itself speaks winrm through ansible (+pywinrm) — no pre-flight
// exists at POST /provision (ruled W-Q4), the executor fails honestly.
var errWinRMNeedsAnsible = errors.New("winrm transport needs ansible (+pywinrm) on the agent host — not installed (Windows hosts: ansible + pywinrm inside WSL's default distribution)")

// winrmConnectionVars is the EXACT winrm connection var set (zoneweaver's
// shipped winrm shape, sync 2026-07-17: W-Q1..W-Q5) — shared by win_ping,
// the win_copy/win_shell script runs, and remote playbooks against a winrm
// guest: connection/user/password/port plus ansible_winrm_transport=ntlm
// ALWAYS (negotiate rides ntlm — zoneweaver ships this), the https scheme
// ONLY when the document transport is ssl, and cert-validation ignore ONLY
// when the document turned peer verification off. ansible_port is the
// RESOLVED transport port (the NAT winrm forward when one exists).
func winrmConnectionVars(meta *provisionTaskMetadata) map[string]any {
	vars := map[string]any{
		"ansible_connection":      "winrm",
		"ansible_user":            meta.Credentials.Username,
		"ansible_password":        meta.Credentials.Password,
		"ansible_port":            meta.Port,
		"ansible_winrm_transport": "ntlm",
	}
	if meta.WinRM != nil {
		if meta.WinRM.Transport == "ssl" {
			vars["ansible_winrm_scheme"] = "https"
		}
		if !meta.WinRM.SSLPeerVerification {
			vars["ansible_winrm_server_cert_validation"] = "ignore"
		}
	}
	return vars
}

// waitWinRM is machine_wait_ssh's winrm mechanism: poll the guest with
// host-ansible win_ping (`ansible all -i '<ip>,' -m win_ping` + the shared
// connection vars as ONE --extra-vars JSON) on the same interval until
// success or the same timeout — never a new op, the SAME wait branching on
// its metadata (W-Q1..W-Q5).
func (e *executors) waitWinRM(ctx context.Context, task *tasks.Task,
	meta *provisionTaskMetadata, timeout, interval time.Duration, out *tasks.OutputWriter,
) (time.Duration, error) {
	runner, err := ansiblehost.Resolve(ctx, "ansible")
	if err != nil {
		return 0, errWinRMNeedsAnsible
	}
	dialIP, cleanupTransport, err := e.wslReachableTransport(ctx, runner,
		task.MachineName, meta.IP, meta.Port, wslWinRMGuestPort(meta), wslRuleWinRM, out)
	if err != nil {
		return 0, err
	}
	defer cleanupTransport()
	varsJSON, err := json.Marshal(winrmConnectionVars(meta))
	if err != nil {
		return 0, err
	}
	inv, err := runner.Invocation("ansible", nil, "",
		"all", "-i", dialIP+",", "-m", "win_ping", "--extra-vars", string(varsJSON))
	if err != nil {
		return 0, errWinRMNeedsAnsible
	}
	workdir := e.machineWorkdir(task.MachineName)
	start := time.Now()
	deadline := start.Add(timeout)
	for {
		if ctx.Err() != nil {
			return time.Since(start), ctx.Err()
		}
		if time.Now().After(deadline) {
			return time.Since(start), fmt.Errorf("WinRM not available after %ds", int(timeout.Seconds()))
		}
		attemptCtx, cancel := context.WithTimeout(ctx, time.Minute)
		perr := runHostCommand(attemptCtx, out, workdir, inv.Env, nil, inv.Exe, inv.Args...)
		cancel()
		if perr == nil {
			return time.Since(start), nil
		}
		select {
		case <-ctx.Done():
			return time.Since(start), ctx.Err()
		case <-time.After(interval):
		}
	}
}

// runWinRMScript lands ONE script on a winrm guest and runs it — NO
// transient playbook (ruled W-Q1..W-Q5): THREE ad-hoc ansible module calls
// on the agent host, inventory -i '<ip>,': win_copy the resolved working-copy
// script to C:\Windows\Temp\hw-shell-<taskId>.ps1 (hw- prefix — zoneweaver
// uses zw-, the prefix-only divergence the D14 rule permits), win_shell it
// with the document's vars inlined as PowerShell $env: assignments in
// DOCUMENT ORDER, then win_file state=absent (a cleanup failure narrates,
// never fails the task). Shared by the shell provisioner and guest-target
// sequence hooks — the runGuestScript twin, mechanism per communicator.
func (e *executors) runWinRMScript(ctx context.Context, task *tasks.Task,
	meta *provisionTaskMetadata, script string, out *tasks.OutputWriter,
) error {
	runner, err := ansiblehost.Resolve(ctx, "ansible")
	if err != nil {
		return errWinRMNeedsAnsible
	}
	dialIP, cleanupTransport, err := e.wslReachableTransport(ctx, runner,
		task.MachineName, meta.IP, meta.Port, wslWinRMGuestPort(meta), wslRuleWinRM, out)
	if err != nil {
		return err
	}
	defer cleanupTransport()
	workdir := e.machineWorkdir(task.MachineName)
	local := filepath.FromSlash(script)
	if !filepath.IsAbs(local) {
		local = filepath.Join(workdir,
			strings.TrimPrefix(strings.TrimPrefix(script, "./"), "."))
	}
	if _, serr := os.Stat(local); serr != nil {
		return fmt.Errorf("script %s is not in the working copy (%s) — the package must ship it: %w",
			script, local, serr)
	}

	// The remote path carries NO document input (task id only) — the same
	// collision-free rule the SSH mechanism applies.
	remote := `C:\Windows\Temp\hw-shell-` + task.ID + `.ps1`
	timeout := e.env.PlaybookTimeout
	if timeout <= 0 {
		timeout = 21600 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	varsJSON, err := json.Marshal(winrmConnectionVars(meta))
	if err != nil {
		return err
	}
	adhoc := func(module, moduleArgs string) error {
		inv, ierr := runner.Invocation("ansible", nil, "",
			"all", "-i", dialIP+",", "-m", module, "-a", moduleArgs,
			"--extra-vars", string(varsJSON))
		if ierr != nil {
			return ierr
		}
		return runHostCommand(runCtx, out, workdir, inv.Env, nil, inv.Exe, inv.Args...)
	}

	// vars → env (design §5's rule on the winrm mechanism): the document's
	// global vars ride as $env: assignments inlined before the call, in
	// DOCUMENT ORDER — the raw section bytes feed the builder.
	env := ""
	if machine, gerr := e.store.Get(ctx, task.MachineName); gerr == nil {
		env = psEnvAssignments(RawObject(RawProvisioner(machine))["vars"], out)
	}

	e.taskProgress(task, 15, "uploading_script")
	out.Write("stdout", "Uploading "+script+" → "+remote+" (win_copy)\n")
	copyArgs, err := json.Marshal(map[string]string{"src": runner.Path(local), "dest": remote})
	if err != nil {
		return err
	}
	if cerr := adhoc("win_copy", string(copyArgs)); cerr != nil {
		return fmt.Errorf("upload %s: %w", script, cerr)
	}

	e.taskProgress(task, 30, "running_script")
	out.Write("stdout", "Running "+script+" (win_shell)\n")
	shellErr := adhoc("win_shell", env+"& '"+remote+"'")

	// Cleanup ALWAYS runs (the SSH mechanism's rm -f twin); its failure only
	// narrates — the script's own exit told the real story.
	fileArgs, ferr := json.Marshal(map[string]string{"state": "absent", "path": remote})
	if ferr == nil {
		if rerr := adhoc("win_file", string(fileArgs)); rerr != nil {
			out.Write("stderr", "cleanup of "+remote+" failed: "+rerr.Error()+"\n")
		}
	}
	if shellErr != nil {
		return fmt.Errorf("script %s failed: %w", script, shellErr)
	}
	return nil
}

// psEnvAssignments renders the document's raw vars section as PowerShell
// `$env:KEY = 'value'; ` assignments (shellEnvAssignments' winrm twin):
// strings verbatim, scalars in their document spelling, lists/dicts as raw
// JSON bytes — PowerShell single-quote escaping doubles the quote. POSIX-legal
// names only (PowerShell env names are wider, but the ruled vocabulary stays
// one — others narrate-skip, the existing envNamePattern rule); the
// document's own key order IS the order.
func psEnvAssignments(varsRaw json.RawMessage, out *tasks.OutputWriter) string {
	keys := OrderedKeys(varsRaw)
	if len(keys) == 0 {
		return ""
	}
	values := RawObject(varsRaw)
	var b strings.Builder
	for _, key := range keys {
		if !envNamePattern.MatchString(key) {
			out.Write("stderr", "vars."+key+" cannot export as an environment name — skipped\n")
			continue
		}
		text, ok := envValueText(key, values[key], out)
		if !ok {
			continue
		}
		b.WriteString("$env:")
		b.WriteString(key)
		b.WriteString(" = '")
		b.WriteString(strings.ReplaceAll(text, "'", "''"))
		b.WriteString("'; ")
	}
	return b.String()
}
