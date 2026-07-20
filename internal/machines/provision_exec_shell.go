package machines

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/sshrun"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// runShellScript executes machine_shell — ONE provisioning.shell.scripts[]
// entry (core/Hosts.rb:493-497's vagrant shell provisioner, spoken over the
// pipeline's own transport), run exactly where the document walk placed it:
// resolve the package-relative path against the working copy, upload over the
// built-in SFTP floor (never dependent on a folder sync carrying it — vagrant
// uploads too), chmod +x, execute with sudo (vagrant's privileged default,
// shebang honored), remove. The guest exit code fails the task honestly.
func (e *executors) runShellScript(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	meta, err := readProvisionMetadata(task)
	if err != nil {
		return err
	}
	if meta.Script == "" {
		return errors.New("script is required in task metadata")
	}
	// The SAME op, the communicator's mechanism (W-Q1..W-Q5): winrm guests
	// take the win_copy/win_shell/win_file triple instead of SFTP+sudo.
	runScript := e.runGuestScript
	if meta.Communicator == "winrm" {
		runScript = e.runWinRMScript
	}
	if err := runScript(ctx, task, meta, meta.Script, out); err != nil {
		return err
	}
	e.stampIfFinal(task, meta, out)
	e.taskProgress(task, 100, "completed")
	out.Write("stdout", "Shell script completed: "+meta.Script+"\n")
	return nil
}

// runGuestScript lands ONE script in the guest and runs it: resolve the
// package-relative path against the working copy, upload over the built-in
// SFTP floor, chmod +x, sudo exec with the document's vars as env
// (assignments AFTER sudo so they survive env_reset), remove. Shared by the
// shell provisioner and guest-target sequence hooks.
func (e *executors) runGuestScript(ctx context.Context, task *tasks.Task,
	meta *provisionTaskMetadata, script string, out *tasks.OutputWriter,
) error {
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

	// The remote path carries NO document input (task id only): nothing to
	// shell-quote, and chained scripts can never collide.
	remote := "/tmp/hw-shell-" + task.ID + ".sh"
	timeout := e.env.PlaybookTimeout
	if timeout <= 0 {
		timeout = 21600 * time.Second
	}

	// vars → env (design §5, ruled 2026-07-16): the document's global vars
	// export under their EXACT names, no prefix; lists/dicts ride as JSON
	// strings. The RAW section bytes feed the builder — the map view would
	// alphabetize the document's own key order.
	env := ""
	if machine, gerr := e.store.Get(ctx, task.MachineName); gerr == nil {
		env = shellEnvAssignments(RawObject(RawProvisioner(machine))["vars"], out)
	}

	e.taskProgress(task, 15, "uploading_script")
	out.Write("stdout", "Uploading "+script+" → "+remote+"\n")
	if uerr := sshrun.UploadFile(ctx, meta.IP, meta.Port, meta.Credentials,
		local, remote, workdir, e.env.ProvisionKeyPath); uerr != nil {
		return fmt.Errorf("upload %s: %w", script, uerr)
	}

	e.taskProgress(task, 30, "running_script")
	out.Write("stdout", "Running "+script+" (sudo)\n")
	command := fmt.Sprintf("chmod +x %[1]s && sudo %[2]s%[1]s; rc=$?; rm -f %[1]s; exit $rc", remote, env)
	if rerr := sshrun.Run(ctx, meta.IP, meta.Port, meta.Credentials, command,
		workdir, e.env.ProvisionKeyPath, timeout, out.Write); rerr != nil {
		return fmt.Errorf("script %s failed: %w", script, rerr)
	}
	return nil
}

// runHook executes machine_hook — ONE sequence-hook entry (design §5, ruled
// shape; the walk plans pre[] before the first method and post[] after the
// last): guest target rides the shared guest-script mechanic; host target
// runs the working-copy script ON THE AGENT HOST, gated by
// provisioning.host_hooks (the HTTP pre-flight already refused unconfirmed
// documents — this gate is the backstop). on_failure: continue narrates the
// failure and lets the sequence proceed.
func (e *executors) runHook(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	meta, err := readProvisionMetadata(task)
	if err != nil {
		return err
	}
	if meta.Hook == nil || meta.Hook.Script == "" {
		return errors.New("hook is required in task metadata")
	}
	hook := meta.Hook

	var runErr error
	switch {
	case hook.HostTarget():
		if !e.env.HostHooks {
			return errors.New("host-target hooks are disabled (provisioning.host_hooks: false)")
		}
		runErr = e.runHostHookScript(ctx, task, hook.Script, out)
	case meta.Communicator == "winrm":
		// Guest-target hooks on winrm guests ride the winrm script mechanism
		// (W-Q1..W-Q5); host-target hooks above are UNAFFECTED — they run on
		// the agent host regardless of the guest's communicator.
		runErr = e.runWinRMScript(ctx, task, meta, hook.Script, out)
	default:
		runErr = e.runGuestScript(ctx, task, meta, hook.Script, out)
	}
	if runErr != nil {
		if strings.EqualFold(hook.OnFailure, "continue") {
			out.Write("stderr", "Hook "+hook.Script+" failed (on_failure: continue): "+runErr.Error()+"\n")
			// An ignored failure still completes the chain — the stamp rides.
			e.stampIfFinal(task, meta, out)
			e.taskProgress(task, 100, "completed_with_ignored_failure")
			return nil
		}
		return runErr
	}
	e.stampIfFinal(task, meta, out)
	e.taskProgress(task, 100, "completed")
	out.Write("stdout", "Hook completed: "+hook.Script+" ("+hook.Target+")\n")
	return nil
}

// runHostHookScript runs one working-copy script on the agent host: .ps1
// through powershell on Windows, direct exec (shebang honored, +x ensured)
// elsewhere. The document's vars ride as real environment entries.
func (e *executors) runHostHookScript(ctx context.Context, task *tasks.Task,
	script string, out *tasks.OutputWriter,
) error {
	workdir := e.machineWorkdir(task.MachineName)
	if machine, gerr := e.store.Get(ctx, task.MachineName); gerr == nil &&
		machine.Home != nil && *machine.Home != "" {
		workdir = *machine.Home
	}
	local := filepath.FromSlash(script)
	if !filepath.IsAbs(local) {
		local = filepath.Join(workdir,
			strings.TrimPrefix(strings.TrimPrefix(script, "./"), "."))
	}
	if _, serr := os.Stat(local); serr != nil {
		return fmt.Errorf("host hook %s is not in the working copy (%s): %w", script, local, serr)
	}

	env := append([]string{}, os.Environ()...)
	if machine, gerr := e.store.Get(ctx, task.MachineName); gerr == nil {
		env = append(env, hostEnvEntries(RawObject(RawProvisioner(machine))["vars"], out)...)
	}

	timeout := e.env.PlaybookTimeout
	if timeout <= 0 {
		timeout = 21600 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	out.Write("stdout", "Running host hook "+script+"\n")
	if runtime.GOOS == "windows" && strings.EqualFold(filepath.Ext(local), ".ps1") {
		return runHostCommand(runCtx, out, workdir, env, nil,
			"powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", local)
	}
	if runtime.GOOS != "windows" {
		// Add owner-exec ONLY, preserving the author's own mode — direct exec
		// needs the bit, and blanket 0755 would widen a package's 0600 script.
		if info, ierr := os.Stat(local); ierr == nil && info.Mode().Perm()&0o100 == 0 {
			if cerr := os.Chmod(local, info.Mode().Perm()|0o100); cerr != nil {
				out.Write("stderr", "chmod u+x "+local+" failed: "+cerr.Error()+"\n")
			}
		}
	}
	return runHostCommand(runCtx, out, workdir, env, nil, local)
}

// hostEnvEntries renders the document's raw vars section as KEY=value
// environment entries (host-hook exec — the same value encoding
// shellEnvAssignments uses, without shell quoting: argv env needs none).
// Keys walk in the document's own order — the ruling's order.
func hostEnvEntries(varsRaw json.RawMessage, out *tasks.OutputWriter) []string {
	keys := OrderedKeys(varsRaw)
	if len(keys) == 0 {
		return nil
	}
	values := RawObject(varsRaw)
	entries := make([]string, 0, len(keys))
	for _, key := range keys {
		if !envNamePattern.MatchString(key) {
			out.Write("stderr", "vars."+key+" cannot export as an environment name — skipped\n")
			continue
		}
		text, ok := envValueText(key, values[key], out)
		if !ok {
			continue
		}
		entries = append(entries, key+"="+text)
	}
	return entries
}

// envValueText renders one raw vars value for the env builders. Scalars
// decode with UseNumber() so numbers keep their document spelling —
// json.Number's String() is the verbatim digits, where fmt.Sprint on a
// float64 would mangle large integers into e-notation. Objects and arrays
// ride as their own raw bytes: they ARE the JSON encoding, more verbatim
// than a re-marshal (which would alphabetize).
func envValueText(key string, valueRaw json.RawMessage, out *tasks.OutputWriter) (text string, ok bool) {
	trimmed := bytes.TrimSpace(valueRaw)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		return string(trimmed), true
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	var value any
	if derr := decoder.Decode(&value); derr != nil {
		out.Write("stderr", "vars."+key+" is not decodable — skipped\n")
		return "", false
	}
	switch v := value.(type) {
	case string:
		return v, true
	case json.Number:
		return v.String(), true
	case bool:
		return strconv.FormatBool(v), true
	default: // null — the only scalar left.
		return "", true
	}
}

// envNamePattern is what a POSIX environment name can carry — vars outside
// it cannot export and narrate instead of silently mangling.
var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// shellEnvAssignments renders the document's raw vars section as KEY='value'
// assignments (trailing space when any exist): strings verbatim, scalars in
// their document spelling, lists/dicts as their own raw JSON bytes — each
// single-quoted with the pipeline's standard escaping. The document's own
// key order IS the order (the ruling: vars ride verbatim, never re-sorted).
func shellEnvAssignments(varsRaw json.RawMessage, out *tasks.OutputWriter) string {
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
		b.WriteString(key)
		b.WriteString("='")
		b.WriteString(strings.ReplaceAll(text, "'", `'\''`))
		b.WriteString("' ")
	}
	return b.String()
}
