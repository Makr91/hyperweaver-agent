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
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// The provision-chain children — the ONE document walk (Mark's ruling
// 2026-07-17: there are no phases): machine_wait_ssh polls the guest,
// machine_sync lands ONE folder (transport per the folder's own type: rsync |
// scp; virtualbox attaches a real shared folder), and every walk executor
// below runs ONE document entry exactly where the stored provisioning:
// section placed it. The chain is linear — every child depends_on its
// predecessor — so the walk's LAST task carries final: true and stamps
// provisioner_state on success (stampIfFinal).

// Provision-chain operations. OpProvisionParent survives ONLY as the
// /run-provisioners anchor — the full pipeline chains method and hook
// children directly under the orchestration parent.
const (
	OpProvisionOrchestration = "machine_provision_orchestration"
	OpWaitSSH                = "machine_wait_ssh"
	OpSyncParent             = "machine_sync_parent"
	OpSyncFolder             = "machine_sync"
	OpShellScript            = "machine_shell"
	OpProvisionParent        = "machine_provision_parent"
	OpProvisionPlaybook      = "machine_provision"
	OpRemotePlaybook         = "machine_provision_remote"
	OpDockerCompose          = "machine_docker_compose"
	OpHook                   = "machine_hook"
)

// provisionTaskMetadata is the wait_ssh/sync/shell/provision/remote/docker/
// hook children's metadata — the base's exact shape: {ip, port, credentials,
// folder?, script?, playbook?, compose_file?, hook?} plus final, marking the
// walk's overall LAST task (the provisioned-state stamp rides it — the
// whole-walk stamp ruling). Communicator/WinRM are zoneweaver's exact winrm
// metadata shape (sync 2026-07-17: W-Q1..W-Q5): communicator "winrm" flips
// the SAME ops onto their winrm MECHANISM (never new ops), and the winrm
// block carries the document's RULED knobs — the guest port, transport, and
// peer-verification the connection vars derive from.
type provisionTaskMetadata struct {
	IP           string             `json:"ip"`
	Port         int                `json:"port"`
	Credentials  sshrun.Credentials `json:"credentials"`
	Communicator string             `json:"communicator,omitempty"`
	WinRM        *struct {
		Port                int    `json:"port"`
		Transport           string `json:"transport"`
		SSLPeerVerification bool   `json:"ssl_peer_verification"`
	} `json:"winrm,omitempty"`
	Folder      *Folder   `json:"folder,omitempty"`
	Script      string    `json:"script,omitempty"`
	Playbook    *Playbook `json:"playbook,omitempty"`
	ComposeFile string    `json:"compose_file,omitempty"`
	Hook        *Hook     `json:"hook,omitempty"`
	Final       bool      `json:"final,omitempty"`
}

func readProvisionMetadata(task *tasks.Task) (*provisionTaskMetadata, error) {
	if task.Metadata == nil {
		return nil, errors.New("provision task has no metadata")
	}
	var meta provisionTaskMetadata
	if err := json.Unmarshal([]byte(*task.Metadata), &meta); err != nil {
		return nil, fmt.Errorf("parse provision metadata: %w", err)
	}
	if meta.IP == "" {
		return nil, errors.New("ip is required in task metadata")
	}
	if meta.Port == 0 {
		meta.Port = 22
	}
	return &meta, nil
}

// stampIfFinal records provisioner_state.last_provisioned_at when the task is
// the walk's final child. The chain is linear — every child depends_on its
// predecessor and failures cascade-cancel — so the final task's success
// proves the WHOLE walk's (Mark's whole-walk stamp ruling): a partial run
// must never mark the machine provisioned, or the once/not_first filters flip
// after a mid-chain failure. context.Background() keeps the bookkeeping alive
// through cancellation; a stamp failure narrates and never fails the task.
func (e *executors) stampIfFinal(task *tasks.Task, meta *provisionTaskMetadata, out *tasks.OutputWriter) {
	if !meta.Final {
		return
	}
	e.taskProgress(task, 95, "recording_provision_state")
	if serr := e.store.StampProvisionerState(context.Background(), task.MachineName); serr != nil {
		out.Write("stderr", "Failed to record provision state: "+serr.Error()+"\n")
	}
}

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

// syncFolder executes machine_sync — ONE folder (executeZoneSyncTask 1:1):
// skip disabled/virtualbox entries, resolve a relative map against the
// working directory, pre-create the destination, transport over the folder's
// ladder (runFolderTransport — binary rsync/scp with pure-Go fallbacks),
// chown to owner:group after.
func (e *executors) syncFolder(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	meta, err := readProvisionMetadata(task)
	if err != nil {
		return err
	}
	if meta.Folder == nil {
		return errors.New("folder is required in task metadata")
	}
	folder := meta.Folder
	if folder.Disabled {
		out.Write("stdout", "Folder sync skipped (disabled)\n")
		// A disabled folder can still be the walk's final task — its skip is
		// a success, so the whole-walk stamp must not be lost with it.
		e.stampIfFinal(task, meta, out)
		return nil
	}
	if folder.Map == "" || folder.To == "" {
		return errors.New("folder missing source (map) or destination (to)")
	}
	if strings.EqualFold(folder.Type, "virtualbox") {
		return e.attachSharedFolder(ctx, task, meta, folder, out)
	}

	workdir := e.machineWorkdir(task.MachineName)
	source := folder.Map
	if !strings.HasPrefix(source, "/") && !strings.Contains(source, ":") {
		source = workdir + "/" + strings.TrimPrefix(strings.TrimPrefix(source, "./"), ".")
	}

	e.taskProgress(task, 10, "creating_destination")
	out.Write("stdout", "Syncing "+source+" → "+folder.To+" ("+transportFor(folder)+")\n")
	if rerr := sshrun.Run(ctx, meta.IP, meta.Port, meta.Credentials,
		"sudo mkdir -p "+folder.To, workdir, e.env.ProvisionKeyPath, time.Minute, out.Write); rerr != nil {
		return fmt.Errorf("pre-create %s: %w", folder.To, rerr)
	}

	e.taskProgress(task, 30, "syncing_files")
	if terr := e.runFolderTransport(ctx, meta, folder, source, workdir, out); terr != nil {
		return terr
	}

	e.taskProgress(task, 85, "setting_ownership")
	owner := folder.Owner
	if owner == "" {
		owner = meta.Credentials.Username
	}
	if owner == "" {
		owner = "root"
	}
	group := folder.Group
	if group == "" {
		group = owner
	}
	if cerr := sshrun.Run(ctx, meta.IP, meta.Port, meta.Credentials,
		"sudo chown -R "+owner+":"+group+" "+folder.To,
		workdir, e.env.ProvisionKeyPath, time.Minute, out.Write); cerr != nil {
		out.Write("stderr", "chown "+folder.To+" failed: "+cerr.Error()+"\n")
	}
	e.stampIfFinal(task, meta, out)
	e.taskProgress(task, 100, "completed")
	return nil
}

// attachSharedFolder lands a `type: virtualbox` folder as a REAL VirtualBox
// shared folder (Mark's go 2026-07-12 — these were skipped before): register
// on the VM (hot-add works while running; already-registered narrates as the
// idempotent re-sync), then mount in the guest — vboxsf needs Guest
// Additions, so a mount failure narrates the automount fallback instead of
// failing the pipeline.
func (e *executors) attachSharedFolder(ctx context.Context, task *tasks.Task,
	meta *provisionTaskMetadata, folder *Folder, out *tasks.OutputWriter,
) error {
	machine, vboxExe, err := e.resolve(ctx, task)
	if err != nil {
		return err
	}
	hostPath := filepath.FromSlash(folder.Map)
	if !filepath.IsAbs(hostPath) {
		hostPath = filepath.Join(e.machineWorkdir(task.MachineName),
			strings.TrimPrefix(strings.TrimPrefix(folder.Map, "./"), "."))
	}
	shareName := sharedFolderName(folder.To)

	e.taskProgress(task, 20, "registering_shared_folder")
	out.Write("stdout", "Registering VirtualBox shared folder "+shareName+" ("+hostPath+" → "+folder.To+")\n")
	if aerr := vbox.SharedFolderAdd(ctx, vboxExe, machine.VBoxTarget(), shareName, hostPath, folder.To); aerr != nil {
		if !strings.Contains(aerr.Error(), "already exists") {
			return aerr
		}
		out.Write("stdout", "Shared folder already registered — continuing\n")
	}

	// Guest mount (vagrant's model): skipped when automount already landed it.
	owner := folder.Owner
	if owner == "" {
		owner = meta.Credentials.Username
	}
	if owner == "" {
		owner = "root"
	}
	group := folder.Group
	if group == "" {
		group = owner
	}
	e.taskProgress(task, 60, "mounting_in_guest")
	mount := fmt.Sprintf(
		"sudo mkdir -p %s && (mount | grep -q ' %s ' || sudo mount -t vboxsf -o uid=$(id -u %s),gid=$(getent group %s | cut -d: -f3) %s %s)",
		folder.To, folder.To, owner, group, shareName, folder.To)
	if merr := sshrun.Run(ctx, meta.IP, meta.Port, meta.Credentials, mount,
		e.machineWorkdir(task.MachineName), e.env.ProvisionKeyPath, time.Minute, out.Write); merr != nil {
		out.Write("stderr", "Guest mount failed ("+merr.Error()+") — vboxsf needs Guest Additions; the automount lands it at "+folder.To+" when they run\n")
	} else {
		out.Write("stdout", "Shared folder mounted at "+folder.To+"\n")
	}
	e.stampIfFinal(task, meta, out)
	e.taskProgress(task, 100, "completed")
	return nil
}

// sharedFolderName derives the share's registry name from the guest path
// (vagrant's rule: "/vagrant" → "vagrant").
func sharedFolderName(guestPath string) string {
	name := strings.Trim(strings.ReplaceAll(guestPath, "/", "_"), "_")
	if name == "" {
		return "shared"
	}
	return name
}

// runFolderTransport lands one folder over the transport ladder (Mark's
// vagrant-optional ruling 2026-07-07): the folder's chosen tool first — the
// runtime-proven binary path — falling to the agent's built-in pure-Go
// transports ONLY when the tool is ABSENT. A failed run stays a failure:
// silently switching transports would hide real errors.
//
//	rsync: system/vagrant rsync binary → built-in Go rsync client (the
//	       guest's own rsync serves the remote half, same as the binary path)
//	scp:   system/vagrant/Windows-OpenSSH scp binary → built-in SFTP
func (e *executors) runFolderTransport(ctx context.Context, meta *provisionTaskMetadata,
	folder *Folder, source, workdir string, out *tasks.OutputWriter,
) error {
	if transportFor(folder) == SyncSCP {
		// scp and SFTP write as the SSH user (rsync writes as root through
		// --rsync-path='sudo rsync') — hand the freshly sudo-created
		// destination to that user first; the post-sync chown still sets the
		// folder's final ownership.
		e.preChownDestination(ctx, meta, folder, workdir, out)
		if scpExe, lerr := sshrun.FindTool("scp"); lerr == nil {
			if serr := sshrun.SCPSync(ctx, scpExe, meta.IP, meta.Port, meta.Credentials,
				source, folder.To, workdir, e.env.ProvisionKeyPath, out.Write); serr != nil {
				return fmt.Errorf("%s → %s: %w", folder.Map, folder.To, serr)
			}
			return nil
		}
		out.Write("stdout", "scp binary not found on this host — using the built-in SFTP transport (pure Go, no host tools)\n")
		if serr := sshrun.SFTPSync(ctx, meta.IP, meta.Port, meta.Credentials,
			source, folder.To, workdir, e.env.ProvisionKeyPath, out.Write); serr != nil {
			return fmt.Errorf("%s → %s: %w", folder.Map, folder.To, serr)
		}
		return nil
	}

	options := &sshrun.SyncOptions{
		Args:    folder.Args,
		Exclude: folder.Exclude,
		Delete:  folder.Delete,
	}
	// PATH first, then vagrant's embedded toolchain (a vagrant install
	// carries a working rsync on every platform) — but vagrant is OPTIONAL:
	// no rsync binary anywhere drops to the embedded Go rsync client.
	if rsyncExe, lerr := sshrun.FindTool("rsync"); lerr == nil {
		if serr := sshrun.SyncFiles(ctx, rsyncExe, meta.IP, meta.Port, meta.Credentials,
			source, folder.To, workdir, e.env.ProvisionKeyPath, options, out.Write); serr != nil {
			return fmt.Errorf("%s → %s: %w", folder.Map, folder.To, serr)
		}
		return nil
	}
	out.Write("stdout", "rsync binary not found on this host — using the built-in Go rsync client (the guest's own rsync serves the remote half)\n")
	if serr := sshrun.BuiltinRsyncSync(ctx, meta.IP, meta.Port, meta.Credentials,
		source, folder.To, workdir, e.env.ProvisionKeyPath, options, out.Write); serr != nil {
		return fmt.Errorf("%s → %s: %w", folder.Map, folder.To, serr)
	}
	return nil
}

// preChownDestination hands the destination directory to the SSH user before
// a user-privileged transport writes into it (sudo mkdir -p left it
// root-owned). Failures narrate and never fail the sync — the transport's
// own error tells the real story.
func (e *executors) preChownDestination(ctx context.Context, meta *provisionTaskMetadata,
	folder *Folder, workdir string, out *tasks.OutputWriter,
) {
	owner := meta.Credentials.Username
	if owner == "" {
		owner = "root"
	}
	if cerr := sshrun.Run(ctx, meta.IP, meta.Port, meta.Credentials,
		"sudo chown -R "+owner+":"+owner+" "+folder.To,
		workdir, e.env.ProvisionKeyPath, time.Minute, out.Write); cerr != nil {
		out.Write("stderr", "pre-sync chown "+folder.To+" failed: "+cerr.Error()+"\n")
	}
}

// transportFor resolves a folder's sync transport: the folder's own type
// wins; anything not scp is rsync (the base is rsync-only; scp exists for
// Mark's broken-macOS-rsync rule and the document's per-folder choice).
func transportFor(folder *Folder) string {
	if strings.EqualFold(folder.Type, SyncSCP) {
		return SyncSCP
	}
	return SyncRsync
}

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

// provisionPlaybook executes machine_provision — ONE playbook
// (executeZoneProvisionTask + runAnsibleLocalProvisioner 1:1): extra_vars
// built AT RUN TIME from the stored document + working-directory secrets,
// ansible installed in the guest (pip or pkg), galaxy collections --force,
// then ansible-playbook -i 'localhost,' -c local with the JSON extra_vars;
// provisioner_state.last_provisioned_at stamps only on the walk's final task
// (metadata final: true — stampIfFinal).
func (e *executors) provisionPlaybook(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	meta, err := readProvisionMetadata(task)
	if err != nil {
		return err
	}
	if meta.Playbook == nil || meta.Playbook.Playbook == "" {
		return errors.New("playbook is required in task metadata")
	}
	playbook := meta.Playbook

	machine, err := e.store.Get(ctx, task.MachineName)
	if err != nil {
		return fmt.Errorf("machine %s: %w", task.MachineName, err)
	}
	config := ParseConfiguration(machine)
	e.fillLiveMACs(ctx, machine, config, out)
	workdir := e.machineWorkdir(task.MachineName)

	installTimeout := e.env.AnsibleInstallTimeout
	if installTimeout <= 0 {
		installTimeout = 300 * time.Second
	}
	playbookTimeout := e.env.PlaybookTimeout
	if playbookTimeout <= 0 {
		playbookTimeout = 21600 * time.Second
	}

	e.taskProgress(task, 10, "installing_ansible")
	if playbook.InstallMode != "" {
		installCommand := "pkg install ansible 2>/dev/null || sudo apt-get install -y ansible 2>/dev/null || sudo yum install -y ansible 2>/dev/null"
		if playbook.InstallMode == "pip" {
			installCommand = "pip3 install ansible 2>/dev/null || pip install ansible 2>/dev/null"
		}
		if ierr := sshrun.Run(ctx, meta.IP, meta.Port, meta.Credentials, installCommand,
			workdir, e.env.ProvisionKeyPath, installTimeout, out.Write); ierr != nil {
			out.Write("stderr", "ansible install reported: "+ierr.Error()+" (continuing — it may already be present)\n")
		}
	}

	e.taskProgress(task, 25, "installing_collections")
	if playbook.RemoteCollections {
		for _, collection := range playbook.Collections {
			if cerr := sshrun.Run(ctx, meta.IP, meta.Port, meta.Credentials,
				"ansible-galaxy collection install "+collection+" --force",
				workdir, e.env.ProvisionKeyPath, installTimeout, out.Write); cerr != nil {
				return fmt.Errorf("install collection %s: %w", collection, cerr)
			}
		}
	} else if len(playbook.Collections) > 0 {
		// Hosts.rb's remote_collections:false contract (Mark's ruling
		// 2026-07-07): the collections ship INSIDE the provisioner package
		// and reach the guest through the folder sync — the galaxy is never
		// called (guests need no internet for them; zoneweaver's
		// always-install is its routed-network reality, not the contract).
		out.Write("stdout", "Collections are package-local (remote_collections: false) — skipping ansible-galaxy\n")
	}

	e.taskProgress(task, 40, "running_playbook")
	extraVars := BuildPlaybookExtraVars(
		BuildExtraVars(machine, config, workdir), playbook)
	varsJSON, err := json.Marshal(extraVars)
	if err != nil {
		return err
	}
	// The base's single-quote escaping for the remote shell.
	escaped := strings.ReplaceAll(string(varsJSON), "'", `'\''`)

	// The base's command shape exactly: cd to provisioning_path (default
	// /vagrant), ANSIBLE_CONFIG only when the playbook names a config_file.
	provisioningPath := playbook.ProvisioningPath
	if provisioningPath == "" {
		provisioningPath = "/vagrant"
	}
	// Hosts.rb:519 sets ansible.config_file to /vagrant/ansible/ansible.cfg
	// unconditionally for every local playbook — the document's own value
	// wins here, the vagrant default covers documents that omit it (Mark's
	// review 2026-07-07: it was never the template's job).
	configFile := playbook.ConfigFile
	if configFile == "" {
		configFile = "/vagrant/ansible/ansible.cfg"
	}
	ansibleConfig := "ANSIBLE_CONFIG=" + configFile + " "
	command := fmt.Sprintf("cd %s && %sansible-playbook -i 'localhost,' -c local %s --extra-vars '%s'",
		provisioningPath, ansibleConfig, playbook.Playbook, escaped)

	out.Write("stdout", "Running ansible-local playbook "+playbook.Playbook+"\n")
	// STARTcloud progress adoption: watch the streamed ansible output for the
	// packages' callback marker (PROGRESS::{json}, progress_scan.go) and fold
	// it into the task's progress_info live (the guest's percent maps into
	// this task's running_playbook window, 40→95 — the task percent stays
	// honest across the install/collections phases before it and the stamp
	// after).
	scanner := newProgressScanner(func(percent int, description string) {
		e.playbookProgress(task, percent, description)
	})
	streamWrite := func(stream, data string) {
		scanner.Scan(stream, data)
		out.Write(stream, data)
	}
	if rerr := sshrun.Run(ctx, meta.IP, meta.Port, meta.Credentials, command,
		workdir, e.env.ProvisionKeyPath, playbookTimeout, streamWrite); rerr != nil {
		return fmt.Errorf("ansible-local failed: %w", rerr)
	}

	e.stampIfFinal(task, meta, out)
	e.taskProgress(task, 100, "completed")
	out.Write("stdout", "Playbook completed: "+playbook.Playbook+"\n")
	return nil
}

// fillLiveMACs resolves auto/empty networks[].mac entries in the PARSED
// configuration copy feeding the extra_vars — the networking role's netplan
// matches guest adapters BY MAC (runtime-proven 2026-07-07: a vars mac of
// "auto" left the second adapter addressless mid-provision), while the
// STORED document keeps the user's own words verbatim (Mark's ruling: the
// document is the user's source of truth — hypervisor facts are resolved
// into the run's variable document ONLY, zoneweaver's live-scan model).
// Adapter numbering follows the create layout: NAT at 1, document network i
// at adapter i+2. The row's merged live view answers first; a fresh machine
// the sweeps haven't merged yet falls back to one live showvminfo. Failures
// narrate and never fail the run.
func (e *executors) fillLiveMACs(ctx context.Context, machine *Machine, config MachineConfig, out *tasks.OutputWriter) {
	var live *vbox.Info
	for i, entry := range config.List("networks") {
		network := mapOr(entry)
		if mac := stringOr(network["mac"], ""); mac != "" && !strings.EqualFold(mac, "auto") {
			continue
		}
		adapter := "macaddress" + strconv.Itoa(i+2)
		raw, _ := config[adapter].(string)
		if raw == "" {
			if live == nil {
				vboxExe := VBoxManagePath(ctx)
				if vboxExe == "" {
					out.Write("stderr", "Live MAC resolution skipped: VirtualBox is not installed\n")
					return
				}
				info, ierr := vbox.ShowVMInfo(ctx, vboxExe, machine.VBoxTarget())
				if ierr != nil {
					out.Write("stderr", "Live MAC resolution failed: "+ierr.Error()+"\n")
					return
				}
				live = info
			}
			raw = live.Raw[adapter]
		}
		if raw == "" {
			out.Write("stderr", fmt.Sprintf("No live MAC for adapter %d — networks[%d] keeps its document value\n", i+2, i))
			continue
		}
		network["mac"] = formatMAC(raw)
		out.Write("stdout", fmt.Sprintf("Resolved live MAC for networks[%d]: %s\n", i, network["mac"]))
	}
}

// formatMAC converts machinereadable's bare MAC ("080027018B40") into the
// colon form the roles expect ("08:00:27:01:8B:40").
func formatMAC(raw string) string {
	raw = strings.ToUpper(strings.TrimSpace(raw))
	if len(raw) != 12 {
		return raw
	}
	pairs := make([]string, 0, 6)
	for i := 0; i < len(raw); i += 2 {
		pairs = append(pairs, raw[i:i+2])
	}
	return strings.Join(pairs, ":")
}

// syncParentAnchor is the zone_sync_parent/zone_provision_parent executor —
// the parents are pure anchors: their children's completion drives their
// aggregation (they are created as running containers and finish through the
// parent-progress rollup).
func (e *executors) parentAnchor(_ context.Context, _ *tasks.Task, _ *tasks.OutputWriter) error {
	return nil
}
