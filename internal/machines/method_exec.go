package machines

// Walk executors whose mechanism leaves the in-guest ansible path: ansible
// REMOTE (ansible-playbook running ON THE AGENT HOST over the guest transport
// — Hosts.rb:548-586's `server.vm.provision :ansible`, gated on host ansible
// presence) and docker compose (Hosts.rb:591-598, executed in the guest over
// the pipeline's SSH transport). local/remote is an ENTRY's execution
// mechanism in the document walk — never a phase.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/procattr"
	"github.com/Makr91/hyperweaver-agent/internal/sshrun"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// verbosePattern is ansible's -v ladder (v, vv, vvv, vvvv).
var verbosePattern = regexp.MustCompile(`^v{1,4}$`)

// runRemotePlaybook executes machine_provision_remote — ONE remote playbook:
// ansible-playbook on the AGENT HOST, dialing the guest over the pipeline's
// own transport (the NAT ssh port-forward or the control IP). Gated on host
// ansible presence: no ansible-playbook binary is an honest failure, never a
// silent skip (Windows hosts fail here until the WSL control-node row lands —
// the design matrix's LATER). The provisioned-state stamp rides Final exactly
// like the local executor.
func (e *executors) runRemotePlaybook(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	meta, err := readProvisionMetadata(task)
	if err != nil {
		return err
	}
	if meta.Playbook == nil || meta.Playbook.Playbook == "" {
		return errors.New("playbook is required in task metadata")
	}
	playbook := meta.Playbook

	ansibleExe, err := exec.LookPath("ansible-playbook")
	if err != nil {
		return errors.New("remote playbooks run ansible-playbook ON THE AGENT HOST and this host has none — install ansible, or move the playbook to the local list (in-guest ansible)")
	}

	machine, err := e.store.Get(ctx, task.MachineName)
	if err != nil {
		return fmt.Errorf("machine %s: %w", task.MachineName, err)
	}
	config := ParseConfiguration(machine)
	e.fillLiveMACs(ctx, machine, config, out)
	workdir := e.machineWorkdir(task.MachineName)
	if machine.Home != nil && *machine.Home != "" {
		workdir = *machine.Home
	}

	timeout := e.env.PlaybookTimeout
	if timeout <= 0 {
		timeout = 21600 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// remote_collections: true fetches from the galaxy ON THE HOST into the
	// working copy (vagrant's galaxy_role_file/galaxy_roles_path pair);
	// false means the package vendors them — ANSIBLE_COLLECTIONS_PATH below
	// resolves the shipped tree.
	if playbook.RemoteCollections {
		e.taskProgress(task, 15, "installing_collections")
		if galaxyExe, gerr := exec.LookPath("ansible-galaxy"); gerr == nil {
			requirements := filepath.Join(workdir, "ansible", "requirements.yml")
			if _, serr := os.Stat(requirements); serr == nil {
				if rerr := runHostCommand(runCtx, out, workdir, nil, nil, galaxyExe,
					"collection", "install", "-r", requirements,
					"-p", filepath.Join(workdir, "ansible", "ansible_collections"), "--force"); rerr != nil {
					return fmt.Errorf("ansible-galaxy install: %w", rerr)
				}
			} else {
				out.Write("stderr", "remote_collections is true but the working copy has no ansible/requirements.yml — skipping galaxy\n")
			}
			for _, collection := range playbook.Collections {
				if rerr := runHostCommand(runCtx, out, workdir, nil, nil, galaxyExe,
					"collection", "install", collection, "--force"); rerr != nil {
					return fmt.Errorf("install collection %s: %w", collection, rerr)
				}
			}
		} else {
			out.Write("stderr", "remote_collections is true but the host has no ansible-galaxy — relying on already-present collections\n")
		}
	}

	e.taskProgress(task, 40, "running_playbook")
	extraVars := BuildPlaybookExtraVars(
		BuildExtraVars(machine, config, workdir), playbook)
	varsJSON, err := json.Marshal(extraVars)
	if err != nil {
		return err
	}

	args := []string{"-i", meta.IP + ","}
	if meta.Communicator == "winrm" {
		// winrm guests replace the SSH connection args with the ruled winrm
		// var set (zoneweaver's shipped winrm shape, sync 2026-07-17:
		// W-Q1..W-Q5) — no --private-key, no ansible_ssh_common_args. The set
		// rides ONE --extra-vars JSON argument, the same argv channel the
		// playbook extra_vars below already use.
		winrmJSON, werr := json.Marshal(winrmConnectionVars(meta))
		if werr != nil {
			return werr
		}
		args = append(args, "--extra-vars", string(winrmJSON))
	} else {
		args = append(args,
			"-e", "ansible_port="+strconv.Itoa(meta.Port),
			"-e", "ansible_ssh_common_args=-o StrictHostKeyChecking=no -o UserKnownHostsFile="+os.DevNull,
		)
		if user := meta.Credentials.Username; user != "" {
			args = append(args, "-e", "ansible_user="+user)
		}
		switch {
		case meta.Credentials.SSHKeyPath != "":
			key := meta.Credentials.SSHKeyPath
			if !filepath.IsAbs(key) {
				key = filepath.Join(workdir, key)
			}
			args = append(args, "--private-key", key)
		case meta.Credentials.Password != "":
			// ansible's OpenSSH connection needs sshpass for password auth — the
			// var is set either way so the failure names the real gap.
			out.Write("stderr", "password-only credentials: ansible-playbook needs sshpass on the agent host for these\n")
			args = append(args, "-e", "ansible_password="+meta.Credentials.Password)
		default:
			args = append(args, "--private-key", e.env.ProvisionKeyPath)
		}
	}
	if flag := verboseFlag(playbook.Verbose); flag != "" {
		args = append(args, flag)
	}
	args = append(args, "--extra-vars", string(varsJSON), filepath.FromSlash(playbook.Playbook))

	// Environment: the working copy's ansible.cfg (the document's own
	// config_file wins) and the package-vendored collections tree.
	env := append([]string{}, os.Environ()...)
	configFile := playbook.ConfigFile
	if configFile == "" {
		candidate := filepath.Join(workdir, "ansible", "ansible.cfg")
		if _, serr := os.Stat(candidate); serr == nil {
			configFile = candidate
		}
	} else if !filepath.IsAbs(configFile) {
		configFile = filepath.Join(workdir, filepath.FromSlash(configFile))
	}
	if configFile != "" {
		env = append(env, "ANSIBLE_CONFIG="+configFile)
	}
	env = append(env, "ANSIBLE_COLLECTIONS_PATH="+
		filepath.Join(workdir, "provisioners", "ansible_collections")+
		string(os.PathListSeparator)+
		filepath.Join(workdir, "ansible", "ansible_collections"))

	out.Write("stdout", "Running host-side ansible-playbook "+playbook.Playbook+
		" against "+meta.IP+":"+strconv.Itoa(meta.Port)+"\n")
	scanner := newProgressScanner(func(percent int, description string) {
		e.playbookProgress(task, percent, description)
	})
	if rerr := runHostCommand(runCtx, out, workdir, env, func(stream, data string) {
		scanner.Scan(stream, data)
		out.Write(stream, data)
	}, ansibleExe, args...); rerr != nil {
		return fmt.Errorf("ansible-playbook (remote) failed: %w", rerr)
	}

	e.stampIfFinal(task, meta, out)
	e.taskProgress(task, 100, "completed")
	out.Write("stdout", "Remote playbook completed: "+playbook.Playbook+"\n")
	return nil
}

// verboseFlag maps Hosts.rb's verbose knob onto ansible's -v ladder: true →
// -v, "vv" → -vv; anything else is silently no-flag (vagrant's own leniency).
func verboseFlag(verbose any) string {
	switch v := verbose.(type) {
	case bool:
		if v {
			return "-v"
		}
	case string:
		if verbosePattern.MatchString(v) {
			return "-" + v
		}
	}
	return ""
}

// dockerCompose executes machine_docker_compose — ONE compose file (a guest
// path, /vagrant-rooted in real documents), `up -d`. Bare compose entries
// carry no run directive and execute every time the walk reaches them. The
// v2 plugin is tried first, the standalone docker-compose binary second; an
// engine is NEVER installed here — an absent guest engine fails the task
// honestly through the in-guest neither-plugin-nor-binary branch below.
func (e *executors) dockerCompose(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	meta, err := readProvisionMetadata(task)
	if err != nil {
		return err
	}
	if meta.ComposeFile == "" {
		return errors.New("compose_file is required in task metadata")
	}
	timeout := e.env.PlaybookTimeout
	if timeout <= 0 {
		timeout = 21600 * time.Second
	}
	workdir := e.machineWorkdir(task.MachineName)
	quoted := "'" + strings.ReplaceAll(meta.ComposeFile, "'", `'\''`) + "'"

	e.taskProgress(task, 20, "running_compose")
	out.Write("stdout", "docker compose up -d — "+meta.ComposeFile+"\n")
	command := fmt.Sprintf(
		"if sudo docker compose version >/dev/null 2>&1; then sudo docker compose -f %[1]s up -d; "+
			"elif command -v docker-compose >/dev/null 2>&1; then sudo docker-compose -f %[1]s up -d; "+
			"else echo 'neither the docker compose plugin nor docker-compose exists in the guest' >&2; exit 1; fi",
		quoted)
	if rerr := sshrun.Run(ctx, meta.IP, meta.Port, meta.Credentials, command,
		workdir, e.env.ProvisionKeyPath, timeout, out.Write); rerr != nil {
		return fmt.Errorf("docker compose %s failed: %w", meta.ComposeFile, rerr)
	}
	e.stampIfFinal(task, meta, out)
	e.taskProgress(task, 100, "completed")
	out.Write("stdout", "Compose stack up: "+meta.ComposeFile+"\n")
	return nil
}

// errWinRMNeedsAnsible is the honest gate on every winrm mechanism: the
// agent host itself speaks winrm through ansible (+pywinrm) — no pre-flight
// exists at POST /provision (ruled W-Q4), the executor fails honestly.
var errWinRMNeedsAnsible = errors.New("winrm transport needs ansible (+pywinrm) on the agent host — not installed")

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
	ansibleExe, err := exec.LookPath("ansible")
	if err != nil {
		return 0, errWinRMNeedsAnsible
	}
	varsJSON, err := json.Marshal(winrmConnectionVars(meta))
	if err != nil {
		return 0, err
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
		perr := runHostCommand(attemptCtx, out, workdir, nil, nil, ansibleExe,
			"all", "-i", meta.IP+",", "-m", "win_ping", "--extra-vars", string(varsJSON))
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
	ansibleExe, err := exec.LookPath("ansible")
	if err != nil {
		return errWinRMNeedsAnsible
	}
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
		return runHostCommand(runCtx, out, workdir, nil, nil, ansibleExe,
			"all", "-i", meta.IP+",", "-m", module, "-a", moduleArgs,
			"--extra-vars", string(varsJSON))
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
	copyArgs, err := json.Marshal(map[string]string{"src": local, "dest": remote})
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

// runHostCommand streams one agent-host command into the task output (the
// import executor's streaming shape, machines-side). env nil inherits the
// agent's environment; tap, when set, sees every line instead of out (the
// progress scanner wraps out itself). The context is the kill switch.
func runHostCommand(ctx context.Context, out *tasks.OutputWriter, dir string, env []string,
	tap func(stream, data string), exe string, args ...string,
) error {
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.SysProcAttr = procattr.NoConsole()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if serr := cmd.Start(); serr != nil {
		return serr
	}

	forward := func(r io.Reader, stream string) {
		scanner := bufio.NewScanner(r)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text() + "\n"
			if tap != nil {
				tap(stream, line)
			} else {
				out.Write(stream, line)
			}
		}
	}
	stdoutDone := make(chan struct{})
	go func() {
		defer close(stdoutDone)
		forward(stdout, "stdout")
	}()
	forward(stderr, "stderr")
	<-stdoutDone

	err = cmd.Wait()
	if ctx.Err() != nil {
		return fmt.Errorf("host command cancelled or timed out: %w", ctx.Err())
	}
	return err
}
