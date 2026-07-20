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

	"github.com/Makr91/hyperweaver-agent/internal/ansiblehost"
	"github.com/Makr91/hyperweaver-agent/internal/procattr"
	"github.com/Makr91/hyperweaver-agent/internal/sshrun"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// verbosePattern is ansible's -v ladder (v, vv, vvv, vvvv).
var verbosePattern = regexp.MustCompile(`^v{1,4}$`)

// runRemotePlaybook executes machine_provision_remote — ONE remote playbook:
// ansible-playbook on the AGENT HOST, dialing the guest over the pipeline's
// own transport (the NAT ssh port-forward or the control IP). Gated on a host
// control node (ansiblehost resolves it: native ansible, or the default WSL
// distribution's on Windows hosts — the matrix's shipped WSL rows); no
// control node anywhere is an honest failure, never a silent skip. The
// provisioned-state stamp rides Final exactly like the local executor.
func (e *executors) runRemotePlaybook(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	meta, err := readProvisionMetadata(task)
	if err != nil {
		return err
	}
	if meta.Playbook == nil || meta.Playbook.Playbook == "" {
		return errors.New("playbook is required in task metadata")
	}
	playbook := meta.Playbook

	runner, rerr := ansiblehost.Resolve(ctx, "ansible-playbook")
	if rerr != nil {
		return errors.New("remote playbooks run ansible-playbook ON THE AGENT HOST and this host has none — install ansible (Windows hosts: ansible inside WSL's default distribution), or move the playbook to the local list (in-guest ansible)")
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

	ruleName, guestPort := wslRuleSSH, 22
	if meta.Communicator == "winrm" {
		ruleName, guestPort = wslRuleWinRM, wslWinRMGuestPort(meta)
	}
	dialIP, cleanupTransport, terr := e.wslReachableTransport(ctx, runner,
		task.MachineName, meta.IP, meta.Port, guestPort, ruleName, out)
	if terr != nil {
		return terr
	}
	defer cleanupTransport()

	// remote_collections: true fetches from the galaxy ON THE HOST into the
	// working copy (vagrant's galaxy_role_file/galaxy_roles_path pair);
	// false means the package vendors them — ANSIBLE_COLLECTIONS_PATH below
	// resolves the shipped tree.
	if playbook.RemoteCollections {
		e.taskProgress(task, 15, "installing_collections")
		if runner.Has("ansible-galaxy") {
			requirements := filepath.Join(workdir, "ansible", "requirements.yml")
			if _, serr := os.Stat(requirements); serr == nil {
				inv, gerr := runner.Invocation("ansible-galaxy", nil, "",
					"collection", "install", "-r", runner.Path(requirements),
					"-p", runner.Path(filepath.Join(workdir, "ansible", "ansible_collections")), "--force")
				if gerr != nil {
					return fmt.Errorf("ansible-galaxy install: %w", gerr)
				}
				if herr := runHostCommand(runCtx, out, workdir, inv.Env, nil, inv.Exe, inv.Args...); herr != nil {
					return fmt.Errorf("ansible-galaxy install: %w", herr)
				}
			} else {
				out.Write("stderr", "remote_collections is true but the working copy has no ansible/requirements.yml — skipping galaxy\n")
			}
			for _, collection := range playbook.Collections {
				inv, gerr := runner.Invocation("ansible-galaxy", nil, "",
					"collection", "install", collection, "--force")
				if gerr != nil {
					return fmt.Errorf("install collection %s: %w", collection, gerr)
				}
				if herr := runHostCommand(runCtx, out, workdir, inv.Env, nil, inv.Exe, inv.Args...); herr != nil {
					return fmt.Errorf("install collection %s: %w", collection, herr)
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

	args := []string{"-i", dialIP + ","}
	keyPath := ""
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
			"-e", "ansible_ssh_common_args=-o StrictHostKeyChecking=no -o UserKnownHostsFile="+runner.DevNull(),
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
			keyPath = key
		case meta.Credentials.Password != "":
			// ansible's OpenSSH connection needs sshpass for password auth — the
			// var is set either way so the failure names the real gap.
			out.Write("stderr", "password-only credentials: ansible-playbook needs sshpass on the agent host for these\n")
			args = append(args, "-e", "ansible_password="+meta.Credentials.Password)
		default:
			keyPath = e.env.ProvisionKeyPath
		}
	}
	if flag := verboseFlag(playbook.Verbose); flag != "" {
		args = append(args, flag)
	}
	varsArg := string(varsJSON)
	if runner.WSL() {
		varsFile := filepath.Join(workdir, "hw-extravars-"+task.ID+".json")
		if werr := os.WriteFile(varsFile, varsJSON, 0o600); werr != nil {
			return werr
		}
		defer func() {
			if cerr := os.Remove(varsFile); cerr != nil {
				out.Write("stderr", "cleanup of "+varsFile+" failed: "+cerr.Error()+"\n")
			}
		}()
		varsArg = "@" + runner.Path(varsFile)
	}
	args = append(args, "--extra-vars", varsArg, runner.RelPath(playbook.Playbook))

	// Environment: the working copy's ansible.cfg (the document's own
	// config_file wins) and the package-vendored collections tree.
	envExtra := map[string]string{}
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
		envExtra["ANSIBLE_CONFIG"] = runner.Path(configFile)
	}
	envExtra["ANSIBLE_COLLECTIONS_PATH"] = runner.PathList(
		filepath.Join(workdir, "provisioners", "ansible_collections"),
		filepath.Join(workdir, "ansible", "ansible_collections"))

	out.Write("stdout", "Running host-side ansible-playbook "+playbook.Playbook+
		" against "+dialIP+":"+strconv.Itoa(meta.Port)+"\n")
	inv, ierr := runner.Invocation("ansible-playbook", envExtra, keyPath, args...)
	if ierr != nil {
		return ierr
	}
	scanner := newProgressScanner(func(percent int, description string) {
		e.playbookProgress(task, percent, description)
	})
	if herr := runHostCommand(runCtx, out, workdir, inv.Env, func(stream, data string) {
		scanner.Scan(stream, data)
		out.Write(stream, data)
	}, inv.Exe, inv.Args...); herr != nil {
		return fmt.Errorf("ansible-playbook (remote) failed: %w", herr)
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
