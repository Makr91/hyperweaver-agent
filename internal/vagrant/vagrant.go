// Package vagrant shells out to the vagrant CLI — the machine-lifecycle
// engine for vagrant-backed machines (SHI's model: the unchanged provisioner
// bundle's Vagrantfile/Hosts.rb does the real work; this agent just drives
// the binary and streams its output). Callers supply the vagrant path from
// the prerequisite detector, which has already validated it through safepath.
package vagrant

import (
	"bufio"
	"context"
	"fmt"
	"io"
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

// StreamFunc receives live command output. stream is "stdout" or "stderr";
// data is one line including its trailing newline.
type StreamFunc func(stream, data string)

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

// Up runs `vagrant up [--provision]` in dir, streaming output. The context
// is the kill switch: cancelling it terminates the vagrant process (task
// cancellation, D-F).
func Up(ctx context.Context, vagrantExe, dir string, provision bool, stream StreamFunc) error {
	args := []string{"up"}
	if provision {
		args = append(args, "--provision")
	}
	return run(ctx, vagrantExe, dir, args, stream)
}

// Halt runs `vagrant halt [-f]` in dir.
func Halt(ctx context.Context, vagrantExe, dir string, force bool, stream StreamFunc) error {
	args := []string{"halt"}
	if force {
		args = append(args, "-f")
	}
	return run(ctx, vagrantExe, dir, args, stream)
}

// Suspend runs `vagrant suspend` in dir.
func Suspend(ctx context.Context, vagrantExe, dir string, stream StreamFunc) error {
	return run(ctx, vagrantExe, dir, []string{"suspend"}, stream)
}

// Destroy runs `vagrant destroy -f` in dir.
func Destroy(ctx context.Context, vagrantExe, dir string, stream StreamFunc) error {
	return run(ctx, vagrantExe, dir, []string{"destroy", "-f"}, stream)
}

// Provision runs `vagrant provision` in dir.
func Provision(ctx context.Context, vagrantExe, dir string, stream StreamFunc) error {
	return run(ctx, vagrantExe, dir, []string{"provision"}, stream)
}

// Rsync runs `vagrant rsync` in dir (the literal subcommand — SHI's
// rsync-binary-as-argument bug is deliberately not replicated).
func Rsync(ctx context.Context, vagrantExe, dir string, stream StreamFunc) error {
	return run(ctx, vagrantExe, dir, []string{"rsync"}, stream)
}

// run executes vagrant in dir, streaming stdout and stderr line by line.
func run(ctx context.Context, vagrantExe, dir string, args []string, stream StreamFunc) error {
	cmd := exec.CommandContext(ctx, vagrantExe, args...)
	cmd.Dir = dir
	cmd.SysProcAttr = procattr.NoConsole()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("vagrant %s: %w", args[0], err)
	}

	stdoutDone := make(chan struct{})
	go func() {
		defer close(stdoutDone)
		scanLines(stdout, "stdout", stream)
	}()
	scanLines(stderr, "stderr", stream)
	<-stdoutDone

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("vagrant %s: %w", args[0], err)
	}
	return nil
}

// scanLines forwards a pipe to the stream callback line by line. Lines far
// beyond bufio's default are possible in ansible output — size the buffer up.
func scanLines(r io.Reader, stream string, cb StreamFunc) {
	if cb == nil {
		cb = func(_, _ string) {}
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		cb(stream, scanner.Text()+"\n")
	}
}
