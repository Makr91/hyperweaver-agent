// Package hostpower implements the host power-management operations
// (/system/host/*, the `host-power` capability token — the Node agent's
// System Host Management group made cross-platform): shutdown, restart,
// poweroff, and halt of the machine the agent runs on, each executed as a
// queued task through the platform's shutdown command. Remote power control
// is half the point of a headless datacenter host; the surface is
// config-gated (host_power.enabled) for machines where it is not wanted.
// Deliberately absent — illumos/init semantics with no cross-platform
// analog: runlevel changes, single-user/multi-user transitions, fast reboot,
// and the reboot-required flag tracking.
package hostpower

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/procattr"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// Host power operations (task queue vocabulary — the Node agent's
// system_host_* operation names).
const (
	OpShutdown = "system_host_shutdown"
	OpRestart  = "system_host_restart"
	OpPoweroff = "system_host_poweroff"
	OpHalt     = "system_host_halt"
)

// Metadata is the power task's metadata document.
type Metadata struct {
	// GracePeriod is seconds before the action fires (0 = immediate).
	GracePeriod int `json:"grace_period"`
	// Message is the warning broadcast to logged-in users where the
	// platform supports one.
	Message string `json:"message,omitempty"`
}

// MetadataJSON serializes task metadata for the queue.
func MetadataJSON(m Metadata) (*string, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	s := string(raw)
	return &s, nil
}

// RegisterExecutors wires the host power operations into the task queue.
// shutdownPath is the validated platform shutdown command from LookupCommand.
func RegisterExecutors(queue *tasks.Queue, shutdownPath func(ctx context.Context) (string, error)) {
	e := &executors{lookup: shutdownPath}
	queue.Register(OpShutdown, tasks.Executor{Run: e.run(OpShutdown)})
	queue.Register(OpRestart, tasks.Executor{Run: e.run(OpRestart)})
	queue.Register(OpPoweroff, tasks.Executor{Run: e.run(OpPoweroff)})
	queue.Register(OpHalt, tasks.Executor{Run: e.run(OpHalt)})
}

type executors struct {
	lookup func(ctx context.Context) (string, error)
}

func (e *executors) run(operation string) func(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	return func(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
		var meta Metadata
		if len(task.Metadata) > 0 {
			if err := json.Unmarshal(task.Metadata, &meta); err != nil {
				return fmt.Errorf("parse power task metadata: %w", err)
			}
		}

		exe, err := e.lookup(ctx)
		if err != nil {
			return err
		}
		args := commandArgs(operation, meta)

		out.Write("stdout", "Executing host power operation "+operation+": "+
			exe+" "+strings.Join(args, " ")+"\n")
		cmd := exec.CommandContext(ctx, exe, args...)
		cmd.SysProcAttr = procattr.NoConsole()
		combined, cerr := cmd.CombinedOutput()
		if len(combined) > 0 {
			out.Write("stdout", string(combined))
		}
		if cerr != nil {
			out.Write("stderr", "Host power command failed: "+cerr.Error()+"\n")
			return fmt.Errorf("host power %s: %w", operation, cerr)
		}
		out.Write("stdout", "Host power command accepted by the operating system\n")
		return nil
	}
}

// LookupCommand finds the platform shutdown binary, validated through
// safepath like every other spawned executable.
func LookupCommand(_ context.Context) (string, error) {
	path, err := exec.LookPath(shutdownBinary)
	if err != nil {
		return "", errors.New("the platform shutdown command is not available: " + err.Error())
	}
	return safepath.ValidateExecutable(path)
}
