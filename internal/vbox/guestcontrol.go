package vbox

// Guest Additions command execution (`guestcontrol run`) — the credentialed
// exec channel for guests running Guest Additions (the QGA channel's
// Additions-flavored sibling).

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strconv"

	"github.com/Makr91/hyperweaver-agent/internal/procattr"
)

// GuestRunResult is one guestcontrol run's outcome.
type GuestRunResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// GuestControlRun executes a program in the guest and waits for it,
// capturing both streams. timeoutMS bounds the guest process (VBoxManage's
// own --timeout); the exit code is VBoxManage's — guest exit codes ride
// through for plain runs.
func GuestControlRun(ctx context.Context, vboxManage, name, username, password, exePath string,
	args []string, timeoutMS int,
) (*GuestRunResult, error) {
	cmdArgs := []string{
		"guestcontrol", name, "run",
		"--exe", exePath,
		"--username", username,
		"--password", password,
		"--wait-stdout", "--wait-stderr",
	}
	if timeoutMS > 0 {
		cmdArgs = append(cmdArgs, "--timeout", strconv.Itoa(timeoutMS))
	}
	if len(args) > 0 {
		cmdArgs = append(cmdArgs, "--")
		cmdArgs = append(cmdArgs, args...)
	}

	cmd := exec.CommandContext(ctx, vboxManage, cmdArgs...)
	cmd.SysProcAttr = procattr.NoConsole()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result := &GuestRunResult{Stdout: stdout.String(), Stderr: stderr.String()}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
			return result, nil
		}
		return nil, err
	}
	return result, nil
}
