//go:build !windows

package hostshell

import (
	"context"
	"os"
	"os/exec"

	"github.com/creack/pty"
)

// knownShells is the closed set of shells the host terminal will launch.
// $SHELL selects among them but the launched value is always the MATCHED
// COPY from this list, never the environment value itself (the redirectHost
// precedent: tainted input picks, constants run).
var knownShells = []string{
	"/bin/bash", "/usr/bin/bash", "/usr/local/bin/bash", "/opt/homebrew/bin/bash",
	"/bin/zsh", "/usr/bin/zsh", "/usr/local/bin/zsh", "/opt/homebrew/bin/zsh",
	"/usr/bin/fish", "/usr/local/bin/fish", "/opt/homebrew/bin/fish",
	"/bin/ksh", "/bin/tcsh", "/bin/dash", "/bin/sh",
}

// shellProgram resolves the shell to launch: the user's $SHELL when it names
// a known shell, else bash, else sh.
func shellProgram() string {
	env := os.Getenv("SHELL")
	for _, candidate := range knownShells {
		if env == candidate {
			return candidate
		}
	}
	if _, err := os.Stat("/bin/bash"); err == nil {
		return "/bin/bash"
	}
	return "/bin/sh"
}

// ptyDim converts a terminal dimension for pty.Winsize — bounds checked here
// so the uint16 conversion is provably safe.
func ptyDim(v, fallback int) uint16 {
	if v <= 0 {
		v = fallback
	}
	if v < 1 {
		v = 1
	}
	if v > 500 {
		v = 500
	}
	return uint16(v)
}

// startPlatform opens the user's login shell under a real PTY (creack/pty —
// the Docker/Kubernetes-proven implementation).
func startPlatform(cols, rows int) (terminal, string, error) {
	program := shellProgram()
	// Background, not request-scoped: the shell is a session that lives until
	// Close (which Kills it), never bounded by the WebSocket handler's ctx.
	cmd := exec.CommandContext(context.Background(), program, "-l")
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{
		Cols: ptyDim(cols, 80),
		Rows: ptyDim(rows, 24),
	})
	if err != nil {
		return nil, "", err
	}
	return &unixTerminal{cmd: cmd, ptmx: ptmx}, program, nil
}

// unixTerminal is the creack/pty half: the ptmx file is both the output
// stream and the input sink.
type unixTerminal struct {
	cmd  *exec.Cmd
	ptmx *os.File
}

func (t *unixTerminal) Read(p []byte) (int, error)  { return t.ptmx.Read(p) }
func (t *unixTerminal) Write(p []byte) (int, error) { return t.ptmx.Write(p) }

func (t *unixTerminal) Resize(cols, rows int) error {
	return pty.Setsize(t.ptmx, &pty.Winsize{
		Cols: ptyDim(cols, 80),
		Rows: ptyDim(rows, 24),
	})
}

func (t *unixTerminal) Wait() error {
	return t.cmd.Wait()
}

func (t *unixTerminal) Close() {
	_ = t.ptmx.Close()
	if t.cmd.Process != nil {
		_ = t.cmd.Process.Kill()
	}
}
