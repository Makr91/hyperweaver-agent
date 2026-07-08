package sshrun

import (
	"context"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Interactive shell support — the SSH terminal surface's transport (the
// base's ssh2 Client.shell over the same credential rules Run uses).

// Shell is one interactive SSH shell session.
type Shell struct {
	client      *ssh.Client
	closeClient func()
	session     *ssh.Session
	stdin       io.WriteCloser

	mu     sync.Mutex
	closed bool
}

// shellWriter funnels remote output to the callback (stdout and stderr both
// land on the terminal — the base pipes both to the WebSocket).
type shellWriter struct {
	cb func(string)
}

func (w shellWriter) Write(p []byte) (int, error) {
	w.cb(string(p))
	return len(p), nil
}

// StartShell connects and opens an interactive shell with a PTY
// (xterm-256color, the base's term). onData receives remote output; Wait
// blocks until the remote side ends the shell. The context bounds the
// CONNECT; the shell itself lives until Close or remote exit.
func StartShell(ctx context.Context, ip string, port int, credentials Credentials,
	basePath, defaultKeyPath string, cols, rows int, onData func(string),
) (*Shell, error) {
	client, closeClient, err := connectSSH(ctx, ip, port, credentials, basePath, defaultKeyPath)
	if err != nil {
		return nil, err
	}
	fail := func(ferr error) (*Shell, error) {
		closeClient()
		return nil, ferr
	}

	session, err := client.NewSession()
	if err != nil {
		return fail(fmt.Errorf("ssh session: %w", err))
	}
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}
	if perr := session.RequestPty("xterm-256color", rows, cols, ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}); perr != nil {
		_ = session.Close()
		return fail(fmt.Errorf("request pty: %w", perr))
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		return fail(fmt.Errorf("stdin pipe: %w", err))
	}
	session.Stdout = shellWriter{cb: onData}
	session.Stderr = shellWriter{cb: onData}
	if serr := session.Shell(); serr != nil {
		_ = session.Close()
		return fail(fmt.Errorf("open shell: %w", serr))
	}

	return &Shell{
		client:      client,
		closeClient: closeClient,
		session:     session,
		stdin:       stdin,
	}, nil
}

// Write sends terminal input to the remote shell.
func (s *Shell) Write(data string) error {
	_, err := io.WriteString(s.stdin, data)
	return err
}

// Resize adjusts the remote PTY (the base's stream.setWindow).
func (s *Shell) Resize(cols, rows int) error {
	if cols <= 0 || rows <= 0 {
		return nil
	}
	return s.session.WindowChange(rows, cols)
}

// Wait blocks until the remote shell exits.
func (s *Shell) Wait() error {
	return s.session.Wait()
}

// Close tears the shell and its transport down (idempotent).
func (s *Shell) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()

	_ = s.stdin.Close()
	_ = s.session.Close()
	s.closeClient()
}
