// Package hostshell opens interactive terminals on the AGENT HOST itself —
// the host-terminal console surface (zoneweaver's /term family on this
// agent). The shell runs as the agent's own user over the platform's native
// PTY: a real pseudo-terminal via creack/pty on Unix, a ConPTY pseudo
// console on Windows (hand-rolled over golang.org/x/sys/windows — Mark's
// dependency ruling 2026-07-07: creack/pty has no Windows support, and
// owning the ~150 ConPTY lines beats wrapping an unproven abstraction).
package hostshell

import "sync"

// terminal is the platform PTY: read shell output, write user input, resize,
// wait for exit, tear down. Each platform file provides startPlatform.
type terminal interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Resize(cols, rows int) error
	Wait() error
	Close()
}

// Shell is one interactive host terminal session.
type Shell struct {
	term    terminal
	program string

	mu     sync.Mutex
	closed bool
}

// Start launches the host's shell under a PTY of the given size. onData
// receives terminal output until the shell exits or Close runs.
func Start(cols, rows int, onData func(string)) (*Shell, error) {
	term, program, err := startPlatform(clampDim(cols, 80), clampDim(rows, 24))
	if err != nil {
		return nil, err
	}
	shell := &Shell{term: term, program: program}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, rerr := term.Read(buf)
			if n > 0 {
				onData(string(buf[:n]))
			}
			if rerr != nil {
				return
			}
		}
	}()
	return shell, nil
}

// clampDim bounds a terminal dimension into the PTY-representable range —
// the explicit bounds also make the platform files' uint16/int16 conversions
// provably safe.
func clampDim(v, fallback int) int {
	if v <= 0 {
		return fallback
	}
	if v > 500 {
		return 500
	}
	return v
}

// Program names the shell executable this session runs.
func (s *Shell) Program() string {
	return s.program
}

// Write sends terminal input to the shell.
func (s *Shell) Write(data string) error {
	_, err := s.term.Write([]byte(data))
	return err
}

// Resize adjusts the PTY dimensions.
func (s *Shell) Resize(cols, rows int) error {
	if cols <= 0 || rows <= 0 {
		return nil
	}
	return s.term.Resize(clampDim(cols, 80), clampDim(rows, 24))
}

// Wait blocks until the shell process exits.
func (s *Shell) Wait() error {
	return s.term.Wait()
}

// Close tears the shell down (idempotent).
func (s *Shell) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	s.term.Close()
}
