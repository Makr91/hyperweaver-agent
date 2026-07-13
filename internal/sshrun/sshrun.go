// Package sshrun is zoneweaver's lib/SSHManager.js ported to Go (Mark's
// ruling: the Go agent recreates zoneweaver's mechanisms exactly): SSH
// connect/exec/wait against provisioned machines, rsync file sync, and the
// agent's own provisioning keypair. Key-based auth is preferred; relative key
// paths resolve against the machine's provisioning base path; the fallback is
// the agent-generated provisioning key.
package sshrun

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Makr91/hyperweaver-agent/internal/logging"
)

// plog is this package's category logger (logging.categories.provision).
func plog() *slog.Logger {
	return logging.Category("provision")
}

// Credentials mirrors the task-metadata credential shape ({username,
// password, ssh_key_path}).
type Credentials struct {
	Username   string `json:"username"`
	Password   string `json:"password,omitempty"`
	SSHKeyPath string `json:"ssh_key_path,omitempty"`
}

// StreamFunc receives live remote output (stream = "stdout" | "stderr").
type StreamFunc func(stream, data string)

// resolveKeyPath resolves a possibly-relative key path against the
// provisioning base path (SSHManager's rule).
func resolveKeyPath(keyPath, basePath string) string {
	if keyPath == "" || filepath.IsAbs(keyPath) || basePath == "" {
		return keyPath
	}
	return filepath.Join(basePath, keyPath)
}

// authMethods builds the connection auth in SSHManager's preference order:
// explicit key → password → the default provisioning key.
func authMethods(credentials Credentials, basePath, defaultKeyPath string) ([]ssh.AuthMethod, error) {
	if credentials.SSHKeyPath != "" {
		key, err := loadKey(resolveKeyPath(credentials.SSHKeyPath, basePath))
		if err != nil {
			return nil, err
		}
		return []ssh.AuthMethod{ssh.PublicKeys(key)}, nil
	}
	if credentials.Password != "" {
		return []ssh.AuthMethod{ssh.Password(credentials.Password)}, nil
	}
	key, err := loadKey(defaultKeyPath)
	if err != nil {
		return nil, fmt.Errorf("no credentials and no default provisioning key: %w", err)
	}
	return []ssh.AuthMethod{ssh.PublicKeys(key)}, nil
}

func loadKey(path string) (ssh.Signer, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read SSH key %s: %w", path, err)
	}
	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse SSH key %s: %w", path, err)
	}
	return signer, nil
}

// acceptAndLogHostKey accepts any host key and records its fingerprint —
// provisioned machines are freshly built with no prior trust anchor
// (StrictHostKeyChecking=no in the base); the fingerprint lands in the log
// for the audit trail.
func acceptAndLogHostKey(hostname string, _ net.Addr, key ssh.PublicKey) error {
	digest := sha256.Sum256(key.Marshal())
	plog().Debug("accepting machine host key",
		"host", hostname, "fingerprint", "SHA256:"+base64.StdEncoding.EncodeToString(digest[:]))
	return nil
}

// clientConfig builds the ssh client configuration.
func clientConfig(credentials Credentials, basePath, defaultKeyPath string) (*ssh.ClientConfig, error) {
	username := credentials.Username
	if username == "" {
		username = "root"
	}
	auth, err := authMethods(credentials, basePath, defaultKeyPath)
	if err != nil {
		return nil, err
	}
	return &ssh.ClientConfig{
		User:            username,
		Auth:            auth,
		HostKeyCallback: acceptAndLogHostKey,
		Timeout:         15 * time.Second,
	}, nil
}

// connectSSH dials and handshakes an SSH client, wiring the context-cancel
// watchdog that closes the raw TCP connection. The context kills the
// TRANSPORT, not just the session: a guest whose kernel lives but whose sshd
// is wedged (ICMP answers, no SSH banner) stalls the handshake — which runs
// BEFORE any session exists — and a black-holed connection never delivers a
// session-close message either. Closing the TCP connection unblocks every
// phase: handshake, session open, and the running operation (runtime-proven
// 2026-07-07 — a frozen guest wedged machine_sync past its timeout). The
// returned closer is idempotent and releases the watchdog with the client.
// disarm releases ONLY the watchdog: callers whose connection must OUTLIVE
// the connect context (the interactive shell — its 20s connect bound was
// killing the live terminal the moment it was cancelled, runtime-found
// 2026-07-09) disarm after a successful connect and own the lifetime through
// the closer.
func connectSSH(ctx context.Context, ip string, port int, credentials Credentials,
	basePath, defaultKeyPath string,
) (client *ssh.Client, closer, disarm func(), err error) {
	config, err := clientConfig(credentials, basePath, defaultKeyPath)
	if err != nil {
		return nil, nil, nil, err
	}

	dialer := net.Dialer{Timeout: config.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("dial %s:%d: %w", ip, port, err)
	}

	watchdogDone := make(chan struct{})
	var watchdogOnce sync.Once
	disarm = func() {
		watchdogOnce.Do(func() { close(watchdogDone) })
	}
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-watchdogDone:
		}
	}()

	sshConn, channels, requests, err := ssh.NewClientConn(conn, ip, config)
	if err != nil {
		disarm()
		_ = conn.Close()
		if ctx.Err() != nil {
			return nil, nil, nil, fmt.Errorf("ssh handshake %s: %w", ip, ctx.Err())
		}
		return nil, nil, nil, fmt.Errorf("ssh handshake %s: %w", ip, err)
	}
	client = ssh.NewClient(sshConn, channels, requests)

	var once sync.Once
	closer = func() {
		once.Do(func() {
			_ = client.Close()
			disarm()
		})
	}
	return client, closer, disarm, nil
}

// Run executes one command on the machine, streaming its output. The context
// bounds the whole call (task cancellation kills the session).
func Run(ctx context.Context, ip string, port int, credentials Credentials,
	command, basePath, defaultKeyPath string, timeout time.Duration, stream StreamFunc,
) error {
	runCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	client, closeClient, _, err := connectSSH(runCtx, ip, port, credentials, basePath, defaultKeyPath)
	if err != nil {
		return err
	}
	defer closeClient()

	session, err := client.NewSession()
	if err != nil {
		if runCtx.Err() != nil {
			return fmt.Errorf("ssh session: %w", runCtx.Err())
		}
		return fmt.Errorf("ssh session: %w", err)
	}
	defer func() {
		_ = session.Close()
	}()

	if stream != nil {
		session.Stdout = streamWriter{stream: "stdout", cb: stream}
		session.Stderr = streamWriter{stream: "stderr", cb: stream}
	}

	err = session.Run(command)
	if runCtx.Err() != nil {
		return fmt.Errorf("remote command cancelled or timed out: %w", runCtx.Err())
	}
	return err
}

// streamWriter adapts a StreamFunc to io.Writer.
type streamWriter struct {
	stream string
	cb     StreamFunc
}

func (w streamWriter) Write(p []byte) (int, error) {
	w.cb(w.stream, string(p))
	return len(p), nil
}

// WaitForSSH polls until the machine answers `echo ready` over SSH
// (waitForSSH verbatim: bounded total timeout, fixed poll interval, elapsed
// time reported).
func WaitForSSH(ctx context.Context, ip string, port int, credentials Credentials,
	basePath, defaultKeyPath string, timeout, interval time.Duration, stream StreamFunc,
) (time.Duration, error) {
	start := time.Now()
	deadline := start.Add(timeout)
	for {
		if ctx.Err() != nil {
			return time.Since(start), ctx.Err()
		}
		if time.Now().After(deadline) {
			return time.Since(start), fmt.Errorf("SSH not available after %ds", int(timeout.Seconds()))
		}
		err := Run(ctx, ip, port, credentials, "echo ready", basePath, defaultKeyPath,
			10*time.Second, nil)
		if err == nil {
			elapsed := time.Since(start)
			if stream != nil {
				stream("stdout", fmt.Sprintf("SSH available on %s:%d after %ds\n",
					ip, port, int(elapsed.Seconds())))
			}
			return elapsed, nil
		}
		plog().Debug("SSH poll failed", "ip", ip, "error", err)
		select {
		case <-ctx.Done():
			return time.Since(start), ctx.Err()
		case <-time.After(interval):
		}
	}
}
