// Package sshrun is zoneweaver's lib/SSHManager.js ported to Go (Mark's
// ruling: the Go agent recreates zoneweaver's mechanisms exactly): SSH
// connect/exec/wait against provisioned machines, rsync file sync, and the
// agent's own provisioning keypair. Key-based auth is preferred; relative key
// paths resolve against the machine's provisioning base path; key resolution
// walks the tiered ladder (Mark's three-tier ruling, sync 2026-07-17): the
// working copy's own key when its file EXISTS, the packaged bootstrap key
// under driver/ssh_keys or core/ssh_keys, the agent-generated provisioning
// key — and password auth ONLY when no key file exists anywhere
// (zoneweaver's exact ladder, converged 2026-07-17).
package sshrun

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
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

// Key-resolution tiers (Mark's three-tier ruling, sync 2026-07-17) — carried
// alongside the effective path so callers can narrate which rung answered.
const (
	keyTierWorkingCopy = "tier 1 (working-copy key)"
	keyTierPassword    = "password"
	keyTierPackaged    = "tier 2 (packaged bootstrap key)"
	keyTierAgent       = "agent provisioning key"
)

// packagedBootstrapKeys names the bootstrap key candidates INSIDE the working
// copy — the new driver era first, the legacy mount second (Hosts.rb's
// "./core/ssh_keys/id_rsa" default). Mark's three-tier ruling, sync
// 2026-07-17: tier 2 never fetches from the guest.
func packagedBootstrapKeys(basePath string) []string {
	if basePath == "" {
		return nil
	}
	return []string{
		filepath.Join(basePath, "driver", "ssh_keys", "id_rsa"),
		filepath.Join(basePath, "core", "ssh_keys", "id_rsa"),
	}
}

// keyFileExists reports a readable regular file at path.
func keyFileExists(path string) bool {
	info, err := os.Stat(filepath.Clean(path))
	return err == nil && info.Mode().IsRegular()
}

// effectiveKeyPath walks Mark's three-tier ruling (sync 2026-07-17) and
// answers the EFFECTIVE key path plus which tier hit — the ONE resolver both
// the in-process auth (authMethods) and the binary transports
// (credentialKeyPath) consume. The walk is zoneweaver's shipped
// resolveConnectKeyPath exactly (source-verified, converged 2026-07-17):
//
//	tier 1:   the working copy's vagrant_user_private_key_path — used when
//	          the file EXISTS (the machine was rotated, or the user supplied
//	          it).
//	tier 2:   the packaged bootstrap key inside the working copy, then the
//	          agent's own provisioning key — first EXISTING file wins; never
//	          a guest fetch.
//	password: ONLY when no key file exists anywhere — a key file on disk
//	          always beats a document password (zoneweaver's exact rule).
//	last:     no key anywhere, no password — the agent key path answers
//	          UNCHECKED so the downstream load errors honestly.
func effectiveKeyPath(credentials Credentials, basePath, defaultKeyPath string) (path, tier string) {
	if credentials.SSHKeyPath != "" {
		named := resolveKeyPath(credentials.SSHKeyPath, basePath)
		if keyFileExists(named) {
			return named, keyTierWorkingCopy
		}
	}
	for _, candidate := range packagedBootstrapKeys(basePath) {
		if keyFileExists(candidate) {
			plog().Debug("SSH key resolved to the packaged bootstrap key",
				"path", candidate, "named", credentials.SSHKeyPath)
			return candidate, keyTierPackaged
		}
	}
	if keyFileExists(defaultKeyPath) {
		return defaultKeyPath, keyTierAgent
	}
	if credentials.Password != "" {
		return "", keyTierPassword
	}
	return defaultKeyPath, keyTierAgent
}

// authMethods builds the connection auth over the tiered resolver (Mark's
// three-tier ruling, sync 2026-07-17): working-copy key when its file exists
// → packaged bootstrap key → the agent's provisioning key → password ONLY
// when no key file exists anywhere. ONE method per attempt — never
// key+password on one connection (zoneweaver's exact exclusivity).
func authMethods(credentials Credentials, basePath, defaultKeyPath string) ([]ssh.AuthMethod, error) {
	path, tier := effectiveKeyPath(credentials, basePath, defaultKeyPath)
	if tier == keyTierPassword {
		return []ssh.AuthMethod{ssh.Password(credentials.Password)}, nil
	}
	if path == "" {
		return nil, errors.New("no credentials, no packaged bootstrap key, and no default provisioning key")
	}
	key, err := loadKey(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", tier, err)
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
