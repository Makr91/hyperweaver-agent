package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/config"
	"github.com/Makr91/hyperweaver-agent/internal/localclient"
	"github.com/Makr91/hyperweaver-agent/internal/protocol"
)

func runHeadless(serverErr chan error, updateExit chan struct{}, shutdown func()) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case srvErr := <-serverErr:
		if srvErr != nil {
			slog.Error("http server failed", "error", srvErr)
			shutdown()
			return srvErr
		}
	case <-updateExit:
		slog.Info("update installer launched — exiting for it to take over")
	case <-ctx.Done():
		slog.Info("signal received, shutting down")
	}
	shutdown()
	return nil
}

// selfClient builds the loopback client for talking to this agent's own
// origin — over TLS with certificate verification when ssl.enabled (it
// trusts the agent's own certificate file; Mark's ruling 2026-07-05: SSL
// enabled means ALL traffic rides TLS, internal probes included). Built at
// each call site, not at boot: the first TLS boot generates the certificate
// during Listen, after startup code has already run.
func selfClient(cfg *config.Config) *http.Client {
	return localclient.New(cfg.SSLCACertPath(), cfg.SSLCertPath())
}

// handleBindConflict resolves a failed port bind on a desktop launch: when
// the port holder is another instance of this agent, hand it an open action
// (authenticated by the shared per-user handoff secret) and exit cleanly —
// launching the app twice reuses the running instance instead of showing a
// dead tray icon. Anything else holding the port is a real error.
func handleBindConflict(cfg *config.Config, selfClient *http.Client, bindErr error) error {
	if !probeRunningAgent(selfClient, cfg.BaseURL()) {
		slog.Error("http server bind failed", "error", bindErr)
		return bindErr
	}
	slog.Info("another instance is already running; asking it to open the UI")

	secret, serr := protocol.ReadSecret(cfg.ProtocolSecretPath())
	if serr != nil {
		return fmt.Errorf("agent already running at %s, and its handoff secret is unreadable: %w",
			cfg.BaseURL(), serr)
	}
	if ferr := protocol.Forward(context.Background(), selfClient, cfg.BaseURL(), protocol.ActionOpen, secret); ferr != nil {
		return fmt.Errorf("agent already running at %s but refused the open handoff: %w",
			cfg.BaseURL(), ferr)
	}
	return nil
}

// probeRunningAgent reports whether another instance of this agent answers
// the public status probe at baseURL — distinguishing "our port, our agent"
// from an unrelated service squatting on it.
func probeRunningAgent(selfClient *http.Client, baseURL string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/status", http.NoBody)
	if err != nil {
		return false
	}
	resp, err := selfClient.Do(req)
	if err != nil {
		return false
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return false
	}
	var status struct {
		Agent string `json:"agent"`
	}
	if derr := json.NewDecoder(resp.Body).Decode(&status); derr != nil {
		return false
	}
	return status.Agent == "hyperweaver-agent"
}

// handleProtocolInvocation processes an hwa:// URI this process was spawned
// with. True means the action was delivered to the running agent (this
// process should exit); false means no agent answered and startup should
// continue, completing the action once the server is up.
func handleProtocolInvocation(cfg *config.Config, selfClient *http.Client, uri string) (bool, error) {
	if _, err := protocol.ParseAction(uri); err != nil {
		return false, err
	}

	secret, err := protocol.ReadSecret(cfg.ProtocolSecretPath())
	if errors.Is(err, fs.ErrNotExist) {
		// No secret on disk: no agent has ever booted for this user.
		return false, nil
	}
	if err != nil {
		// Present but unreadable — typically an agent running as a different
		// user (e.g. the packaged systemd service); its secret is 0600 and
		// the running instance would reject a handoff we cannot read anyway.
		return false, fmt.Errorf("read protocol secret (agent running as another user?): %w", err)
	}

	ferr := protocol.Forward(context.Background(), selfClient, cfg.BaseURL(), protocol.ActionOpen, secret)
	if ferr == nil {
		slog.Info("protocol action delivered to the running agent")
		return true, nil
	}
	if errors.Is(ferr, protocol.ErrRejected) {
		return false, ferr
	}
	// Transport failure: stale secret from a dead agent, nothing listening —
	// become the running agent and finish the action ourselves.
	slog.Info("no running agent answered the protocol handoff; starting up", "error", ferr)
	return false, nil
}

// waitForServer polls the agent's own status endpoint until the listener
// answers, bounded to a few seconds — protocol invocations can race server
// startup (tray clicks always find it up on the first probe). Opening the
// browser anyway on timeout is deliberate: the user gets a page, or a
// browser error a reload fixes, instead of silence.
func waitForServer(selfClient *http.Client, baseURL string) {
	client := &http.Client{Transport: selfClient.Transport, Timeout: 500 * time.Millisecond}
	for attempt := 0; attempt < 10; attempt++ {
		req, err := http.NewRequestWithContext(context.Background(),
			http.MethodGet, baseURL+"/status", http.NoBody)
		if err != nil {
			return
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	slog.Warn("server not answering yet; opening the browser anyway")
}
