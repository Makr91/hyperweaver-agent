// Hyperweaver Agent — VirtualBox/Vagrant host-agent for the Hyperweaver
// control plane. Runs a local web server serving the Hyperweaver UI plus the
// Agent API, with a native system-tray icon (LedFx model: manage it from your
// own browser).
package main

//go:generate goversioninfo -platform-specific=true

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/config"
	"github.com/Makr91/hyperweaver-agent/internal/db"
	"github.com/Makr91/hyperweaver-agent/internal/keys"
	"github.com/Makr91/hyperweaver-agent/internal/localclient"
	"github.com/Makr91/hyperweaver-agent/internal/logging"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/openbrowser"
	"github.com/Makr91/hyperweaver-agent/internal/protocol"
	"github.com/Makr91/hyperweaver-agent/internal/server"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/tray"
	"github.com/Makr91/hyperweaver-agent/internal/version"
)

// main stays defer-free so os.Exit cannot skip cleanup — all work (and all
// defers) live in run.
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "", "path to config.yaml (default: per-user config dir)")
	headless := flag.Bool("headless", false, "run without the system-tray icon")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Fprintln(os.Stdout, version.Version)
		return nil
	}

	cfg, resolvedPath, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	closeLog, err := logging.Setup(cfg)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := closeLog(); cerr != nil {
			fmt.Fprintln(os.Stderr, cerr)
		}
	}()

	slog.Info("hyperweaver-agent starting",
		"version", version.Version,
		"config", resolvedPath,
		"headless", *headless,
	)

	// hwa:// invocation? Windows and Linux deliver protocol opens by spawning
	// a fresh process with the URI as an argument. Hand the action to the
	// agent already running for this user; with none running, keep starting
	// up and finish the action once the server is listening.
	pendingProtocolOpen := false
	if uri, ok := protocol.URIFromArgs(flag.Args()); ok {
		delivered, perr := handleProtocolInvocation(cfg, selfClient(cfg), uri)
		if perr != nil {
			slog.Error("protocol invocation failed", "uri", uri, "error", perr)
			return perr
		}
		if delivered {
			return nil
		}
		pendingProtocolOpen = true
	}

	keyStore, err := keys.Open(cfg.KeyStorePath())
	if err != nil {
		slog.Error("key store setup failed", "error", err)
		return err
	}

	// First-boot claim token: while the agent can still be bootstrapped (no
	// keys yet), ensure the setup token exists and print it so a host admin
	// can read it. It guards POST /api-keys/bootstrap. No-op once a key exists.
	if cfg.APIKeys.BootstrapEnabled && cfg.APIKeys.BootstrapRequireClaimToken && keyStore.Count() == 0 {
		if token := auth.GetOrGenerateSetupToken(cfg.SetupTokenPath()); token != "" {
			slog.Info("Setup token (required to create the first API key): " + token)
		}
	}

	trayTokens := auth.NewTrayTokens()

	// Handoff secret for the hwa:// protocol handler: rewritten fresh every
	// boot, so possession proves "local process, same user, current agent
	// run". A write failure only disables the protocol handoff.
	if werr := protocol.WriteSecret(cfg.ProtocolSecretPath()); werr != nil {
		slog.Error("write protocol secret (hwa:// handoff disabled)", "error", werr)
	}

	// openUI is the one signed-in-browser action shared by every entry point:
	// the tray Open click, the hwa:// protocol handler (POST /protocol/open
	// on Windows/Linux, the in-process Apple Event on macOS), and a
	// cold-start protocol invocation. Local presence is the credential: a
	// single-use token in the URL fragment signs the SPA in without a login
	// screen.
	openUI := func() {
		waitForServer(selfClient(cfg), cfg.BaseURL())
		url := cfg.LocalURL()
		if token, mintErr := trayTokens.Mint(); mintErr == nil {
			url += "#tray=" + token
		} else {
			slog.Error("mint tray token", "error", mintErr)
		}
		openbrowser.Open(url, cfg.Browser.Path)
	}

	// Arguments a restart-spawned successor gets: rebuilt from parsed flag
	// values (the sanitized config path), never raw process arguments.
	restartArgs := []string{"--config", resolvedPath}
	if *headless {
		restartArgs = append(restartArgs, "--headless")
	}

	taskQueue, machineStore, reconciler, closeDBs, err := setupTasks(cfg)
	if err != nil {
		slog.Error("task system setup failed", "error", err)
		return err
	}
	defer closeDBs()

	srv, err := server.New(cfg, keyStore, trayTokens, taskQueue, machineStore, restartArgs, openUI)
	if err != nil {
		slog.Error("server setup failed", "error", err)
		return err
	}

	// Bind before anything is visible: a conflict means another instance owns
	// the port. Desktop launches resolve that LedFx-style — hand the running
	// instance an open action and exit, so a duplicate launch (or a protocol
	// race) never shows a second tray icon. Headless duplicates just fail;
	// that is systemd's problem to referee.
	if lerr := srv.Listen(); lerr != nil {
		if *headless {
			slog.Error("http server bind failed", "error", lerr)
			return lerr
		}
		return handleBindConflict(cfg, selfClient(cfg), lerr)
	}

	// The queue and reconciler start only once this process owns the port —
	// a duplicate desktop launch (resolved above) must never process tasks
	// or sweep the registry.
	taskQueue.Start()
	reconciler.Start()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.Start()
	}()

	if pendingProtocolOpen {
		go openUI()
	}

	shutdown := func() {
		reconciler.Stop()
		taskQueue.Stop()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if serr := srv.Shutdown(ctx); serr != nil {
			slog.Error("server shutdown", "error", serr)
		}
		slog.Info("hyperweaver-agent stopped")
	}

	if *headless {
		return runHeadless(serverErr, shutdown)
	}

	// Quit the tray if the server dies or a signal arrives, so the process
	// never lingers as a dead icon.
	fatal := make(chan error, 1)
	go func() {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		select {
		case srvErr := <-serverErr:
			if srvErr != nil {
				slog.Error("http server failed", "error", srvErr)
				fatal <- srvErr
			}
		case <-ctx.Done():
			slog.Info("signal received, shutting down")
		}
		tray.Quit()
	}()

	// macOS delivers hwa:// invocations to this running process as an Apple
	// Event (no new process, no HTTP handoff) — receive them in-process.
	// No-op on other platforms. Installed before the tray takes the main
	// thread so an event that cold-launched the app is not dropped.
	protocol.InstallURLHandler(func(uri string) {
		if _, perr := protocol.ParseAction(uri); perr != nil {
			slog.Warn("ignoring invalid protocol invocation", "uri", uri, "error", perr)
			return
		}
		openUI()
	})

	// Blocks the main goroutine until Quit (macOS requires the tray's event
	// loop on the main thread).
	tray.Run(tray.Options{
		Title:   "Hyperweaver Agent v" + version.Version,
		Tooltip: "Hyperweaver Agent",
		OnOpen:  openUI,
		OnExit:  shutdown,
	})

	select {
	case srvErr := <-fatal:
		return srvErr
	default:
		return nil
	}
}

// setupTasks opens the agent's databases and builds the task queue and the
// machine subsystem on top of it: tasks.sqlite carries the queue,
// agent.sqlite the machine registry; the lifecycle executors are registered
// before the queue ever starts. The returned closer releases both database
// handles.
func setupTasks(cfg *config.Config) (*tasks.Queue, *machines.Store, *machines.Reconciler, func(), error) {
	tasksPath, err := cfg.TasksDBPath()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	agentPath, err := cfg.AgentDBPath()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	taskLogDir, err := cfg.TaskLogDir()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// database.sqlite_options applies to both agent databases.
	sqliteOpts := cfg.Database.SQLiteOptions
	dbOptions := db.Options{
		JournalMode:       sqliteOpts.JournalMode,
		Synchronous:       sqliteOpts.Synchronous,
		CacheSizeMB:       sqliteOpts.CacheSizeMB,
		TempStore:         sqliteOpts.TempStore,
		MmapSizeMB:        sqliteOpts.MmapSizeMB,
		BusyTimeoutMS:     sqliteOpts.BusyTimeoutMS,
		WALAutocheckpoint: sqliteOpts.WALAutocheckpoint,
		Optimize:          sqliteOpts.Optimize,
	}

	// Startup-scoped, not request-scoped — Background is correct here.
	// A restart-spawned successor retries while its predecessor releases the
	// database file locks — same handshake the port bind uses; the databases
	// open before the port, so without this a restart races the dying
	// process's SQLite locks (observed as "disk I/O error (1546)").
	openDB := func(path string, migrations []string) (*sql.DB, error) {
		attempts := 1
		if os.Getenv("HYPERWEAVER_RESTART") == "1" {
			attempts = 20
		}
		var lastErr error
		for i := 0; i < attempts; i++ {
			database, oerr := db.Open(context.Background(), path, &dbOptions, migrations)
			if oerr == nil {
				return database, nil
			}
			lastErr = oerr
			if attempts > 1 {
				time.Sleep(500 * time.Millisecond)
			}
		}
		return nil, lastErr
	}

	tasksDB, err := openDB(tasksPath, tasks.Migrations)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	agentDB, err := openDB(agentPath, machines.Migrations)
	if err != nil {
		_ = tasksDB.Close()
		return nil, nil, nil, nil, err
	}
	closer := func() {
		if cerr := tasksDB.Close(); cerr != nil {
			slog.Error("close tasks database", "error", cerr)
		}
		if cerr := agentDB.Close(); cerr != nil {
			slog.Error("close agent database", "error", cerr)
		}
	}

	store := tasks.NewStore(tasksDB)
	output := tasks.NewOutputManager(store, tasks.OutputConfig{
		Enabled:          cfg.Tasks.Output.Enabled,
		Mode:             cfg.Tasks.Output.Mode,
		CircularMaxLines: cfg.Tasks.Output.CircularMaxLines,
		FlushInterval:    time.Duration(cfg.Tasks.Output.FlushIntervalSeconds) * time.Second,
		PersistLogFile:   cfg.Tasks.Output.PersistLogFile,
		LogDirectory:     taskLogDir,
	})
	queue := tasks.NewQueue(store, output, tasks.QueueConfig{
		PollInterval:    time.Duration(cfg.Tasks.PollIntervalSeconds) * time.Second,
		MaxConcurrent:   cfg.Tasks.MaxConcurrent,
		RetentionDays:   cfg.Tasks.RetentionDays,
		CleanupInterval: time.Duration(cfg.Cleanup.Interval) * time.Second,
	})

	machineStore := machines.NewStore(agentDB)
	reconciler := machines.NewReconciler(machineStore, store,
		cfg.Machines.AutoDiscovery,
		time.Duration(cfg.Machines.DiscoveryInterval)*time.Second)
	machines.RegisterExecutors(queue, machineStore, reconciler,
		time.Duration(cfg.Machines.ShutdownTimeout)*time.Second)

	return queue, machineStore, reconciler, closer, nil
}

func runHeadless(serverErr chan error, shutdown func()) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case srvErr := <-serverErr:
		if srvErr != nil {
			slog.Error("http server failed", "error", srvErr)
			shutdown()
			return srvErr
		}
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
