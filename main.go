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
	"sync"
	"syscall"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/assets"
	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/config"
	"github.com/Makr91/hyperweaver-agent/internal/db"
	"github.com/Makr91/hyperweaver-agent/internal/hostpower"
	"github.com/Makr91/hyperweaver-agent/internal/keys"
	"github.com/Makr91/hyperweaver-agent/internal/localclient"
	"github.com/Makr91/hyperweaver-agent/internal/logging"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/monitoring"
	"github.com/Makr91/hyperweaver-agent/internal/openbrowser"
	"github.com/Makr91/hyperweaver-agent/internal/protocol"
	"github.com/Makr91/hyperweaver-agent/internal/provisioner"
	"github.com/Makr91/hyperweaver-agent/internal/secrets"
	"github.com/Makr91/hyperweaver-agent/internal/server"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/tray"
	"github.com/Makr91/hyperweaver-agent/internal/updater"
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

	// Global secrets store (architecture D-C): secrets.yaml beside the
	// config, feeding SECRETS_* template vars and private-repo import
	// tokens. Missing file = empty store.
	secretsStore, err := secrets.Open(cfg.SecretsPath())
	if err != nil {
		slog.Error("secrets store setup failed", "error", err)
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

	systems, err := setupTasks(cfg, secretsStore)
	if err != nil {
		slog.Error("task system setup failed", "error", err)
		return err
	}
	defer systems.closeDBs()
	taskQueue := systems.queue
	reconciler := systems.reconciler
	monitor := systems.monitor

	srv, err := server.New(cfg, keyStore, trayTokens, taskQueue, systems.machines, systems.provisioners, secretsStore, systems.assets, monitor, systems.dbs, restartArgs, openUI)
	if err != nil {
		slog.Error("server setup failed", "error", err)
		return err
	}

	// Agent-update flow (SHI's download-then-relaunch): once the executor
	// has launched the verified installer, it fires this channel and the
	// agent exits cleanly so the installer can replace the binary. Wired for
	// both tray and headless modes below.
	downloadsDir, err := cfg.DownloadsDir()
	if err != nil {
		slog.Error("resolve downloads dir", "error", err)
		return err
	}
	updateExit := make(chan struct{})
	var updateExitOnce sync.Once
	updater.RegisterExecutors(taskQueue, &updater.ApplyEnv{
		VersionInfoURL: cfg.Updates.VersionInfoURL,
		CurrentVersion: version.Version,
		DownloadsDir:   downloadsDir,
		ExitAgent: func() {
			updateExitOnce.Do(func() { close(updateExit) })
		},
	})

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

	// The queue, reconciler, and monitoring collector start only once this
	// process owns the port — a duplicate desktop launch (resolved above)
	// must never process tasks, sweep the registry, or write telemetry.
	taskQueue.Start()
	reconciler.Start()
	monitor.Start()

	// Installer-bundled provisioner packages extract on startup — never
	// clobbering existing versions, so every boot is safe — and likewise
	// only once this process owns the port. Background: large bundles must
	// not delay the tray/UI, and the registry scans the directory live.
	go func() {
		if serr := provisioner.Seed(systems.provisioners.Dir()); serr != nil {
			slog.Error("provisioner seeding failed", "error", serr)
		}
	}()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.Start()
	}()

	if pendingProtocolOpen {
		go openUI()
	}

	shutdown := func() {
		monitor.Stop()
		reconciler.Stop()
		taskQueue.Stop()
		// SHI's keepserversrunning: the default leaves VMs alone; turned off,
		// every provisioned machine is force-powered-off on the way out
		// (direct commands — the queue is already stopped).
		if !cfg.Machines.KeepRunningOnExit {
			stopCtx, stopCancel := context.WithTimeout(context.Background(), 60*time.Second)
			machines.StopAllProvisioned(stopCtx, systems.machines)
			stopCancel()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if serr := srv.Shutdown(ctx); serr != nil {
			slog.Error("server shutdown", "error", serr)
		}
		slog.Info("hyperweaver-agent stopped")
	}

	if *headless {
		return runHeadless(serverErr, updateExit, shutdown)
	}

	// Quit the tray if the server dies, a signal arrives, or an update's
	// installer has launched, so the process never lingers as a dead icon.
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
		case <-updateExit:
			slog.Info("update installer launched — exiting for it to take over")
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

// agentSystems bundles everything setupTasks builds over the databases —
// the task queue, machine subsystem, provisioner registry, monitoring
// service, the open database handles (for the /database endpoints), and
// their closer.
type agentSystems struct {
	queue        *tasks.Queue
	machines     *machines.Store
	provisioners *provisioner.Registry
	assets       *assets.Store
	reconciler   *machines.Reconciler
	monitor      *monitoring.Service
	dbs          []server.DBHandle
	closeDBs     func()
}

// setupTasks opens the agent's databases and builds the task queue, the
// machine subsystem, the provisioner registry, and the monitoring service
// on top of them:
// tasks.sqlite carries the queue, agent.sqlite the machine registry, and —
// only when monitoring.storage_enabled — the per-datatype telemetry files
// carry stored samples. Every executor is registered before the queue ever
// starts. The returned closer releases every database handle.
func setupTasks(cfg *config.Config, secretsStore *secrets.Store) (*agentSystems, error) {
	tasksPath, err := cfg.TasksDBPath()
	if err != nil {
		return nil, err
	}
	agentPath, err := cfg.AgentDBPath()
	if err != nil {
		return nil, err
	}
	taskLogDir, err := cfg.TaskLogDir()
	if err != nil {
		return nil, err
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
		return nil, err
	}
	// agent.sqlite carries every core-state family: the machine registry's
	// migrations plus the artifact cache's, one ordered list.
	agentMigrations := append(append([]string{}, machines.Migrations...), assets.Migrations...)
	agentDB, err := openDB(agentPath, agentMigrations)
	if err != nil {
		_ = tasksDB.Close()
		return nil, err
	}

	// Every open handle lands here — the /database endpoints operate across
	// them all, and the closer releases them in reverse-open order.
	handles := []server.DBHandle{
		{Name: "tasks.sqlite", Path: tasksPath, DB: tasksDB, Tables: []string{"tasks"}},
		{Name: "agent.sqlite", Path: agentPath, DB: agentDB, Tables: []string{"machines", "artifacts"}},
	}
	closer := func() {
		for i := len(handles) - 1; i >= 0; i-- {
			if cerr := handles[i].DB.Close(); cerr != nil {
				slog.Error("close database", "name", handles[i].Name, "error", cerr)
			}
		}
	}

	// Telemetry storage (monitoring.storage_enabled): one database file per
	// data family so telemetry write churn never contends with the main
	// databases — Mark's ruling, 2026-07-05.
	var monitorStore *monitoring.Store
	if cfg.Monitoring.StorageEnabled {
		kinds := []struct {
			kind       string
			table      string
			migrations []string
		}{
			{"cpu", "cpu_samples", monitoring.CPUMigrations},
			{"memory", "memory_samples", monitoring.MemoryMigrations},
			{"network", "network_samples", monitoring.NetworkMigrations},
		}
		opened := make([]*sql.DB, 0, len(kinds))
		for _, k := range kinds {
			path, perr := cfg.MonitoringDBPath(k.kind)
			if perr != nil {
				closer()
				return nil, perr
			}
			database, oerr := openDB(path, k.migrations)
			if oerr != nil {
				closer()
				return nil, oerr
			}
			opened = append(opened, database)
			handles = append(handles, server.DBHandle{
				Name:   "monitoring-" + k.kind + ".sqlite",
				Path:   path,
				DB:     database,
				Tables: []string{k.table},
			})
		}
		monitorStore = monitoring.NewStore(opened[0], opened[1], opened[2])
	}
	monitor := monitoring.NewService(monitoring.NewSampler(), monitorStore,
		time.Duration(cfg.Monitoring.CollectionInterval)*time.Second,
		cfg.Monitoring.RetentionDays)

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

	// Provisioner package registry (architecture §8): the directory is the
	// source of truth — scanned live, seeded after the port is owned.
	provisionersDir, err := cfg.ProvisionersDir()
	if err != nil {
		closer()
		return nil, err
	}
	provisioners := provisioner.NewRegistry(provisionersDir)
	provisioner.RegisterExecutors(queue, provisioners, secretsStore.GitToken)

	// Installer file cache (assets.enabled): registered rows verify every
	// file machines mount (Mark's ruling — hash verification in full). The
	// store always exists (the /database endpoints see the table); a nil
	// handle in ProvisionEnv is what "disabled" means to the pipeline.
	assetsDir, err := cfg.AssetsDir()
	if err != nil {
		closer()
		return nil, err
	}
	assetsStore := assets.NewStore(agentDB, assetsDir)
	assets.RegisterExecutors(queue, assetsStore, secretsStore.ResourceAuth, secretsStore)
	var pipelineAssets *assets.Store
	if cfg.Assets.Enabled {
		pipelineAssets = assetsStore
		if serr := assets.SeedExpectations(context.Background(), assetsStore); serr != nil {
			closer()
			return nil, serr
		}
	}

	machinesDir, err := cfg.MachinesDir()
	if err != nil {
		closer()
		return nil, err
	}

	machineStore := machines.NewStore(agentDB)
	reconciler := machines.NewReconciler(machineStore, store,
		cfg.Machines.AutoDiscovery,
		time.Duration(cfg.Machines.DiscoveryInterval)*time.Second)
	machines.RegisterExecutors(queue, machineStore, reconciler,
		time.Duration(cfg.Machines.ShutdownTimeout)*time.Second,
		&machines.ProvisionEnv{
			Registry:                provisioners,
			SecretsVars:             secretsStore.TemplateVars,
			MachinesDir:             machinesDir,
			Assets:                  pipelineAssets,
			CACertPath:              cfg.SSLCACertPath(),
			CAKeyPath:               cfg.SSLCAKeyPath(),
			KeepFailedRunning:       cfg.Provisioning.KeepFailedMachinesRunning,
			DefaultSyncMethod:       cfg.Provisioning.DefaultSyncMethod,
			DefaultNetworkInterface: cfg.Provisioning.DefaultNetworkInterface,
		})

	// Host power operations run through the queue too (config-gated at the
	// HTTP surface; registering the executors unconditionally is harmless —
	// no handler queues them while the surface is disabled).
	hostpower.RegisterExecutors(queue, hostpower.LookupCommand)

	return &agentSystems{
		queue:        queue,
		machines:     machineStore,
		provisioners: provisioners,
		assets:       assetsStore,
		reconciler:   reconciler,
		monitor:      monitor,
		dbs:          handles,
		closeDBs:     closer,
	}, nil
}

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
