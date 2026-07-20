// Hyperweaver Agent — VirtualBox/Vagrant host-agent for the Hyperweaver
// control plane. Runs a local web server serving the Hyperweaver UI plus the
// Agent API, with a native system-tray icon (LedFx model: manage it from your
// own browser).
//
//	@title			Agent API
//	@version		1.0.0
//	@description	Hyperweaver Agent API v1 — the shared host-agent contract (architecture D1), as implemented by hyperweaver-agent (VirtualBox/Vagrant, Go). Reference implementation: zoneweaver-agent (Bhyve/OmniOS, Node). Capabilities are advertised by the public GET /api/status (role, hypervisors, console, auth, features) and drive conditional UI rendering. This document describes only the endpoints this agent implements today and grows with it; the console group lands with the console phase. The implementing application version is `info.x-app-version`; `info.version` is the frozen contract line. Authorization is role-based (admin > operator > viewer) and enforced by a central method+path policy; each operation notes its minimum role.
//	@license.name	GPL-3.0
//	@license.url	https://github.com/Makr91/hyperweaver-agent/blob/main/LICENSE.md
//	@contact.name	Hyperweaver Agent
//	@contact.url	https://github.com/Makr91/hyperweaver-agent
//	@externalDocs.description	View on GitHub
//	@externalDocs.url	https://github.com/Makr91/hyperweaver-agent
//	@tag.name		Status
//	@tag.description	Public identity and capability discovery (Hyperweaver dual-mode contract)
//	@tag.name		API Keys
//	@tag.description	API-key lifecycle (Agent API v1 local auth tier)
//	@tag.name		Local Login
//	@tag.description	Local-presence sign-in: the tray Open handoff and the hwa:// protocol handler
//	@tag.name		System
//	@tag.description	Version, update checking, prerequisite detection
//	@tag.name		Task Management
//	@tag.description	The task queue: every machine operation runs as a prioritized, dependency-chained task with streamed output
//	@tag.name		Machine Management
//	@tag.description	VirtualBox machines, built and provisioned natively by the agent (the zoneweaver mechanism: create orchestration → SSH/ansible pipeline; vagrant is never executed — externally-created vagrant projects are still discovered read-only), operated through queued tasks
//	@tag.name		Console
//	@tag.description	Machine consoles: SSH terminal sessions (interactive shell over the provisioning transport), the VNC websockify bridge onto the machine's VRDE port (requires a usable VBoxVNC extpack — the console list in /api/status advertises vnc only then), the browser-RDP bridge (the IronRDP web client's RDCleanPath transport onto the VRDE port — base VRDP, no extpack; advertised as rdp), the turnkey VRDE TLS setup that path demands, no-session framebuffer screenshots, and the WebSocket ticket every upgrade requires. WebSocket upgrades authenticate by ?ticket= (minted at GET /ws-ticket), never by API-key headers — browser WebSocket clients cannot send them.
//	@tag.name		Provisioning
//	@tag.description	Provisioner package registry (the provisioner-registry capability token — finer than the cross-agent provisioning token, which any provisioning-capable agent advertises regardless of wire shape): packages in SHI's on-disk format — <name>/provisioner-collection.yml with <version>/provisioner.yml trees — listed, imported (folder, archive, or git clone; task-queued), and deleted only while no machine references them. One system for every package family; installer-bundled packages seed on startup without ever overwriting existing versions. Hosts.template.yml renders with TRUE Jinja2 semantics (gonja): parenthesized filter args, loop.*, is defined; undefined variables render empty; includes resolve inside the package's templates/ dir only.
//	@tag.name		Artifacts
//	@tag.description	The merged artifact system (the artifacts capability token, config-gated by artifact_storage.enabled — Mark's 2026-07-09 ruling: ONE zoneweaver-shaped system): typed storage locations where iso, image, installer, fixpack, and hotfix are ALL location types — one scan, one SHA-256 checksum store (the ONLY algorithm; md5/sha1 are rejected everywhere), one surface. Five BUILT-IN locations always exist under artifact_storage.dir (isos, images, installers, fixpacks, hotfixes; source builtin, never deletable — disable instead); operator locations come from artifact_storage.paths[] and the storage-path API (which persists into config.yaml). Installer-family locations store per role (<location>/<role>/<file>); iso/image locations are flat and extension-filtered. SHI's hash-expectation model rides on top: bundled registry seeds + the HCL catalog's authoritative hashes; machine prepare REFUSES any referenced file that is absent, unhashed, or hash-mismatched. Automatic scans (startup + artifact_storage.scanning.periodic_scan_interval) run agent-side without task rows; user-triggered scans are tasks. cdroms[] entries reference cached ISOs by filename ({iso}) alongside raw paths.
//	@tag.name		File System
//	@tag.description	Host file browser (the file-browser capability token, config-gated by file_browser.enabled — zoneweaver's FULL surface, 1:1 where the platform allows): GET /filesystem lists agent-host directories, and the mutate family edits them — create folder, text content read/write (bounded by security.max_edit_size_mb), upload/download, rename, move/copy (task-queued: file_move/file_copy), delete, archives (task-queued create/extract under file_browser.archive), permissions. Every path passes the same security bounds (traversal guard, browse-root containment, forbidden paths/patterns); the whole surface is operator-gated by the central policy. Platform honesty: uid/gid ownership applies on Unix hosts only (Windows answers 400 where it matters and mode toggles the read-only attribute); archive CREATION speaks zip/tar/tar.gz (Go's bzip2 is decompress-only), extraction adds tar.bz2 and .gz. Mutations are native Go file operations — the base's pfexec shell-outs have no analog.
//	@tag.name		Guest Agent
//	@tag.description	The QEMU guest-agent channel (the guest-agent capability token, config-gated by guest_agent.enabled — Mark's go 2026-07-10): credential-less structured guest control with NO SSH and NO Guest Additions. The UART is a PER-MACHINE create option (vbox.guest_agent: true, default false, under the guest_agent.enabled master gate — Mark's Proxmox-model ruling 2026-07-12; per-hypervisor key, sync 2026-07-19): opted-in creates wire a COM2 UART onto a host pipe (\\.\pipe\hyperweaver-qga-<machine> on Windows hosts, qga.sock under the machine's working directory elsewhere); the box templates run qemu-ga on that port (isa-serial — auto-transport images pick virtio on bhyve, serial here); the agent opens the pipe per request (the channel takes ONE client), resyncs via guest-sync-delimited, and runs one command. The guest's live IPs also feed the RDP guest-target and SSH transport ladders as the live-truth rung. The DISCOVERY SWEEP additionally probes every running machine (QGA channel first, Guest Additions properties as fallback) and STORES the observation on the machine row (configuration.guest_info: {ips[], source, agent_responding, checked_at}) — the machine list the UI already polls carries the direct-connect gate, so per-machine polling of these endpoints is never needed for gating. Channel access is SERIALIZED per machine agent-side: concurrent commands queue on the single-client pipe instead of colliding.
//	@tag.name		Swap Management
//	@tag.description	Read-only swap information (the swap capability token); add/remove are OmniOS semantics and not implemented on this agent
//	@tag.name		Host Monitoring
//	@tag.description	Host telemetry (the monitoring capability token): always-on realtime sampling via gopsutil; monitoring.storage_enabled adds stored time series in per-datatype database files. Illumos-only families (ZFS pools/datasets/ARC, zpool-iostat disk IO, netstat routes) have no analog on this host and are absent.
//	@tag.name		Processes
//	@tag.description	Host process listing and control (the processes capability token). The zone concept does not exist here: the zone field is absent and ?zone= filters are ignored. Absent by platform: /{pid}/stack, /{pid}/limits (pstack/plimit are illumos tools) and trace/start (DTrace).
//	@tag.name		System Host Management
//	@tag.description	Host power management (the host-power capability token, config-gated by host_power.enabled — every endpoint answers 503 and the token disappears from /api/status when disabled). Absent by platform: runlevels, single-user/multi-user transitions, fast reboot, reboot-required tracking (init semantics with no cross-platform analog).
//	@tag.name		Host Configuration
//	@tag.description	System hosts-file and DNS control on all three platforms (the hosts-file and dns capability tokens — platform tokens, always advertised). Hosts file: Windows System32\drivers\etc\hosts, /etc/hosts elsewhere. DNS (/system/dns, the converged wire, sync 2026-07-17): one wire shape everywhere — nameservers/search_domains/domain/options — with per-OS mechanics: /etc/resolv.conf read/written on Unix; netsh per connected interface on Windows (nameservers only; raw and the resolv.conf-only fields answer 400, backup is ""); networksetup per enabled service on macOS (nameservers + search_domains; domain/options/raw answer 400, backup ""). Host network configuration (/network/hostname and /network/addresses, the hostname and ip-addresses capability tokens — the converged wire, sync 2026-07-17): zoneweaver's shipped network-controller family, BARE documents (no success/message/timestamp envelope; errors are {error, details?}). Hostname: GET is the live view (persisted name vs live system hostname), PUT queues the async set_hostname task. Addresses: GET is the real live listing over Go's stdlib interface enumeration; mutations (shipped 2026-07-19, Mark's build order) queue zoneweaver's create/delete/enable/disable_ip_address tasks with per-OS honesty — static creates everywhere, dhcp on Windows only, addrconf refused (SLAAC is automatic), enable/disable toggle the INTERFACE the addrobj names. Network spaces (/network/spaces*, the network-spaces token, minted 2026-07-19): enumerate and manage VirtualBox's network spaces — host-only interfaces (create/configure/delete + their DHCP servers — every host OS EXCEPT macOS, where VirtualBox 7 removed the family), host-only NETWORKS (VirtualBox's macOS-only vmnet family: create/modify/delete — Oracle's platform split, each side refusing the other's family with an honest 400), NAT networks (create/modify/delete/start/stop + port-forward and loopback rules), and the implicit internal networks (read-only: VirtualBox has no intnet verbs — they exist while a VM references them).
//	@tag.name		Database Management
//	@tag.description	SQLite statistics and maintenance across every open database file (tasks.sqlite, agent.sqlite, and the monitoring files when storage is enabled), plus the read-only explorer drill-down (tables with row counts and indexes, then paged rows — zoneweaver's contract, shared wire; no arbitrary SQL, every table and order_by column verified against the database's own catalog)
//	@tag.name		Settings
//	@tag.description	Agent configuration over the API (admin only)
//	@tag.name		Secrets
//	@tag.description	Global secrets store (the secrets capability token; admin only): SHI's six categories in secrets.yaml beside the config — kept OUT of /settings so that surface stays a pure configuration document. Values are plain text by design (it is the user's local machine; the generated Hosts.yml carries them as SECRETS_* template vars). Independently, Hosts.rb merges the working copy's secrets.yml/.secrets.yml at vagrant runtime — both mechanisms coexist.
package main

//go:generate goversioninfo -platform-specific=true

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/config"
	"github.com/Makr91/hyperweaver-agent/internal/keepawake"
	"github.com/Makr91/hyperweaver-agent/internal/keys"
	"github.com/Makr91/hyperweaver-agent/internal/logging"
	"github.com/Makr91/hyperweaver-agent/internal/loginitem"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/openbrowser"
	"github.com/Makr91/hyperweaver-agent/internal/protocol"
	"github.com/Makr91/hyperweaver-agent/internal/provisioner"
	"github.com/Makr91/hyperweaver-agent/internal/secrets"
	"github.com/Makr91/hyperweaver-agent/internal/server"
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

	// SHI's preventsystemfromsleep: hold the OS's native sleep inhibitor for
	// the agent's whole runtime (tray and headless alike). Failure only logs —
	// a host that cannot inhibit sleep still provisions.
	if cfg.HostPower.PreventSleep {
		if release, kerr := keepawake.Acquire("Hyperweaver Agent: host_power.prevent_sleep"); kerr != nil {
			slog.Warn("sleep prevention unavailable", "error", kerr)
		} else {
			defer release()
			slog.Info("system sleep prevention active (host_power.prevent_sleep)")
		}
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

	// startup.start_at_login: converge the OS login-item registration onto
	// the configured state (registered with these same arguments). Failure
	// only logs — a broken registration never stops the agent.
	if serr := loginitem.Sync(cfg.Startup.StartAtLogin, restartArgs); serr != nil {
		slog.Warn("start-at-login registration failed", "error", serr,
			"start_at_login", cfg.Startup.StartAtLogin)
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

	srv, err := server.New(cfg, keyStore, trayTokens, taskQueue, systems.machines, systems.provisioners, secretsStore, systems.assets, systems.artifactSvc, monitor, systems.dbs, restartArgs, openUI)
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

	// The queue, reconciler, monitoring collector, and artifact storage
	// service start only once this process owns the port — a duplicate
	// desktop launch (resolved above) must never process tasks, sweep the
	// registry, or write telemetry. Location sync + expectation seeding run
	// synchronously so the first task always sees the locations.
	if ierr := systems.artifactSvc.Initialize(context.Background()); ierr != nil {
		slog.Error("artifact storage initialization failed", "error", ierr)
		return ierr
	}
	taskQueue.Start()
	reconciler.Start()
	monitor.Start()
	systems.artifactSvc.Start()
	systems.snapshots.Start()

	// Machine orchestration startup (the base's startZoneOrchestration):
	// autostart machines boot in boot_priority order, highest first — plain
	// start tasks through the queue, skipping machines already running.
	if cfg.Machines.Orchestration.Enabled {
		go machines.StartupOrchestration(context.Background(), systems.machines, taskQueue)
	}

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

	// Open the signed-in UI when the desktop agent starts (Mark's ruling
	// 2026-07-07: one less click — a fresh install lands in the browser
	// instead of a tray hunt). A protocol invocation already opens above.
	if !*headless && cfg.Browser.OpenOnStart && !pendingProtocolOpen {
		go openUI()
	}

	shutdown := func() {
		systems.snapshots.Stop()
		systems.artifactSvc.Stop()
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

	// Troubleshooting submenu targets. Path resolution failures degrade to
	// opening nothing rather than blocking the tray.
	logPath, lerr := cfg.LogFilePath()
	if lerr != nil {
		slog.Warn("resolve log path for tray", "error", lerr)
	}
	dataDir, derr := cfg.DataDir()
	if derr != nil {
		slog.Warn("resolve data dir for tray", "error", derr)
	}

	// Blocks the main goroutine until Quit (macOS requires the tray's event
	// loop on the main thread).
	tray.Run(&tray.Options{
		Title:           "Hyperweaver Agent v" + version.Version,
		Tooltip:         "Hyperweaver Agent",
		OnOpen:          openUI,
		OnExit:          shutdown,
		OnOpenLog:       func() { openbrowser.Open(logPath, "") },
		OnOpenConfigDir: func() { openbrowser.Open(filepath.Dir(resolvedPath), "") },
		OnOpenDataDir:   func() { openbrowser.Open(dataDir, "") },
		OnRestart:       srv.Restart,
	})

	select {
	case srvErr := <-fatal:
		return srvErr
	default:
		return nil
	}
}
