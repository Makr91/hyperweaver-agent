// Package server hosts the agent's HTTP surface: the public status endpoint
// and the Hyperweaver UI (Direct mode).
package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/apidocs"
	"github.com/Makr91/hyperweaver-agent/internal/assets"
	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/config"
	"github.com/Makr91/hyperweaver-agent/internal/keys"
	"github.com/Makr91/hyperweaver-agent/internal/logging"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/monitoring"
	"github.com/Makr91/hyperweaver-agent/internal/provisioner"
	"github.com/Makr91/hyperweaver-agent/internal/secrets"
	"github.com/Makr91/hyperweaver-agent/internal/sslcert"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/version"
	"github.com/Makr91/hyperweaver-agent/internal/webui"
)

// Server is the agent's HTTP (and optional HTTPS) server.
type Server struct {
	cfg          *config.Config
	keys         *keys.Store
	trayTokens   *auth.TrayTokens
	tasks        *tasks.Queue
	machines     *machines.Store
	provisioners *provisioner.Registry
	secrets      *secrets.Store
	assets       *assets.Store
	monitor      *monitoring.Service
	dbs          []DBHandle
	httpSrv      *http.Server
	listener     net.Listener
	startedAt    time.Time

	// httpsSrv/httpsListener exist only when ssl.enabled AND the certificate
	// loaded — certificate problems leave the agent HTTP-only (Node-agent
	// SSLManager semantics), never down.
	httpsSrv      *http.Server
	httpsListener net.Listener

	// restartArgs are the arguments a restart-spawned successor process gets —
	// built by main from parsed flag values (never raw os.Args).
	restartArgs []string

	// openUI opens the signed-in UI in the user's browser — the same action a
	// tray Open click performs, injected by main so the hwa:// protocol
	// handoff (POST /protocol/open) shares it exactly.
	openUI func()
}

// New builds the server and its routes.
func New(cfg *config.Config, keyStore *keys.Store, trayTokens *auth.TrayTokens, taskQueue *tasks.Queue, machineStore *machines.Store, provisioners *provisioner.Registry, secretsStore *secrets.Store, assetsStore *assets.Store, monitor *monitoring.Service, dbs []DBHandle, restartArgs []string, openUI func()) (*Server, error) {
	s := &Server{
		cfg:          cfg,
		keys:         keyStore,
		trayTokens:   trayTokens,
		tasks:        taskQueue,
		machines:     machineStore,
		provisioners: provisioners,
		secrets:      secretsStore,
		assets:       assetsStore,
		monitor:      monitor,
		dbs:          dbs,
		startedAt:    time.Now(),
		restartArgs:  restartArgs,
		openUI:       openUI,
	}

	mux := http.NewServeMux()

	// Public identity + capabilities probe (Hyperweaver dual-mode contract):
	// /status is the canonical path, /api/status the SPA's discovery alias.
	mux.HandleFunc("GET /status", s.handleStatus)
	mux.HandleFunc("GET /api/status", s.handleStatus)

	// API-key surface (Agent API v1 local tier). Bootstrap is public (gated
	// by config + the setup token); everything else goes through the auth
	// middleware, whose central policy enforces the role model per path.
	requireKey := auth.Middleware(s.keys)
	mux.HandleFunc("POST /api-keys/bootstrap", s.handleBootstrapKey)
	mux.HandleFunc("POST /auth/tray-claim", s.handleTrayClaim)
	// hwa:// single-instance handoff: public route, authenticated by the
	// per-boot secret file only a local same-user process can read.
	mux.HandleFunc("POST /protocol/open", s.handleProtocolOpen)
	mux.Handle("POST /api-keys/generate", requireKey(http.HandlerFunc(s.handleGenerateKey)))
	mux.Handle("GET /api-keys", requireKey(http.HandlerFunc(s.handleListKeys)))
	mux.Handle("GET /api-keys/info", requireKey(http.HandlerFunc(s.handleKeyInfo)))
	mux.Handle("DELETE /api-keys/{id}", requireKey(http.HandlerFunc(s.handleDeleteKey)))
	mux.Handle("PUT /api-keys/{id}/revoke", requireKey(http.HandlerFunc(s.handleRevokeKey)))

	// Version / update / prerequisite surfaces (Agent API v1 System group).
	mux.Handle("GET /version", requireKey(http.HandlerFunc(s.handleVersion)))
	mux.Handle("GET /app/updates/check", requireKey(http.HandlerFunc(s.handleUpdateCheck)))
	mux.Handle("POST /app/updates/apply", requireKey(http.HandlerFunc(s.handleUpdateApply)))
	mux.Handle("GET /provisioning/status", requireKey(http.HandlerFunc(s.handleProvisioningStatus)))

	// Swap information (Agent API v1 Swap Management group, read-only —
	// Mark's ruling: the Go agent serves the swap information zoneweaver
	// serves; add/remove are OmniOS semantics and deliberately absent).
	mux.Handle("GET /system/swap/summary", requireKey(http.HandlerFunc(s.handleSwapSummary)))
	mux.Handle("GET /system/swap/areas", requireKey(http.HandlerFunc(s.handleSwapAreas)))
	mux.Handle("GET /monitoring/hosts/low-swap", requireKey(http.HandlerFunc(s.handleLowSwapHosts)))

	// Host telemetry (Agent API v1 Host Monitoring group, the `monitoring`
	// token — spec-matching pass, arch item 16): realtime always; stored
	// history when monitoring.storage_enabled.
	mux.Handle("GET /monitoring/system/cpu", requireKey(http.HandlerFunc(s.handleMonitoringCPU)))
	mux.Handle("GET /monitoring/system/memory", requireKey(http.HandlerFunc(s.handleMonitoringMemory)))
	mux.Handle("GET /monitoring/system/load", requireKey(http.HandlerFunc(s.handleMonitoringLoad)))
	mux.Handle("GET /monitoring/host", requireKey(http.HandlerFunc(s.handleMonitoringHost)))
	mux.Handle("GET /monitoring/summary", requireKey(http.HandlerFunc(s.handleMonitoringSummary)))
	mux.Handle("GET /monitoring/status", requireKey(http.HandlerFunc(s.handleMonitoringStatus)))
	mux.Handle("GET /monitoring/health", requireKey(http.HandlerFunc(s.handleMonitoringHealth)))
	mux.Handle("POST /monitoring/collect", requireKey(http.HandlerFunc(s.handleMonitoringCollect)))
	mux.Handle("GET /monitoring/network/interfaces", requireKey(http.HandlerFunc(s.handleMonitoringInterfaces)))
	mux.Handle("GET /monitoring/network/usage", requireKey(http.HandlerFunc(s.handleMonitoringNetworkUsage)))
	mux.Handle("GET /monitoring/network/ipaddresses", requireKey(http.HandlerFunc(s.handleMonitoringIPAddresses)))

	// Host processes (Agent API v1 Processes group, the `processes` token —
	// arch item 15). Literal segments (find, batch-kill, stats) win over the
	// {pid} wildcards in ServeMux precedence. Deliberately absent: /{pid}/stack,
	// /{pid}/limits (pstack/plimit are illumos tools), trace/start (DTrace).
	mux.Handle("GET /system/processes", requireKey(http.HandlerFunc(s.handleListProcesses)))
	mux.Handle("GET /system/processes/find", requireKey(http.HandlerFunc(s.handleFindProcesses)))
	mux.Handle("GET /system/processes/stats", requireKey(http.HandlerFunc(s.handleProcessStats)))
	mux.Handle("POST /system/processes/batch-kill", requireKey(http.HandlerFunc(s.handleBatchKillProcesses)))
	mux.Handle("GET /system/processes/{pid}", requireKey(http.HandlerFunc(s.handleProcessDetails)))
	mux.Handle("GET /system/processes/{pid}/files", requireKey(http.HandlerFunc(s.handleProcessFiles)))
	mux.Handle("POST /system/processes/{pid}/signal", requireKey(http.HandlerFunc(s.handleProcessSignal)))
	mux.Handle("POST /system/processes/{pid}/kill", requireKey(http.HandlerFunc(s.handleProcessKill)))

	// Host power management (the `host-power` token, config-gated by
	// host_power.enabled — mutations admin-only via the central policy;
	// runlevel/single-user/fast-reboot are init semantics with no analog
	// here and are deliberately absent).
	mux.Handle("GET /system/host/status", requireKey(s.hostPowerGate(s.handleHostStatus)))
	mux.Handle("GET /system/host/uptime", requireKey(s.hostPowerGate(s.handleHostUptime)))
	mux.Handle("POST /system/host/shutdown", requireKey(s.hostPowerGate(s.handleHostShutdown)))
	mux.Handle("POST /system/host/restart", requireKey(s.hostPowerGate(s.handleHostRestart)))
	mux.Handle("POST /system/host/poweroff", requireKey(s.hostPowerGate(s.handleHostPoweroff)))
	mux.Handle("POST /system/host/halt", requireKey(s.hostPowerGate(s.handleHostHalt)))

	// System hosts file (Mark's ruling 2026-07-05: the agent controls
	// /etc/hosts on all three platforms for VM name resolution). /system/dns
	// is deliberately absent — resolv.conf is Unix-only.
	mux.Handle("GET /system/hosts", requireKey(http.HandlerFunc(s.handleGetHostsFile)))
	mux.Handle("PUT /system/hosts", requireKey(http.HandlerFunc(s.handleUpdateHostsFile)))

	// Database management (Agent API v1 Database Management group), across
	// every open database file. Mutations admin-only via the central policy.
	mux.Handle("GET /database/stats", requireKey(http.HandlerFunc(s.handleDatabaseStats)))
	mux.Handle("POST /database/vacuum", requireKey(http.HandlerFunc(s.handleDatabaseVacuum)))
	mux.Handle("POST /database/analyze", requireKey(http.HandlerFunc(s.handleDatabaseAnalyze)))
	mux.Handle("POST /database/cleanup", requireKey(http.HandlerFunc(s.handleDatabaseCleanup)))

	// Host statistics (shared v1 stats shape). stats.public_access serves it
	// without a key (the Node agent's conditional /stats registration).
	if cfg.Stats.PublicAccess {
		mux.HandleFunc("GET /stats", s.handleStats)
	} else {
		mux.Handle("GET /stats", requireKey(http.HandlerFunc(s.handleStats)))
	}

	// Task queue (Agent API v1 Task Management group). Literal patterns
	// (/tasks/stats, /tasks/completed) win over the {taskId} wildcards in
	// ServeMux precedence.
	mux.Handle("GET /tasks", requireKey(http.HandlerFunc(s.handleListTasks)))
	mux.Handle("GET /tasks/stats", requireKey(http.HandlerFunc(s.handleTaskStats)))
	mux.Handle("GET /tasks/{taskId}", requireKey(http.HandlerFunc(s.handleTaskDetails)))
	mux.Handle("GET /tasks/{taskId}/output", requireKey(http.HandlerFunc(s.handleTaskOutput)))
	mux.Handle("DELETE /tasks/completed", requireKey(http.HandlerFunc(s.handleClearCompletedTasks)))
	mux.Handle("DELETE /tasks/{taskId}", requireKey(http.HandlerFunc(s.handleCancelTask)))

	// Machines (Agent API v1, canonical /machines/* noun only — design D-E).
	// Literal segments (ids, bulk) win over {machineName} in ServeMux
	// precedence.
	mux.Handle("GET /machines", requireKey(http.HandlerFunc(s.handleListMachines)))
	mux.Handle("POST /machines", requireKey(http.HandlerFunc(s.handleCreateMachine)))
	mux.Handle("GET /machines/ids", requireKey(http.HandlerFunc(s.handleServerIDs)))
	mux.Handle("GET /machines/ids/next", requireKey(http.HandlerFunc(s.handleNextServerID)))
	mux.Handle("POST /machines/bulk/start", requireKey(http.HandlerFunc(s.handleBulkStart)))
	mux.Handle("POST /machines/bulk/stop", requireKey(http.HandlerFunc(s.handleBulkStop)))
	mux.Handle("GET /machines/{machineName}", requireKey(http.HandlerFunc(s.handleMachineDetails)))
	mux.Handle("PUT /machines/{machineName}", requireKey(http.HandlerFunc(s.handleModifyMachine)))
	mux.Handle("GET /machines/{machineName}/config", requireKey(http.HandlerFunc(s.handleMachineConfig)))
	mux.Handle("POST /machines/{machineName}/start", requireKey(http.HandlerFunc(s.handleStartMachine)))
	mux.Handle("POST /machines/{machineName}/stop", requireKey(http.HandlerFunc(s.handleStopMachine)))
	mux.Handle("POST /machines/{machineName}/restart", requireKey(http.HandlerFunc(s.handleRestartMachine)))
	mux.Handle("POST /machines/{machineName}/suspend", requireKey(http.HandlerFunc(s.handleSuspendMachine)))
	mux.Handle("POST /machines/{machineName}/clone", requireKey(http.HandlerFunc(s.handleCloneMachine)))
	mux.Handle("POST /machines/{machineName}/provision", requireKey(http.HandlerFunc(s.handleProvisionMachine)))
	mux.Handle("GET /machines/{machineName}/provision/status", requireKey(http.HandlerFunc(s.handleProvisionStatus)))
	mux.Handle("POST /machines/{machineName}/run-provisioners", requireKey(http.HandlerFunc(s.handleRunProvisioners)))
	mux.Handle("POST /machines/{machineName}/sync", requireKey(http.HandlerFunc(s.handleSyncMachine)))
	mux.Handle("DELETE /machines/{machineName}", requireKey(http.HandlerFunc(s.handleDeleteMachine)))

	// Box-template registry (zoneweaver's template model on this hypervisor:
	// downloaded boxes as clonable disk images).
	mux.Handle("GET /templates", requireKey(http.HandlerFunc(s.handleListTemplates)))
	mux.Handle("POST /templates/pull", requireKey(http.HandlerFunc(s.handlePullTemplate)))
	mux.Handle("GET /machines/{machineName}/notes", requireKey(http.HandlerFunc(s.handleGetMachineNotes)))
	mux.Handle("PUT /machines/{machineName}/notes", requireKey(http.HandlerFunc(s.handleUpdateMachineNotes)))
	mux.Handle("GET /machines/{machineName}/tags", requireKey(http.HandlerFunc(s.handleGetMachineTags)))
	mux.Handle("PUT /machines/{machineName}/tags", requireKey(http.HandlerFunc(s.handleUpdateMachineTags)))

	// Provisioner package registry (Agent API v1 provisioning surface, the
	// `provisioning` token — architecture §8, first slice of the
	// provisioning engine). The literal "import" segment wins over {name} in
	// ServeMux precedence.
	mux.Handle("GET /provisioning/bridged-interfaces", requireKey(http.HandlerFunc(s.handleBridgedInterfaces)))
	mux.Handle("GET /provisioning/network/status", requireKey(http.HandlerFunc(s.handleProvisioningNetworkStatus)))
	mux.Handle("POST /provisioning/network/setup", requireKey(http.HandlerFunc(s.handleProvisioningNetworkSetup)))
	mux.Handle("DELETE /provisioning/network/teardown", requireKey(http.HandlerFunc(s.handleProvisioningNetworkTeardown)))
	mux.Handle("GET /provisioning/provisioners", requireKey(http.HandlerFunc(s.handleListProvisioners)))
	mux.Handle("POST /provisioning/provisioners/import", requireKey(http.HandlerFunc(s.handleImportProvisioner)))
	mux.Handle("GET /provisioning/provisioners/{name}", requireKey(http.HandlerFunc(s.handleProvisionerDetails)))
	mux.Handle("DELETE /provisioning/provisioners/{name}", requireKey(http.HandlerFunc(s.handleDeleteProvisioner)))
	mux.Handle("GET /provisioning/provisioners/{name}/versions/{version}", requireKey(http.HandlerFunc(s.handleProvisionerVersion)))
	mux.Handle("DELETE /provisioning/provisioners/{name}/versions/{version}", requireKey(http.HandlerFunc(s.handleDeleteProvisionerVersion)))

	// Installer file cache (the `artifacts` token, config-gated by
	// assets.enabled — Mark's ruling 2026-07-06: hash verification in full).
	// Literal segments win over {id} in ServeMux precedence.
	mux.Handle("GET /artifacts", requireKey(s.assetsGate(s.handleListArtifacts)))
	mux.Handle("POST /artifacts/scan", requireKey(s.assetsGate(s.handleScanArtifacts)))
	mux.Handle("POST /artifacts/download", requireKey(s.assetsGate(s.handleDownloadArtifact)))
	mux.Handle("POST /artifacts/hcl-download", requireKey(s.assetsGate(s.handleHCLDownload)))
	mux.Handle("POST /artifacts/upload", requireKey(s.assetsGate(s.handleUploadArtifact)))
	mux.Handle("POST /artifacts/register", requireKey(s.assetsGate(s.handleRegisterArtifact)))
	mux.Handle("DELETE /artifacts/{id}", requireKey(s.assetsGate(s.handleDeleteArtifact)))

	// Global secrets store (architecture D-C, SHI's SecretsPage categories) —
	// admin-only via the central role policy; separate from /settings so that
	// surface keeps serving just the configuration document.
	mux.Handle("GET /secrets", requireKey(http.HandlerFunc(s.handleGetSecrets)))
	mux.Handle("PUT /secrets", requireKey(http.HandlerFunc(s.handleUpdateSecrets)))

	// Settings surface (Agent API v1) — admin-only via the central role policy.
	mux.Handle("GET /settings", requireKey(http.HandlerFunc(s.handleGetSettings)))
	mux.Handle("GET /settings/schema", requireKey(http.HandlerFunc(s.handleSettingsSchema)))
	mux.Handle("PUT /settings", requireKey(http.HandlerFunc(s.handleUpdateSettings)))
	mux.Handle("POST /settings/backup", requireKey(http.HandlerFunc(s.handleCreateBackup)))
	mux.Handle("GET /settings/backups", requireKey(http.HandlerFunc(s.handleListBackups)))
	mux.Handle("DELETE /settings/backups/{filename}", requireKey(http.HandlerFunc(s.handleDeleteBackup)))
	mux.Handle("POST /settings/restore/{filename}", requireKey(http.HandlerFunc(s.handleRestoreBackup)))
	mux.Handle("POST /server/restart", requireKey(http.HandlerFunc(s.handleServerRestart)))

	// Interactive Agent API documentation (Swagger UI), Node-agent parity:
	// public /api-docs page + /api-docs/swagger.json, gated by configuration.
	if cfg.APIDocs.Enabled {
		if err := apidocs.Mount(mux); err != nil {
			return nil, err
		}
	}

	uiFS, err := webui.FS(cfg.UI.Path)
	if err != nil {
		return nil, err
	}

	// The docs site rides inside the UI artifact but is served independent of
	// ui.enabled — a docs-only (headless UI) setup still exposes /docs, same
	// as the Node agent.
	mountDocs(mux, uiFS)

	if cfg.UI.Enabled {
		if err := s.mountUI(mux, uiFS); err != nil {
			return nil, err
		}
	} else {
		mux.HandleFunc("GET /{$}", s.handleRootInfo)
	}

	handler := requestLog(recoverer(corsMiddleware(&cfg.CORS, mux)))
	s.httpSrv = &http.Server{
		Addr:              cfg.ListenAddr(),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if cfg.SSL.Enabled {
		s.httpsSrv = &http.Server{
			Addr:              cfg.HTTPSListenAddr(),
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
		}
	}
	return s, nil
}

// mountUI serves the SPA at /ui/ (with client-side-route fallback) and
// redirects / to /ui/.
func (s *Server) mountUI(mux *http.ServeMux, uiFS fs.FS) error {
	source := "embedded"
	if s.cfg.UI.Path != "" {
		source = s.cfg.UI.Path
	}
	slog.Info("serving UI", "source", source)

	index, err := fs.ReadFile(uiFS, "index.html")
	if err != nil {
		return err
	}
	fileServer := http.FileServerFS(uiFS)

	mux.Handle("GET /ui/", http.StripPrefix("/ui/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" || p == "." {
			p = "index.html"
		}
		if _, statErr := fs.Stat(uiFS, p); statErr != nil {
			// Client-side route: fall back to the SPA entry point. ServeContent
			// (not ServeFileFS) because ServeFileFS redirects */index.html.
			w.Header().Set("Cache-Control", "no-cache")
			http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(index))
			return
		}
		if p == "index.html" {
			w.Header().Set("Cache-Control", "no-cache")
		}
		fileServer.ServeHTTP(w, r)
	})))

	mux.Handle("GET /{$}", http.RedirectHandler("/ui/", http.StatusFound))
	return nil
}

// mountDocs serves the docs site the UI artifact carries at dist/docs
// (baseurl /docs). When the docs are not bundled (dev placeholder builds),
// requests get the Node agent's 503-with-guidance answer instead of a bare
// 404. fs.Sub cannot detect a missing directory, so existence is checked
// with fs.Stat.
func mountDocs(mux *http.ServeMux, uiFS fs.FS) {
	if _, err := fs.Stat(uiFS, "docs"); err != nil {
		mux.HandleFunc("GET /docs/", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			body := map[string]string{
				"error":   "Documentation not bundled in this build",
				"details": "The docs site ships inside the Hyperweaver UI artifact (dist/docs); use a build with the UI artifact baked in, or point ui.path at one.",
			}
			if err := json.NewEncoder(w).Encode(body); err != nil {
				slog.Error("write docs response", "error", err)
			}
		})
		return
	}

	sub, err := fs.Sub(uiFS, "docs")
	if err != nil {
		mux.Handle("GET /docs/", http.NotFoundHandler())
		return
	}
	mux.Handle("GET /docs/", http.StripPrefix("/docs/", http.FileServerFS(sub)))
}

func (s *Server) handleRootInfo(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	info := map[string]any{
		"name":    "Hyperweaver Agent",
		"version": version.Version,
		"ui":      false,
		"status":  "/api/status",
	}
	if err := json.NewEncoder(w).Encode(info); err != nil {
		slog.Error("write root response", "error", err)
	}
}

// Listen binds the configured address without serving yet. Split from Start
// so main can detect a bind conflict — the single-instance signal — before
// any tray icon is shown, and hand the action to the instance that owns the
// port instead. The HTTPS listener binds afterwards, non-fatally: only the
// HTTP port participates in single-instance detection.
func (s *Server) Listen() error {
	listener, err := s.listen()
	if err != nil {
		return err
	}
	s.listener = listener
	s.listenHTTPS()
	return nil
}

// listenHTTPS binds the TLS listener when ssl.enabled — the Node agent's
// setupHTTPSServer: certificates are generated on demand (ssl.generate_ssl),
// and any certificate or bind problem logs an error and leaves the agent
// HTTP-only rather than failing startup.
func (s *Server) listenHTTPS() {
	if s.httpsSrv == nil {
		return
	}
	keyPath := s.cfg.SSLKeyPath()
	certPath := s.cfg.SSLCertPath()

	// Installer-shipped CA (the ssl role's bundled STARTcloud CA): copied
	// into place before any generation decision.
	if serr := sslcert.SeedCA(s.cfg.SSLCACertPath(), s.cfg.SSLCAKeyPath()); serr != nil {
		slog.Warn("seeding installer CA failed; continuing", "error", serr)
	}

	if s.cfg.SSL.GenerateSSL {
		generated, err := sslcert.EnsureCertificates(keyPath, certPath,
			s.cfg.SSLCACertPath(), s.cfg.SSLCAKeyPath())
		if err != nil {
			slog.Error("SSL certificate generation failed; HTTPS not started",
				"error", err, "key_path", keyPath, "cert_path", certPath)
			s.httpsSrv = nil
			return
		}
		if generated {
			slog.Info("SSL certificates generated (CA-signed)",
				"key_path", keyPath, "cert_path", certPath,
				"ca_cert_path", s.cfg.SSLCACertPath())
		}
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		slog.Error("SSL certificate error; HTTPS not started",
			"error", err, "key_path", keyPath, "cert_path", certPath)
		s.httpsSrv = nil
		return
	}

	// Server-lifetime bind, not request-scoped — Background is correct here.
	listenConfig := net.ListenConfig{}
	listener, err := listenConfig.Listen(context.Background(), "tcp", s.cfg.HTTPSListenAddr())
	if err != nil {
		slog.Error("https bind failed; HTTPS not started",
			"addr", s.cfg.HTTPSListenAddr(), "error", err)
		s.httpsSrv = nil
		return
	}
	s.httpsListener = tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})

	// Mark's ruling (2026-07-05): ssl.enabled means ALL traffic rides TLS —
	// once the TLS listener is up, the plain listener's only job is
	// redirecting to the HTTPS counterpart (308 preserves method and body).
	// ssl.force_secure: false is the escape valve for clients that cannot
	// chase redirects — the HTTP port keeps serving the full app alongside
	// HTTPS (the Node agent's dual-serve model). When HTTPS could not start
	// (the early returns above), the plain listener keeps serving the full
	// app regardless, so a certificate problem degrades to HTTP instead of
	// taking the agent down.
	if s.cfg.SSL.ForceSecure {
		s.httpSrv.Handler = s.httpsRedirect()
	} else {
		slog.Info("ssl.force_secure is false: HTTP port keeps serving the full app alongside HTTPS",
			"http_addr", s.httpSrv.Addr, "https_addr", s.httpsSrv.Addr)
	}
}

// redirectHost returns the host the HTTPS redirect may target: the request's
// Host header is matched against the agent's own identities and the MATCHED
// COPY from the allowlist is returned — never the header value itself, so
// the Location header cannot carry an attacker-supplied host (the open
// redirect gosec's G710 flags).
func (s *Server) redirectHost(requestHost string) string {
	host := requestHost
	if bare, _, err := net.SplitHostPort(host); err == nil {
		host = bare
	}
	allowed := []string{"127.0.0.1", "localhost", "::1", "[::1]", s.cfg.Server.BindAddress}
	if hostname, err := os.Hostname(); err == nil {
		allowed = append(allowed, hostname)
	}
	for _, candidate := range allowed {
		if candidate != "" && strings.EqualFold(host, candidate) {
			return candidate
		}
	}
	return "127.0.0.1"
}

// httpsRedirect sends every plain-HTTP request to its HTTPS counterpart.
func (s *Server) httpsRedirect() http.Handler {
	port := strconv.Itoa(s.cfg.Server.HTTPSPort)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := url.URL{
			Scheme:   "https",
			Host:     net.JoinHostPort(s.redirectHost(r.Host), port),
			Path:     r.URL.Path,
			RawQuery: r.URL.RawQuery,
		}
		http.Redirect(w, r, target.String(), http.StatusPermanentRedirect)
	})
}

// Start blocks serving HTTP until Shutdown is called or the listener fails.
// The HTTPS server (when up) serves on its own goroutine; its failure never
// takes the HTTP surface down.
func (s *Server) Start() error {
	if s.listener == nil {
		if err := s.Listen(); err != nil {
			return err
		}
	}

	if s.httpsSrv != nil && s.httpsListener != nil {
		slog.Info("https server listening", "addr", s.httpsSrv.Addr)
		go func() {
			serveErr := s.httpsSrv.Serve(s.httpsListener)
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				slog.Error("https server failed", "error", serveErr)
			}
		}()
	}

	slog.Info("http server listening", "addr", s.httpSrv.Addr, "ui_enabled", s.cfg.UI.Enabled)
	err := s.httpSrv.Serve(s.listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// listen binds the configured address. A process spawned by /server/restart
// (HYPERWEAVER_RESTART=1) retries for a few seconds while its predecessor
// releases the port.
func (s *Server) listen() (net.Listener, error) {
	attempts := 1
	if os.Getenv("HYPERWEAVER_RESTART") == "1" {
		attempts = 20
	}

	// Server-lifetime bind, not request-scoped — Background is correct here.
	listenConfig := net.ListenConfig{}
	var lastErr error
	for i := 0; i < attempts; i++ {
		listener, err := listenConfig.Listen(context.Background(), "tcp", s.cfg.ListenAddr())
		if err == nil {
			return listener, nil
		}
		lastErr = err
		if attempts > 1 {
			time.Sleep(500 * time.Millisecond)
		}
	}
	return nil, lastErr
}

// Shutdown gracefully drains connections on both listeners.
func (s *Server) Shutdown(ctx context.Context) error {
	err := s.httpSrv.Shutdown(ctx)
	if s.httpsSrv != nil {
		if herr := s.httpsSrv.Shutdown(ctx); herr != nil {
			err = errors.Join(err, herr)
		}
	}
	return err
}

// corsMiddleware implements the Node agent's CORS policy (its index.js
// corsOptions): an API-key-authenticated backend in a many-to-many mesh
// gates on the key, not the browser Origin — allow_all (default true)
// answers any Origin, allow_all: false falls back to the whitelist.
// Disallowed origins are declined by omitting the CORS headers, never by
// failing the request. Credentialed responses echo the Origin (a wildcard is
// invalid with credentials).
func corsMiddleware(cfg *config.CORSConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			// Not a cross-origin browser request.
			next.ServeHTTP(w, r)
			return
		}

		allowed := cfg.AllowAll
		if !allowed {
			for _, entry := range cfg.Whitelist {
				if entry == origin {
					allowed = true
					break
				}
			}
		}

		headers := w.Header()
		if allowed {
			headers.Set("Access-Control-Allow-Origin", origin)
			headers.Set("Access-Control-Allow-Credentials", "true")
			headers.Add("Vary", "Origin")
		} else {
			logging.Category("api_requests").Warn("CORS: origin not allowed", "origin", origin)
		}

		// Preflight: answered here (204) — the mux has no OPTIONS routes.
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			if allowed {
				headers.Set("Access-Control-Allow-Methods", "GET,HEAD,PUT,PATCH,POST,DELETE")
				if requestHeaders := r.Header.Get("Access-Control-Request-Headers"); requestHeaders != "" {
					headers.Set("Access-Control-Allow-Headers", requestHeaders)
					headers.Add("Vary", "Access-Control-Request-Headers")
				}
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// requestLog logs each request at debug level under the api_requests
// category (the Node agent's api-requests logger).
func requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		logging.Category("api_requests").Debug("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

// recoverer converts handler panics into 500s instead of killing the process.
func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("handler panic", "panic", rec, "path", r.URL.Path)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
