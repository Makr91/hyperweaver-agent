// Package server hosts the agent's HTTP surface: the public status endpoint
// and the Hyperweaver UI (Direct mode).
package server

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/assets"
	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/config"
	"github.com/Makr91/hyperweaver-agent/internal/keys"
	"github.com/Makr91/hyperweaver-agent/internal/locations"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/monitoring"
	"github.com/Makr91/hyperweaver-agent/internal/prefs"
	"github.com/Makr91/hyperweaver-agent/internal/provisioner"
	"github.com/Makr91/hyperweaver-agent/internal/secrets"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// Server is the agent's HTTP (and optional HTTPS) server.
type Server struct {
	cfg            *config.Config
	keys           *keys.Store
	trayTokens     *auth.TrayTokens
	oidcMgr        *oidcManager
	oidcStarts     *startLimiter
	tasks          *tasks.Queue
	machines       *machines.Store
	provisioners   *provisioner.Registry
	storage        *locations.Set
	secrets        *secrets.Store
	prefs          *prefs.Store
	assets         *assets.Store
	artifactSvc    *assets.Service
	monitor        *monitoring.Service
	dbs            []DBHandle
	wsTickets      *wsTickets
	sshSessions    *sshSessions
	termSessions   *termSessions
	machineMetrics *machineMetricsState
	events         *eventHub
	health         *healthState
	httpSrv        *http.Server
	listener       net.Listener
	startedAt      time.Time

	// httpsSrv/httpsListener exist only when ssl.enabled AND the certificate
	// loaded — certificate problems leave the agent HTTP-only (Node-agent
	// SSLManager semantics), never down.
	httpsSrv      *http.Server
	httpsListener net.Listener

	// restartArgs are the arguments a restart-spawned successor process gets —
	// built by main from parsed flag values (never raw os.Args).
	restartArgs []string

	// teardown stops the queue and services and closes the databases; the
	// restart runs it before telling the successor the files are free.
	teardown func()

	handoffMu         sync.Mutex
	successorExpected bool
	released          chan struct{}

	// openUI opens the signed-in UI in the user's browser — the same action a
	// tray Open click performs, injected by main so the hwa:// protocol
	// handoff (POST /protocol/open) shares it exactly.
	openUI func(query string)
}

// New builds the server and its routes.
func New(cfg *config.Config, keyStore *keys.Store, trayTokens *auth.TrayTokens, taskQueue *tasks.Queue, machineStore *machines.Store, provisioners *provisioner.Registry, storage *locations.Set, secretsStore *secrets.Store, prefsStore *prefs.Store, assetsStore *assets.Store, artifactSvc *assets.Service, monitor *monitoring.Service, dbs []DBHandle, restartArgs []string, teardown func(), openUI func(query string)) (*Server, error) {
	s := &Server{
		cfg:            cfg,
		keys:           keyStore,
		trayTokens:     trayTokens,
		tasks:          taskQueue,
		machines:       machineStore,
		provisioners:   provisioners,
		storage:        storage,
		secrets:        secretsStore,
		prefs:          prefsStore,
		assets:         assetsStore,
		artifactSvc:    artifactSvc,
		monitor:        monitor,
		dbs:            dbs,
		wsTickets:      newWsTickets(),
		sshSessions:    newSSHSessions(),
		termSessions:   newTermSessions(),
		machineMetrics: newMachineMetricsState(),
		events:         newEventHub(),
		health:         &healthState{},
		startedAt:      time.Now(),
		restartArgs:    restartArgs,
		teardown:       teardown,
		released:       make(chan struct{}),
		openUI:         openUI,
	}

	s.oidcMgr = newOIDCManager(cfg, keyStore)
	s.oidcStarts = newStartLimiter()
	machines.SetOIDCTokenSource(s.oidcMgr.bearerToken)
	taskQueue.Store().Notify = s.publishTask
	machineStore.Notify = s.publishStats
	monitor.SetOnCollected(s.publishSamples)

	mux := http.NewServeMux()
	if err := s.registerRoutes(mux); err != nil {
		return nil, err
	}
	handler := requestLog(recoverer(corsMiddleware(&cfg.CORS, mux)))
	s.httpSrv = &http.Server{
		Addr:              cfg.ListenAddr(),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	s.httpSrv.RegisterOnShutdown(s.events.shutdown)
	if cfg.SSL.Enabled {
		s.httpsSrv = &http.Server{
			Addr:              cfg.HTTPSListenAddr(),
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
		}
		s.httpsSrv.RegisterOnShutdown(s.events.shutdown)
	}
	return s, nil
}
