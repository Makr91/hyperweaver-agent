// Package server hosts the agent's HTTP surface: the public status endpoint
// and the Hyperweaver UI (Direct mode).
package server

import (
	"net"
	"net/http"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/assets"
	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/config"
	"github.com/Makr91/hyperweaver-agent/internal/keys"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/monitoring"
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
	secrets        *secrets.Store
	assets         *assets.Store
	artifactSvc    *assets.Service
	monitor        *monitoring.Service
	dbs            []DBHandle
	wsTickets      *wsTickets
	sshSessions    *sshSessions
	termSessions   *termSessions
	machineMetrics *machineMetricsState
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

	// openUI opens the signed-in UI in the user's browser — the same action a
	// tray Open click performs, injected by main so the hwa:// protocol
	// handoff (POST /protocol/open) shares it exactly.
	openUI func()
}

// New builds the server and its routes.
func New(cfg *config.Config, keyStore *keys.Store, trayTokens *auth.TrayTokens, taskQueue *tasks.Queue, machineStore *machines.Store, provisioners *provisioner.Registry, secretsStore *secrets.Store, assetsStore *assets.Store, artifactSvc *assets.Service, monitor *monitoring.Service, dbs []DBHandle, restartArgs []string, openUI func()) (*Server, error) {
	s := &Server{
		cfg:            cfg,
		keys:           keyStore,
		trayTokens:     trayTokens,
		tasks:          taskQueue,
		machines:       machineStore,
		provisioners:   provisioners,
		secrets:        secretsStore,
		assets:         assetsStore,
		artifactSvc:    artifactSvc,
		monitor:        monitor,
		dbs:            dbs,
		wsTickets:      newWsTickets(),
		sshSessions:    newSSHSessions(),
		termSessions:   newTermSessions(),
		machineMetrics: newMachineMetricsState(),
		startedAt:      time.Now(),
		restartArgs:    restartArgs,
		openUI:         openUI,
	}

	s.oidcMgr = newOIDCManager(cfg, keyStore)
	s.oidcStarts = newStartLimiter()
	machines.SetOIDCTokenSource(s.oidcMgr.bearerToken)

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
	if cfg.SSL.Enabled {
		s.httpsSrv = &http.Server{
			Addr:              cfg.HTTPSListenAddr(),
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
		}
	}
	return s, nil
}
