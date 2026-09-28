package server

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/machines"
)

const (
	healthOK      = "ok"
	healthWarning = "warning"
	healthError   = "error"

	healthProbeTimeout = 15 * time.Second
)

type healthReport struct {
	// ok | warning | error — the worst of the services
	Status string `json:"status" example:"ok"`
	// When the report was taken, RFC 3339
	Timestamp string `json:"timestamp"`
	// One coarse status word per service: database, hypervisor, tasks, monitoring
	Services map[string]string `json:"services"`
}

type healthState struct {
	mu   sync.Mutex
	last *healthReport
}

func (s *Server) databaseHealth(ctx context.Context) string {
	for i := range s.dbs {
		if err := s.dbs[i].DB.PingContext(ctx); err != nil {
			return healthError
		}
	}
	return healthOK
}

func (s *Server) hypervisorHealth(ctx context.Context) string {
	if machines.VBoxManagePath(ctx) != "" || utmHypervisorAvailable(ctx) {
		return healthOK
	}
	return healthError
}

func (s *Server) taskHealth() string {
	if s.tasks.ProcessorRunning() {
		return healthOK
	}
	return healthError
}

func (s *Server) monitoringHealth() string {
	if s.monitor.StorageEnabled() && !s.monitor.Running() {
		return healthError
	}
	if _, failed := s.monitor.Stats()["last_error"]; failed {
		return healthWarning
	}
	return healthOK
}

func worstHealth(services map[string]string) string {
	worst := healthOK
	for _, state := range services {
		if state == healthError {
			return healthError
		}
		if state == healthWarning {
			worst = healthWarning
		}
	}
	return worst
}

func (s *Server) healthReport(ctx context.Context) *healthReport {
	probeCtx, cancel := context.WithTimeout(ctx, healthProbeTimeout)
	defer cancel()
	services := map[string]string{
		"database":   s.databaseHealth(probeCtx),
		"hypervisor": s.hypervisorHealth(probeCtx),
		"tasks":      s.taskHealth(),
		"monitoring": s.monitoringHealth(),
	}
	return &healthReport{
		Status:    worstHealth(services),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Services:  services,
	}
}

func healthChanged(previous, next *healthReport) bool {
	if previous == nil || previous.Status != next.Status || len(previous.Services) != len(next.Services) {
		return true
	}
	for service, state := range next.Services {
		if previous.Services[service] != state {
			return true
		}
	}
	return false
}

func (s *Server) publishHealth() {
	go func() {
		report := s.healthReport(context.Background())
		s.health.mu.Lock()
		changed := healthChanged(s.health.last, report)
		if changed {
			s.health.last = report
		}
		s.health.mu.Unlock()
		if changed {
			s.events.publish("health", "health", report)
		}
	}()
}

// @Summary		Health of the agent and its services
// @Description	Public. The one health shape every UI backend answers: status is ok, warning or error, the worst of the services; timestamp is when the report was taken; services carries one coarse status word each for database (every open database file answers a ping), hypervisor (VBoxManage or a usable UTM is present), tasks (the task processor runs) and monitoring (error when storage is on and the collector is down, warning after a collector error). The same report is sent as the health event on the health topic of GET /api/events whenever a task ends and the report differs from the last one sent.
// @Tags			Status
// @Produce		json
// @Success		200	{object}	healthReport	"The health report"
// @Router			/api/health [get]
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.healthReport(r.Context()))
}
