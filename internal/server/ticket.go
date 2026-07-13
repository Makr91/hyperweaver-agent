package server

import "net/http"

// The Help & Support link's config feed — the Server's public
// GET /api/config/ticket (ConfigController.getTicketConfig) on this agent,
// so Direct mode renders the same profile-dropdown link. The UI consumes
// BoxVault's {value}-wrapped field shape and builds
// base_url&req=<req_type>&customerId=&user=&email=&context=<context>;
// it renders the link only when enabled AND base_url are set.

// handleTicketConfig serves GET /api/config/ticket (public — the UI fetches
// it without credentials, exactly like the Server's).
func (s *Server) handleTicketConfig(w http.ResponseWriter, _ *http.Request) {
	ticket := s.cfg.TicketSystem
	writeJSON(w, map[string]any{
		"ticket_system": map[string]any{
			"enabled":  map[string]any{"value": ticket.Enabled},
			"base_url": map[string]any{"value": ticket.BaseURL},
			"req_type": map[string]any{"value": ticket.ReqType},
			"context":  map[string]any{"value": ticket.Context},
		},
	})
}
