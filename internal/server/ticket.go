package server

import "net/http"

// The Help & Support link's config feed — the Server's public
// GET /api/config/ticket (ConfigController.getTicketConfig) on this agent,
// so Direct mode renders the same profile-dropdown link. The UI consumes
// BoxVault's {value}-wrapped field shape and builds
// base_url&req=<req_type>&customerId=&user=&email=&context=<context>;
// it renders the link only when enabled AND base_url are set.

type ticketSystemConfig struct {
	Enabled            bool   `json:"enabled"`
	BaseURL            string `json:"base_url" example:"https://xd.prominic.net/app/apprequest.nsf/router?openagent"`
	ReqType            string `json:"req_type" example:"sso"`
	FallbackCustomerID string `json:"fallback_customer_id"`
	Context            string `json:"context" example:"https://github.com/Makr91/hyperweaver-agent"`
}

type ticketConfigResponse struct {
	TicketSystem ticketSystemConfig `json:"ticket_system"`
}

// handleTicketConfig serves GET /api/config/ticket (public — the UI fetches
// it without credentials, exactly like the Server's).
//
//	@Summary		Ticket-system configuration (public)
//	@Description	The Help & Support link's config feed. No authentication. Every member of ticket_system is a plain value: enabled, base_url, req_type, fallback_customer_id and context. The UI renders the link only when enabled AND base_url are set, building base_url&req=<req_type>&customerId=&user=&email=&context=<context>, customerId falling back to fallback_customer_id.
//	@Tags			Status
//	@Produce		json
//	@Success		200	{object}	ticketConfigResponse	"Ticket-system configuration"
//	@Router			/api/config/ticket [get]
func (s *Server) handleTicketConfig(w http.ResponseWriter, _ *http.Request) {
	ticket := s.cfg.TicketSystem
	writeJSON(w, ticketConfigResponse{
		TicketSystem: ticketSystemConfig{
			Enabled:            ticket.Enabled,
			BaseURL:            ticket.BaseURL,
			ReqType:            ticket.ReqType,
			FallbackCustomerID: ticket.FallbackCustomerID,
			Context:            ticket.Context,
		},
	})
}
