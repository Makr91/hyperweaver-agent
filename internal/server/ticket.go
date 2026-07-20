package server

import "net/http"

// The Help & Support link's config feed — the Server's public
// GET /api/config/ticket (ConfigController.getTicketConfig) on this agent,
// so Direct mode renders the same profile-dropdown link. The UI consumes
// BoxVault's {value}-wrapped field shape and builds
// base_url&req=<req_type>&customerId=&user=&email=&context=<context>;
// it renders the link only when enabled AND base_url are set.

type ticketEnabledValue struct {
	Value bool `json:"value"`
}

type ticketBaseURLValue struct {
	Value string `json:"value" example:"https://xd.prominic.net/app/apprequest.nsf/router?openagent"`
}

type ticketReqTypeValue struct {
	Value string `json:"value" example:"sso"`
}

type ticketContextValue struct {
	Value string `json:"value" example:"https://github.com/Makr91/hyperweaver-agent"`
}

type ticketSystemConfig struct {
	Enabled ticketEnabledValue `json:"enabled"`
	BaseURL ticketBaseURLValue `json:"base_url"`
	ReqType ticketReqTypeValue `json:"req_type"`
	Context ticketContextValue `json:"context"`
}

type ticketConfigResponse struct {
	TicketSystem ticketSystemConfig `json:"ticket_system"`
}

// handleTicketConfig serves GET /api/config/ticket (public — the UI fetches
// it without credentials, exactly like the Server's).
//
//	@Summary		Ticket-system configuration (public)
//	@Description	The Help & Support link's config feed (the Server's /api/config/ticket served on this agent too, so Direct mode renders the same profile-dropdown link). No authentication. Fields ride BoxVault's {value}-wrapped shape; the UI renders the link only when enabled AND base_url are set, building base_url&req=<req_type>&customerId=&user=&email=&context=<context>.
//	@Tags			Status
//	@Produce		json
//	@Success		200	{object}	ticketConfigResponse	"Ticket-system configuration"
//	@Router			/api/config/ticket [get]
func (s *Server) handleTicketConfig(w http.ResponseWriter, _ *http.Request) {
	ticket := s.cfg.TicketSystem
	writeJSON(w, ticketConfigResponse{
		TicketSystem: ticketSystemConfig{
			Enabled: ticketEnabledValue{Value: ticket.Enabled},
			BaseURL: ticketBaseURLValue{Value: ticket.BaseURL},
			ReqType: ticketReqTypeValue{Value: ticket.ReqType},
			Context: ticketContextValue{Value: ticket.Context},
		},
	})
}
