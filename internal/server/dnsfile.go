package server

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

// DNS endpoints (/system/dns — the Host Configuration group's second surface,
// the converged wire, sync 2026-07-17): zoneweaver's shipped resolv.conf
// editor, answered identically here. The WIRE is one shape everywhere — the
// standard envelope with nameservers/search_domains/domain/options (+raw on
// GET, +backup on PUT) — while the MECHANICS are per-platform honesty:
//   - Unix (Linux and friends): /etc/resolv.conf read and written directly,
//     the resolv.conf grammar, timestamped backup beside the file.
//   - Windows: there is NO resolv.conf — per-interface DNS via netsh
//     (structured fields only; raw and search_domains/domain/options refuse
//     with a 400 naming the field; backup is "" — no file to back up).
//   - macOS: /etc/resolv.conf is generated and IGNORED by the resolver for
//     most lookups — networksetup per network service is the honest route
//     (nameservers + search_domains; domain/options/raw refuse; backup "").

// dnsResolvConfPath is the Unix DNS configuration file.
const dnsResolvConfPath = "/etc/resolv.conf"

// dnsView is the structured half of the converged wire — exactly the four
// fields zoneweaver's parseResolvConf returns.
type dnsView struct {
	Nameservers   []string
	SearchDomains []string
	Domain        string
	Options       []string
}

// domainPtr renders the domain directive for the wire — nil when absent
// (zoneweaver's null shape).
func domainPtr(domain string) *string {
	if domain == "" {
		return nil
	}
	return &domain
}

// parseResolvConf implements the resolv.conf grammar (zoneweaver's parser,
// verbatim semantics): blanks and lines starting # or ; are skipped;
// nameserver appends, search extends, domain sets, options extends.
func parseResolvConf(raw string) dnsView {
	view := dnsView{Nameservers: []string{}, SearchDomains: []string{}, Options: []string{}}
	for _, line := range strings.Split(raw, "\n") {
		text := strings.TrimSpace(line)
		if text == "" || strings.HasPrefix(text, "#") || strings.HasPrefix(text, ";") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "nameserver":
			view.Nameservers = append(view.Nameservers, fields[1])
		case "search":
			view.SearchDomains = append(view.SearchDomains, fields[1:]...)
		case "domain":
			view.Domain = fields[1]
		case "options":
			view.Options = append(view.Options, fields[1:]...)
		}
	}
	return view
}

// renderResolvConf serializes the structured view in the converged order:
// manager header, domain, search, nameservers, options, trailing newline.
// The header text is agent-local (zoneweaver writes its own name) — the
// header's EXISTENCE is the shared shape, its wording is not wire.
func renderResolvConf(view *dnsView) string {
	var b strings.Builder
	b.WriteString("# Managed by hyperweaver-agent (" +
		time.Now().UTC().Format(time.RFC3339) + ")\n")
	if view.Domain != "" {
		b.WriteString("domain " + view.Domain + "\n")
	}
	if len(view.SearchDomains) > 0 {
		b.WriteString("search " + strings.Join(view.SearchDomains, " ") + "\n")
	}
	for _, ns := range view.Nameservers {
		b.WriteString("nameserver " + ns + "\n")
	}
	if len(view.Options) > 0 {
		b.WriteString("options " + strings.Join(view.Options, " ") + "\n")
	}
	return b.String()
}

// dnsGetResponse is the GET /system/dns answer: the converged success
// envelope spread with the parsed DNS view plus raw.
type dnsGetResponse struct {
	Success       bool     `json:"success"`
	Message       string   `json:"message"`
	Timestamp     string   `json:"timestamp"`
	Nameservers   []string `json:"nameservers"`
	SearchDomains []string `json:"search_domains"`
	// The resolv.conf domain directive; null when absent (always null on Windows/macOS)
	Domain  *string  `json:"domain"`
	Options []string `json:"options"`
	// The whole source text: /etc/resolv.conf on Unix, the platform tool's output on Windows/macOS
	Raw string `json:"raw"`
}

// handleGetDNS mirrors GET /system/dns — zoneweaver's shipped wire (the
// converged wire, sync 2026-07-17): the standard success envelope with
// nameservers/search_domains/domain/options/raw spread top-level.
//
//	@Summary		Read the DNS configuration
//	@Description	Minimum role: viewer (the dns capability token). The converged wire (sync 2026-07-17 — both agents answer the same shape): the standard success envelope with nameservers/search_domains/domain/options plus raw. Per-OS mechanics behind the one shape: Unix parses /etc/resolv.conf (grammar: blanks and #/; comment lines skipped; nameserver appends, search extends, domain sets, options extends; raw = the whole file). Windows has no resolv.conf — nameservers are the unique server IPs (static or DHCP-configured) across CONNECTED interfaces via netsh, search_domains/domain/options stay empty (the honest platform subset; DNS suffixes live elsewhere), raw = the netsh output. macOS resolv.conf is generated and ignored by the resolver — nameservers/search_domains union networksetup's per-enabled-service answers, domain/options stay empty, raw = the concatenated tool output.
//	@Tags			Host Configuration
//	@Produce		json
//	@Success		200	{object}	dnsGetResponse	"DNS configuration"
//	@Failure		500	{object}	wrappedError	"Failed to read DNS configuration"
//	@Router			/system/dns [get]
func (s *Server) handleGetDNS(w http.ResponseWriter, r *http.Request) {
	var view dnsView
	var raw string
	switch runtime.GOOS {
	case "windows":
		v, out, err := windowsDNSView(r)
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, "Failed to read DNS configuration", err.Error())
			return
		}
		view, raw = v, out
	case "darwin":
		v, out, err := darwinDNSView(r)
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, "Failed to read DNS configuration", err.Error())
			return
		}
		view, raw = v, out
	default:
		content, err := os.ReadFile(dnsResolvConfPath)
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, "Failed to read DNS configuration", err.Error())
			return
		}
		view, raw = parseResolvConf(string(content)), string(content)
	}

	writeJSON(w, dnsGetResponse{
		Success:       true,
		Message:       "DNS configuration retrieved successfully",
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Nameservers:   view.Nameservers,
		SearchDomains: view.SearchDomains,
		Domain:        domainPtr(view.Domain),
		Options:       view.Options,
		Raw:           raw,
	})
}

// dnsUpdateRequest is the PUT body (zoneweaver's shape): raw wins when
// present; pointers keep JS presence semantics — an absent key and an empty
// value are different answers on this wire.
type dnsUpdateRequest struct {
	// DNS server IP addresses (required unless raw is present; [] clears — DHCP revert on Windows, Empty on macOS)
	Nameservers *[]string `json:"nameservers"`
	// Search domains (Unix and macOS; 400 on Windows)
	SearchDomains *[]string `json:"search_domains"`
	// The resolv.conf domain directive (Unix only; 400 on Windows/macOS)
	Domain *string `json:"domain"`
	// resolv.conf options (Unix only; 400 on Windows/macOS)
	Options *[]string `json:"options"`
	// Raw resolv.conf content, written verbatim (takes precedence; Unix only — 400 on Windows/macOS)
	Raw *string `json:"raw"`
}

// validateNameservers requires every entry to be a literal IP — resolv.conf
// nameservers are addresses, and on Windows/macOS each entry becomes an argv
// word of a spawned tool.
func validateNameservers(nameservers []string) error {
	for _, ns := range nameservers {
		if net.ParseIP(ns) == nil {
			return fmt.Errorf("invalid nameserver %q: must be an IP address", ns)
		}
	}
	return nil
}

// validateDNSTokens rejects values that would break the single-line
// resolv.conf grammar (or smuggle extra directives).
func validateDNSTokens(kind string, values []string) error {
	for _, value := range values {
		if value == "" || strings.ContainsAny(value, " \t\r\n#") {
			return fmt.Errorf("invalid %s %q: whitespace and # are not allowed", kind, value)
		}
	}
	return nil
}

// dnsUpdateResponse is the PUT /system/dns answer: the converged success
// envelope with backup plus the parsed-back view (no raw).
type dnsUpdateResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
	// The backup FILENAME (<file>.bak.<ISO-timestamp>, colons→dashes) on Unix; "" on Windows/macOS — there is no file to back up
	Backup        string   `json:"backup"`
	Nameservers   []string `json:"nameservers"`
	SearchDomains []string `json:"search_domains"`
	Domain        *string  `json:"domain"`
	Options       []string `json:"options"`
}

// handleUpdateDNS mirrors PUT /system/dns (the converged wire, sync
// 2026-07-17): raw wins when present; Unix writes resolv.conf, Windows/macOS
// take the structured fields their tooling can honor and answer 400 naming
// anything they cannot — never a silent no-op.
//
//	@Summary		Replace the DNS configuration
//	@Description	Minimum role: operator. The converged wire (sync 2026-07-17): raw WINS when present; a body carrying neither raw nor nameservers answers 400 "Either nameservers array or raw string is required". Unix serializes the structured fields into /etc/resolv.conf (manager header, then domain, search, one nameserver per entry, options), backs the current file up beside it first (<file>.bak.<ISO-timestamp>, colons→dashes — the hosts-file precedent), and replaces atomically (0644); the answer carries the backup FILENAME plus the parsed-back view of what was written (no raw on the PUT answer). Windows applies nameservers to EVERY connected interface via netsh (static + primary/add; an empty array reverts to DHCP) — raw and search_domains/domain/options have no analog and answer 400 naming the field, and backup is "" (no file to back up, honest absence). macOS applies nameservers (and search_domains when sent) to every enabled service via networksetup — domain/options/raw answer 400, backup "". Nameservers must be literal IP addresses everywhere. Writing needs the same OS privilege editing DNS by hand would (root on Unix, Administrator on Windows) — a refusal fails honestly.
//	@Tags			Host Configuration
//	@Accept			json
//	@Produce		json
//	@Param			body	body	dnsUpdateRequest	true	"DNS configuration to apply"
//	@Success		200	{object}	dnsUpdateResponse	"DNS configuration updated"
//	@Failure		400	{object}	wrappedError	"Neither nameservers nor raw present ('Either nameservers array or raw string is required'), a non-IP nameserver, invalid token values, or a field the platform cannot honor (raw / search_domains / domain / options per the per-OS rules above — refused by name, never silently dropped)"
//	@Failure		500	{object}	wrappedError	"Failed to write DNS configuration (tool failure, backup or write failure — typically missing OS privilege)"
//	@Router			/system/dns [put]
func (s *Server) handleUpdateDNS(w http.ResponseWriter, r *http.Request) {
	var body dnsUpdateRequest
	if err := decodeBody(r, &body); err != nil {
		errorResponse(w, http.StatusBadRequest, "Failed to write DNS configuration", "Invalid JSON body")
		return
	}
	if body.Raw == nil && body.Nameservers == nil {
		// Zoneweaver's exact refusal wording — the shared wire.
		errorResponse(w, http.StatusBadRequest, "Either nameservers array or raw string is required", "")
		return
	}
	if body.Nameservers != nil {
		if verr := validateNameservers(*body.Nameservers); verr != nil {
			errorResponse(w, http.StatusBadRequest, "Failed to write DNS configuration", verr.Error())
			return
		}
	}

	switch runtime.GOOS {
	case "windows", "darwin":
		if body.Raw != nil {
			errorResponse(w, http.StatusBadRequest, "Failed to write DNS configuration",
				"raw DNS content has no "+runtime.GOOS+" analog — use the structured fields")
			return
		}
		// Structured-only subset per platform: what the tooling cannot set is
		// refused by name, never accepted-and-dropped.
		unsupported := []string{}
		if body.Domain != nil {
			unsupported = append(unsupported, "domain")
		}
		if body.Options != nil {
			unsupported = append(unsupported, "options")
		}
		if runtime.GOOS == "windows" && body.SearchDomains != nil {
			unsupported = append(unsupported, "search_domains")
		}
		if len(unsupported) > 0 {
			errorResponse(w, http.StatusBadRequest, "Failed to write DNS configuration",
				strings.Join(unsupported, ", ")+" not supported on "+runtime.GOOS+" — resolv.conf-only fields")
			return
		}
		if runtime.GOOS == "windows" {
			s.updateDNSWindows(w, r, *body.Nameservers)
			return
		}
		s.updateDNSDarwin(w, r, *body.Nameservers, body.SearchDomains)
	default:
		s.updateDNSResolvConf(w, r, body)
	}
}
