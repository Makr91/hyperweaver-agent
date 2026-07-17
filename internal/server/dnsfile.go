package server

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/procattr"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
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

// payload spreads the view into the response envelope (domain is null when
// absent — zoneweaver's shape).
func (v *dnsView) payload() map[string]any {
	return map[string]any{
		"nameservers":    v.Nameservers,
		"search_domains": v.SearchDomains,
		"domain":         nullable(v.Domain),
		"options":        v.Options,
	}
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

// runDNSTool executes one platform DNS tool invocation (netsh/networksetup)
// with the agent's no-console spawn attributes, answering combined output —
// the tools narrate errors on stdout/stderr interchangeably.
func runDNSTool(r *http.Request, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(r.Context(), name, args...)
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s",
			name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// windowsConnectedInterfaces parses `netsh interface show interface` for the
// connected interfaces' names (columns: Admin State, State, Type, Name; the
// exact-match on "Connected" never catches "Disconnected"). Platform reality:
// netsh output is localized — non-English Windows may list nothing, which
// surfaces honestly as an empty set rather than a wrong one.
func windowsConnectedInterfaces(r *http.Request) ([]string, error) {
	out, err := runDNSTool(r, "netsh", "interface", "show", "interface")
	if err != nil {
		return nil, err
	}
	names := []string{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 4 && fields[1] == "Connected" {
			names = append(names, strings.Join(fields[3:], " "))
		}
	}
	return names, nil
}

// windowsDNSView collects the unique DNS server IPs configured (statically or
// via DHCP) across the CONNECTED interfaces from `netsh interface ipv4 show
// dnsservers`. search_domains/domain/options stay empty — DNS suffixes live
// elsewhere on Windows (the honest platform subset). raw is the netsh output.
func windowsDNSView(r *http.Request) (dnsView, string, error) {
	connected, err := windowsConnectedInterfaces(r)
	if err != nil {
		return dnsView{}, "", err
	}
	isConnected := map[string]bool{}
	for _, name := range connected {
		isConnected[name] = true
	}

	out, err := runDNSTool(r, "netsh", "interface", "ipv4", "show", "dnsservers")
	if err != nil {
		return dnsView{}, "", err
	}
	view := dnsView{Nameservers: []string{}, SearchDomains: []string{}, Options: []string{}}
	seen := map[string]bool{}
	current := ""
	for _, line := range strings.Split(out, "\n") {
		text := strings.TrimSpace(line)
		if strings.HasPrefix(text, "Configuration for interface") {
			current = ""
			if open := strings.Index(text, `"`); open >= 0 {
				if closing := strings.LastIndex(text, `"`); closing > open {
					current = text[open+1 : closing]
				}
			}
			continue
		}
		if current == "" || !isConnected[current] {
			continue
		}
		for _, field := range strings.Fields(text) {
			if net.ParseIP(field) != nil && !seen[field] {
				seen[field] = true
				view.Nameservers = append(view.Nameservers, field)
			}
		}
	}
	return view, out, nil
}

// darwinNetworkServices lists the ENABLED network services from
// `networksetup -listallnetworkservices` (the first line is the asterisk
// legend; '*'-prefixed rows are disabled services and are skipped).
func darwinNetworkServices(r *http.Request) ([]string, error) {
	out, err := runDNSTool(r, "networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, err
	}
	services := []string{}
	for i, line := range strings.Split(out, "\n") {
		text := strings.TrimSpace(line)
		if i == 0 || text == "" || strings.HasPrefix(text, "*") {
			continue
		}
		services = append(services, text)
	}
	return services, nil
}

// darwinDNSView unions `networksetup -getdnsservers` and -getsearchdomains
// across every enabled service ("There aren't any ..." answers carry spaces
// and are skipped; server lines must parse as IPs). domain/options stay empty
// — resolv.conf-only concepts. raw is the concatenated tool output.
func darwinDNSView(r *http.Request) (dnsView, string, error) {
	services, err := darwinNetworkServices(r)
	if err != nil {
		return dnsView{}, "", err
	}
	view := dnsView{Nameservers: []string{}, SearchDomains: []string{}, Options: []string{}}
	seenNS := map[string]bool{}
	seenSearch := map[string]bool{}
	var raw strings.Builder
	for _, service := range services {
		servers, serr := runDNSTool(r, "networksetup", "-getdnsservers", service)
		if serr != nil {
			return dnsView{}, "", serr
		}
		domains, derr := runDNSTool(r, "networksetup", "-getsearchdomains", service)
		if derr != nil {
			return dnsView{}, "", derr
		}
		raw.WriteString("== " + service + " ==\n" + servers + domains)
		for _, line := range strings.Split(servers, "\n") {
			text := strings.TrimSpace(line)
			if net.ParseIP(text) != nil && !seenNS[text] {
				seenNS[text] = true
				view.Nameservers = append(view.Nameservers, text)
			}
		}
		for _, line := range strings.Split(domains, "\n") {
			text := strings.TrimSpace(line)
			if text == "" || strings.Contains(text, " ") || seenSearch[text] {
				continue
			}
			seenSearch[text] = true
			view.SearchDomains = append(view.SearchDomains, text)
		}
	}
	return view, raw.String(), nil
}

// handleGetDNS mirrors GET /system/dns — zoneweaver's shipped wire (the
// converged wire, sync 2026-07-17): the standard success envelope with
// nameservers/search_domains/domain/options/raw spread top-level.
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

	payload := view.payload()
	payload["raw"] = raw
	successResponse(w, "DNS configuration retrieved successfully", payload)
}

// dnsUpdateRequest is the PUT body (zoneweaver's shape): raw wins when
// present; pointers keep JS presence semantics — an absent key and an empty
// value are different answers on this wire.
type dnsUpdateRequest struct {
	Nameservers   *[]string `json:"nameservers"`
	SearchDomains *[]string `json:"search_domains"`
	Domain        *string   `json:"domain"`
	Options       *[]string `json:"options"`
	Raw           *string   `json:"raw"`
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

// updateDNSWindows applies the nameservers to EVERY connected interface via
// netsh: `set dnsservers name=<if> static <first> primary` plus one `add
// dnsservers` per remaining entry; an empty list reverts every interface to
// DHCP. Requires the privilege netsh itself demands (Administrator) — a
// refusal fails honestly.
func (s *Server) updateDNSWindows(w http.ResponseWriter, r *http.Request, nameservers []string) {
	interfaces, err := windowsConnectedInterfaces(r)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to write DNS configuration", err.Error())
		return
	}
	for _, iface := range interfaces {
		if len(nameservers) == 0 {
			if _, derr := runDNSTool(r, "netsh", "interface", "ipv4", "set", "dnsservers",
				"name="+iface, "dhcp"); derr != nil {
				errorResponse(w, http.StatusInternalServerError, "Failed to write DNS configuration", derr.Error())
				return
			}
			continue
		}
		if _, serr := runDNSTool(r, "netsh", "interface", "ipv4", "set", "dnsservers",
			"name="+iface, "static", nameservers[0], "primary"); serr != nil {
			errorResponse(w, http.StatusInternalServerError, "Failed to write DNS configuration", serr.Error())
			return
		}
		for i, extra := range nameservers[1:] {
			if _, aerr := runDNSTool(r, "netsh", "interface", "ipv4", "add", "dnsservers",
				"name="+iface, extra, fmt.Sprintf("index=%d", i+2)); aerr != nil {
				errorResponse(w, http.StatusInternalServerError, "Failed to write DNS configuration", aerr.Error())
				return
			}
		}
	}

	slog.Info("dns configuration updated", "platform", "windows",
		"interfaces", len(interfaces), "by", auth.FromContext(r.Context()).Name)
	// backup "" — no file exists to back up on this platform (honest absence).
	applied := dnsView{
		Nameservers: nameservers, SearchDomains: []string{}, Options: []string{},
	}
	payload := applied.payload()
	payload["backup"] = ""
	successResponse(w, "DNS configuration updated successfully", payload)
}

// updateDNSDarwin applies nameservers (and search domains when sent) to every
// ENABLED network service via networksetup — the literal word "Empty" clears
// a list (the tool's own vocabulary).
func (s *Server) updateDNSDarwin(w http.ResponseWriter, r *http.Request, nameservers []string, searchDomains *[]string) {
	services, err := darwinNetworkServices(r)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to write DNS configuration", err.Error())
		return
	}
	for _, service := range services {
		nsArgs := append([]string{"-setdnsservers", service}, nameservers...)
		if len(nameservers) == 0 {
			nsArgs = append(nsArgs, "Empty")
		}
		if _, serr := runDNSTool(r, "networksetup", nsArgs...); serr != nil {
			errorResponse(w, http.StatusInternalServerError, "Failed to write DNS configuration", serr.Error())
			return
		}
		if searchDomains == nil {
			continue
		}
		searchArgs := append([]string{"-setsearchdomains", service}, (*searchDomains)...)
		if len(*searchDomains) == 0 {
			searchArgs = append(searchArgs, "Empty")
		}
		if _, derr := runDNSTool(r, "networksetup", searchArgs...); derr != nil {
			errorResponse(w, http.StatusInternalServerError, "Failed to write DNS configuration", derr.Error())
			return
		}
	}

	applied := dnsView{
		Nameservers: nameservers, SearchDomains: []string{}, Options: []string{},
	}
	if searchDomains != nil {
		applied.SearchDomains = *searchDomains
	}
	slog.Info("dns configuration updated", "platform", "darwin",
		"services", len(services), "by", auth.FromContext(r.Context()).Name)
	payload := applied.payload()
	payload["backup"] = ""
	successResponse(w, "DNS configuration updated successfully", payload)
}

// updateDNSResolvConf is the Unix path: serialize (or take raw verbatim),
// back up beside the file, atomic replace — hostsfile.go's exact mechanism,
// resolv.conf's 0644.
func (s *Server) updateDNSResolvConf(w http.ResponseWriter, r *http.Request, body dnsUpdateRequest) {
	var content string
	if body.Raw != nil {
		content = *body.Raw
	} else {
		view := dnsView{Nameservers: *body.Nameservers, SearchDomains: []string{}, Options: []string{}}
		if body.SearchDomains != nil {
			view.SearchDomains = *body.SearchDomains
		}
		if body.Domain != nil {
			view.Domain = *body.Domain
		}
		if body.Options != nil {
			view.Options = *body.Options
		}
		if verr := validateDNSTokens("search domain", view.SearchDomains); verr != nil {
			errorResponse(w, http.StatusBadRequest, "Failed to write DNS configuration", verr.Error())
			return
		}
		if verr := validateDNSTokens("option", view.Options); verr != nil {
			errorResponse(w, http.StatusBadRequest, "Failed to write DNS configuration", verr.Error())
			return
		}
		if view.Domain != "" {
			if verr := validateDNSTokens("domain", []string{view.Domain}); verr != nil {
				errorResponse(w, http.StatusBadRequest, "Failed to write DNS configuration", verr.Error())
				return
			}
		}
		content = renderResolvConf(&view)
	}

	current, err := os.ReadFile(dnsResolvConfPath)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to write DNS configuration",
			"read current file: "+err.Error())
		return
	}

	// Backup name = zoneweaver's `<file>.bak.<ISO-timestamp>` (the converged
	// wire, sync 2026-07-17) — colons swapped for dashes, the hostsfile.go
	// precedent (a literal ISO timestamp is an illegal Windows filename; the
	// shape stays identical on every platform).
	backup := dnsResolvConfPath + ".bak." + strings.ReplaceAll(
		time.Now().UTC().Format(time.RFC3339), ":", "-")
	if berr := safepath.WriteFile(backup, current, 0o644); berr != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to write DNS configuration",
			"create backup: "+berr.Error())
		return
	}
	// resolv.conf must stay world-readable — every resolver library on the
	// host reads it (0644, unlike the agent's own 0600 state files).
	if werr := safepath.WriteFile(dnsResolvConfPath, []byte(content), 0o644); werr != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to write DNS configuration", werr.Error())
		return
	}

	slog.Info("dns configuration updated", "path", dnsResolvConfPath,
		"backup", filepath.Base(backup), "by", auth.FromContext(r.Context()).Name)
	// The converged PUT answer: backup + the parsed-back view of what was
	// written (zoneweaver spreads parseResolvConf(content) — four fields, no
	// raw).
	written := parseResolvConf(content)
	payload := written.payload()
	payload["backup"] = filepath.Base(backup)
	successResponse(w, "DNS configuration updated successfully", payload)
}

// handleUpdateDNS mirrors PUT /system/dns (the converged wire, sync
// 2026-07-17): raw wins when present; Unix writes resolv.conf, Windows/macOS
// take the structured fields their tooling can honor and answer 400 naming
// anything they cannot — never a silent no-op.
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
