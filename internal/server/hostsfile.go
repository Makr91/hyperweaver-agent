package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// Hosts-file endpoints (/system/hosts — the Node agent's Host Configuration
// group): read and replace the system hosts file on all three platforms, so
// the platform can point names at its virtual machines (Mark's ruling,
// 2026-07-05: "take control of the /etc/hosts file on mac, windows and
// linux"). A timestamped backup lands beside the file before every write.
// The /system/dns counterpart lives in dnsfile.go (the converged wire, sync
// 2026-07-17): same wire on every platform, per-OS mechanics.

// hostsFilePath returns the platform hosts file location.
func hostsFilePath() string {
	if runtime.GOOS == "windows" {
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		return filepath.Join(root, "System32", "drivers", "etc", "hosts")
	}
	return "/etc/hosts"
}

// hostsEntry is one parsed hosts line.
type hostsEntry struct {
	IP        string   `json:"ip"`
	Hostnames []string `json:"hostnames"`
}

// parseHostsFile extracts the address entries (comments and blanks are
// carried only by the raw view).
func parseHostsFile(raw string) []hostsEntry {
	entries := []hostsEntry{}
	for _, line := range strings.Split(raw, "\n") {
		text := strings.TrimSpace(line)
		if comment := strings.Index(text, "#"); comment >= 0 {
			text = strings.TrimSpace(text[:comment])
		}
		if text == "" {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) < 2 {
			continue
		}
		entries = append(entries, hostsEntry{IP: fields[0], Hostnames: fields[1:]})
	}
	return entries
}

type hostsFileResponse struct {
	Success   bool         `json:"success"`
	Message   string       `json:"message"`
	Timestamp string       `json:"timestamp"`
	Entries   []hostsEntry `json:"entries"`
	Raw       string       `json:"raw"`
	Path      string       `json:"path"`
}

// handleGetHostsFile mirrors GET /system/hosts — zoneweaver's shipped wire
// (Mark's ruling 2026-07-17: Go matches zoneweaver here): the standard
// success envelope with entries/raw/path spread top-level.
//
//	@Summary		Read the system hosts file
//	@Description	Minimum role: viewer. Parses the platform hosts file (Windows System32\drivers\etc\hosts, /etc/hosts elsewhere) into structured entries plus the raw content, wrapped in the standard success envelope (the converged wire, Mark's ruling 2026-07-17 — both agents answer identically). entries carries only the parsed address lines; comments and blank lines live only in raw.
//	@Tags			Host Configuration
//	@Produce		json
//	@Success		200	{object}	hostsFileResponse	"Hosts file"
//	@Failure		500	{object}	wrappedError	"Failed to read hosts file"
//	@Router			/system/hosts [get]
func (s *Server) handleGetHostsFile(w http.ResponseWriter, _ *http.Request) {
	path := hostsFilePath()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to read hosts file", err.Error())
		return
	}
	writeJSON(w, hostsFileResponse{
		Success:   true,
		Message:   "Hosts file retrieved successfully",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Entries:   parseHostsFile(string(raw)),
		Raw:       string(raw),
		Path:      path,
	})
}

// hostsUpdateRequest is the PUT body: structured entries, or raw content
// (raw wins).
type hostsUpdateRequest struct {
	Entries []hostsEntry `json:"entries"`
	// Raw file content (takes precedence over entries)
	Raw *string `json:"raw"`
}

// renderHostsFile serializes structured entries into hosts-file text.
func renderHostsFile(entries []hostsEntry) string {
	var b strings.Builder
	b.WriteString("# Managed by hyperweaver-agent (" +
		time.Now().UTC().Format(time.RFC3339) + ")\n")
	for _, entry := range entries {
		b.WriteString(entry.IP)
		b.WriteString("\t")
		b.WriteString(strings.Join(entry.Hostnames, " "))
		b.WriteString("\n")
	}
	return b.String()
}

type hostsUpdateResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
	// The backup FILENAME (not a path), shaped <file>.bak.<ISO-timestamp>; on Windows the timestamp's colons become dashes (colons are illegal in NTFS filenames)
	Backup  string `json:"backup"`
	Entries int    `json:"entries"`
}

// handleUpdateHostsFile mirrors PUT /system/hosts: timestamped backup beside
// the file, then an atomic replace. Writing the file requires the same
// privilege editing it by hand would (Administrator on Windows, root on
// Unix) — a permission refusal fails honestly.
//
//	@Summary		Replace the system hosts file
//	@Description	Minimum role: operator. Provide structured entries or raw content (raw wins when both are present; entries validate per field — no whitespace or # inside an ip or hostname). A timestamped backup lands beside the file before the atomic replace, and the answer carries its filename (the converged wire, Mark's ruling 2026-07-17 — no path field). Writing needs the same OS privilege editing the file by hand would (Administrator on Windows, root on Unix) — a refusal fails honestly.
//	@Tags			Host Configuration
//	@Accept			json
//	@Produce		json
//	@Param			body	body	hostsUpdateRequest	true	"Structured entries or raw content (raw wins)"
//	@Success		200	{object}	hostsUpdateResponse	"Hosts file updated"
//	@Failure		400	{object}	wrappedError	"Invalid body or entry values"
//	@Failure		500	{object}	wrappedError	"Backup or write failure (typically missing OS privilege)"
//	@Router			/system/hosts [put]
func (s *Server) handleUpdateHostsFile(w http.ResponseWriter, r *http.Request) {
	var body hostsUpdateRequest
	if err := decodeBody(r, &body); err != nil {
		errorResponse(w, http.StatusBadRequest, "Failed to write hosts file", "Invalid JSON body")
		return
	}

	var content string
	switch {
	case body.Raw != nil:
		content = *body.Raw
	case body.Entries != nil:
		for _, entry := range body.Entries {
			if entry.IP == "" || len(entry.Hostnames) == 0 {
				errorResponse(w, http.StatusBadRequest, "Failed to write hosts file",
					"every entry needs an ip and at least one hostname")
				return
			}
			for _, field := range append([]string{entry.IP}, entry.Hostnames...) {
				if strings.ContainsAny(field, " \t\r\n#") {
					errorResponse(w, http.StatusBadRequest, "Failed to write hosts file",
						fmt.Sprintf("invalid value %q: whitespace and # are not allowed", field))
					return
				}
			}
		}
		content = renderHostsFile(body.Entries)
	default:
		errorResponse(w, http.StatusBadRequest, "Failed to write hosts file",
			"provide entries or raw")
		return
	}

	path := hostsFilePath()
	current, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to write hosts file",
			"read current file: "+err.Error())
		return
	}

	// Backup name = zoneweaver's `<file>.bak.<ISO-timestamp>` (the converged
	// wire, Mark's ruling 2026-07-17) — colons swapped for dashes because a
	// literal ISO timestamp is an illegal Windows filename; the shape (.bak.
	// prefix + timestamp) is what the wire promises.
	backup := path + ".bak." + strings.ReplaceAll(
		time.Now().UTC().Format(time.RFC3339), ":", "-")
	if berr := safepath.WriteFile(backup, current, 0o644); berr != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to write hosts file",
			"create backup: "+berr.Error())
		return
	}
	// The hosts file must stay world-readable — every resolver on the
	// machine reads it (0644, unlike the agent's own 0600 state files).
	// Internal robustness (atomic temp-rename write, entry validation above)
	// stays — the ruling converged the WIRE only.
	if werr := safepath.WriteFile(path, []byte(content), 0o644); werr != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to write hosts file", werr.Error())
		return
	}

	slog.Info("hosts file updated", "path", path, "backup", filepath.Base(backup),
		"by", auth.FromContext(r.Context()).Name)
	// The converged PUT answer carries backup + entries only — no path
	// (zoneweaver's shipped shape; Mark: Go matches zoneweaver).
	writeJSON(w, hostsUpdateResponse{
		Success:   true,
		Message:   "Hosts file updated successfully",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Backup:    filepath.Base(backup),
		Entries:   len(parseHostsFile(content)),
	})
}
