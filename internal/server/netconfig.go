package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/hostname"
	"github.com/Makr91/hyperweaver-agent/internal/procattr"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// Host network configuration (/network/hostname, /network/addresses — the
// converged wire, sync 2026-07-17): zoneweaver's shipped
// NetworkQueryController/NetworkModificationController family, mirrored on
// this agent. The controller family answers BARE documents — no
// success/message/timestamp envelope; errors are {error} or {error, details}
// (taskError's shape, with an optional details field).

// netconfigError writes this controller family's error shape:
// {error, details?} — zoneweaver's exact wire.
func netconfigError(w http.ResponseWriter, status int, errText, details string) {
	payload := map[string]string{"error": errText}
	if details != "" {
		payload["details"] = details
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		slog.Error("write netconfig error response", "error", err)
	}
}

// persistedHostname reads the platform's PERSISTED/configured host name —
// zoneweaver's /etc/nodename read, per-OS here. ok=false means no persisted
// source exists or it is unreadable (the wire answers nodename_file: null).
//   - Linux: /etc/hostname content, trimmed.
//   - Windows: the PENDING computer name from the registry via `reg query`
//     (a Rename-Computer awaiting reboot shows here before os.Hostname does;
//     exec keeps this file cross-platform — no build-tagged registry import).
//   - macOS: `scutil --get HostName` (unset → no persisted name).
func persistedHostname(r *http.Request) (string, bool) {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.CommandContext(r.Context(), "reg", "query",
			`HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`,
			"/v", "ComputerName")
		cmd.SysProcAttr = procattr.NoConsole()
		out, err := cmd.Output()
		if err != nil {
			return "", false
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) >= 3 && fields[0] == "ComputerName" && fields[1] == "REG_SZ" {
				return strings.Join(fields[2:], " "), true
			}
		}
		return "", false
	case "darwin":
		cmd := exec.CommandContext(r.Context(), "scutil", "--get", "HostName")
		cmd.SysProcAttr = procattr.NoConsole()
		out, err := cmd.Output()
		if err != nil {
			return "", false
		}
		name := strings.TrimSpace(string(out))
		return name, name != ""
	default:
		raw, err := os.ReadFile("/etc/hostname")
		if err != nil {
			return "", false
		}
		name := strings.TrimSpace(string(raw))
		return name, name != ""
	}
}

// hostnameState is the bare GET /network/hostname document — no
// success/message/timestamp envelope (this controller family's shape).
type hostnameState struct {
	// The live system hostname
	Hostname string `json:"hostname"`
	// The persisted/configured name (per-OS source above); null when no persisted source exists
	NodenameFile *string `json:"nodename_file"`
	// The live system hostname again (zoneweaver's shape)
	SystemHostname string `json:"system_hostname"`
	// persisted == live (case-insensitive on Windows; true when nothing is persisted)
	Matches bool `json:"matches"`
	// Mismatch narration (Windows: the pending-rename phrasing); null when consistent
	Warning *string `json:"warning"`
}

// handleGetHostname mirrors GET /network/hostname (zoneweaver's shipped
// wire, sync 2026-07-17): the BARE document {hostname, nodename_file,
// system_hostname, matches, warning}. hostname is the SYSTEM hostname
// (zoneweaver's semantics); nodename_file is null when no persisted name
// exists; warning is null when consistent.
//
//	@Summary		Read the host's hostname state
//	@Description	Minimum role: viewer (the hostname capability token). Zoneweaver's shipped network-controller wire (the converged wire, sync 2026-07-17): a BARE document — NO success/message/timestamp envelope; errors on this controller family are {error, details?}. hostname and system_hostname both carry the LIVE system hostname (zoneweaver's semantics). nodename_file is the PERSISTED/configured name — zoneweaver's /etc/nodename read, per-OS here: /etc/hostname content on Linux, the registry's pending ComputerName on Windows (a Rename-Computer awaiting reboot shows here before the live name changes), scutil --get HostName on macOS — null when no persisted source exists or it is unreadable. matches compares persisted against live (case-insensitively on Windows — computer names are case-insensitive; true when nothing persisted exists to compare) and warning narrates a mismatch (Windows gets the pending-rename phrasing) or stays null.
//	@Tags			Host Configuration
//	@Produce		json
//	@Success		200	{object}	hostnameState	"Hostname state (bare document)"
//	@Failure		500	"Failed to get hostname"
//	@Router			/network/hostname [get]
func (s *Server) handleGetHostname(w http.ResponseWriter, r *http.Request) {
	system, err := os.Hostname()
	if err != nil {
		netconfigError(w, http.StatusInternalServerError, "Failed to get hostname", err.Error())
		return
	}

	persisted, ok := persistedHostname(r)
	matches := true
	if ok {
		matches = persisted == system
		if runtime.GOOS == "windows" {
			// Windows computer names are case-insensitive.
			matches = strings.EqualFold(persisted, system)
		}
	}

	var warning *string
	if !matches {
		text := "The persisted host name " + persisted + " does not match the live system hostname " + system
		if runtime.GOOS == "windows" {
			text = "Computer rename to " + persisted + " is pending — the live hostname stays " + system + " until the next reboot"
		}
		warning = &text
	}
	var nodenameFile *string
	if ok {
		nodenameFile = &persisted
	}
	writeJSON(w, hostnameState{
		Hostname:       system,
		NodenameFile:   nodenameFile,
		SystemHostname: system,
		Matches:        matches,
		Warning:        warning,
	})
}

// Zoneweaver's overall hostname shape gate (its exact regex): alphanumeric
// edges, hyphens and dots inside, 253 characters at most. The per-label
// checks below refine it with their own messages.
var hostnameShapePattern = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-.]{0,251}[a-zA-Z0-9])?$`)

// validateHostnameRequest applies zoneweaver's exact staged validation and
// answers its exact message for the first failed stage ("" = valid).
func validateHostnameRequest(name string) string {
	if !hostnameShapePattern.MatchString(name) {
		return "Invalid hostname format. Must be alphanumeric with hyphens and dots, 1-253 characters"
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return "Invalid hostname format. Each part between dots must be 1-63 characters"
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "Invalid hostname format. Each part must start and end with alphanumeric characters"
		}
	}
	return ""
}

// hostnameUpdateRequest is the PUT body. Hostname is a pointer so a missing
// key and a non-string both land on zoneweaver's "required" refusal.
type hostnameUpdateRequest struct {
	// The new hostname — RFC-1123 label(s), dots allowed, 253 characters at most
	Hostname *string `json:"hostname"`
	// Ask for a live apply. Linux/macOS apply live inherently; Windows cannot (reboot semantics) and narrates that in the task output
	ApplyImmediately bool `json:"apply_immediately"`
}

// hostnameChangeQueued is the 202 answer to PUT /network/hostname — the
// converged task body.
type hostnameChangeQueued struct {
	Success          bool   `json:"success"`
	Message          string `json:"message"`
	TaskID           string `json:"task_id"`
	Hostname         string `json:"hostname"`
	ApplyImmediately bool   `json:"apply_immediately"`
	// true on Windows only — the rename lands at the next reboot; false on Linux/macOS (live apply)
	RequiresReboot bool `json:"requires_reboot"`
	// Why a reboot is needed ("" when none is)
	RebootReason string `json:"reboot_reason"`
	// The platform's apply_immediately semantics, narrated
	Note string `json:"note"`
}

// handleSetHostname mirrors PUT /network/hostname (zoneweaver's shipped
// wire, sync 2026-07-17): queue the async set_hostname task (MachineName
// "system", HIGH priority — zoneweaver's choice) and answer 202 with the
// converged body. requires_reboot is PER-PLATFORM honest (the sync ruling:
// "surface requires_restart honestly where the OS demands it"): Windows
// renames land at reboot; Linux/macOS apply live.
//
//	@Summary		Change the host's hostname (task)
//	@Description	Minimum role: operator. Queues the async set_hostname task (machine_name "system", HIGH priority — zoneweaver's exact op name and choice; the converged wire, sync 2026-07-17) and answers 202 with the converged body. Validation is zoneweaver's exact staged gate with its exact messages: the overall shape first (alphanumeric edges, hyphens and dots inside, 1-253 characters), then per label (1-63 characters between dots; alphanumeric start and end). The task applies through the platform's own tooling: Linux hostnamectl set-hostname (persists AND applies live; without hostnamectl the agent writes /etc/hostname and runs hostname(1) — the same end state), macOS scutil --set HostName + LocalHostName (sanitized single label — Bonjour allows one RFC-1123 label) + ComputerName (all three converge, live), Windows PowerShell Rename-Computer -Force — the rename lands at the NEXT REBOOT. requires_reboot is PER-PLATFORM honest (Mark's ruling: surface it honestly where the OS demands it): true on Windows (reboot_reason names why; apply_immediately cannot take effect there — the task output narrates that, never a silent drop), false on Linux/macOS where the apply is live. note narrates the platform's apply_immediately semantics either way.
//	@Tags			Host Configuration
//	@Accept			json
//	@Produce		json
//	@Param			request	body	hostnameUpdateRequest	true	"The new hostname and apply mode"
//	@Success		202	{object}	hostnameChangeQueued	"Hostname change task created"
//	@Failure		400	"Zoneweaver's exact refusals, {error} shape: "hostname is required and must be a string" (missing/non-string hostname or an unparseable body), "Invalid hostname format. Must be alphanumeric with hyphens and dots, 1-253 characters", "Invalid hostname format. Each part between dots must be 1-63 characters", or "Invalid hostname format. Each part must start and end with alphanumeric characters""
//	@Failure		500	"Failed to create hostname change task"
//	@Router			/network/hostname [put]
func (s *Server) handleSetHostname(w http.ResponseWriter, r *http.Request) {
	var body hostnameUpdateRequest
	if err := decodeBody(r, &body); err != nil || body.Hostname == nil {
		netconfigError(w, http.StatusBadRequest, "hostname is required and must be a string", "")
		return
	}
	name := *body.Hostname
	if problem := validateHostnameRequest(name); problem != "" {
		netconfigError(w, http.StatusBadRequest, problem, "")
		return
	}

	metadata, err := hostname.MetadataJSON(hostname.Metadata{
		Hostname:         name,
		ApplyImmediately: body.ApplyImmediately,
	})
	if err != nil {
		netconfigError(w, http.StatusInternalServerError, "Failed to create hostname change task", err.Error())
		return
	}
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: "system",
		Operation:   hostname.Op,
		Priority:    tasks.PriorityHigh,
		CreatedBy:   auth.FromContext(r.Context()).Name,
		Metadata:    metadata,
	})
	if err != nil {
		slog.Error("queue set_hostname", "hostname", name, "error", err)
		netconfigError(w, http.StatusInternalServerError, "Failed to create hostname change task", err.Error())
		return
	}
	slog.Info("hostname change queued", "hostname", name,
		"apply_immediately", body.ApplyImmediately, "by", auth.FromContext(r.Context()).Name)

	requiresReboot := runtime.GOOS == "windows"
	rebootReason := ""
	note := "apply_immediately applies the new hostname live on " + runtime.GOOS
	if requiresReboot {
		rebootReason = "Windows applies a computer rename at the next reboot"
		note = "apply_immediately cannot take effect on Windows — the rename lands at the next reboot"
	}
	writeJSONStatus(w, http.StatusAccepted, hostnameChangeQueued{
		Success:          true,
		Message:          "Hostname change task created for: " + name,
		TaskID:           task.ID,
		Hostname:         name,
		ApplyImmediately: body.ApplyImmediately,
		RequiresReboot:   requiresReboot,
		RebootReason:     rebootReason,
		Note:             note,
	})
}
