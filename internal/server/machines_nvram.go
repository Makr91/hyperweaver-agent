package server

// UEFI NVRAM / Secure Boot (modifynvram) + Guest Additions exec
// (guestcontrol run) — Mark's verb-survey go 2026-07-12.

import (
	"log/slog"
	"net/http"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

type secureBootRequest struct {
	Enabled bool `json:"enabled"`
	// Enroll Oracle PK + Microsoft signatures (default: the enabled value)
	EnrollDefaultKeys *bool `json:"enroll_default_keys"`
	// DESTRUCTIVE: recreate the UEFI variable store first
	InitVarStore bool `json:"init_var_store"`
}

type secureBootResponse struct {
	Success     bool     `json:"success"`
	MachineName string   `json:"machine_name"`
	Enabled     bool     `json:"enabled"`
	Steps       []string `json:"steps"`
	Message     string   `json:"message"`
}

// handleSecureBoot serves POST /machines/{machineName}/nvram/secureboot —
// the Secure Boot lifecycle on an EFI-firmware machine, powered off:
// optionally (re)initialize the UEFI variable store (DESTRUCTIVE — wipes
// enrolled keys and boot entries), optionally enroll the standard keys
// (Oracle platform key + Microsoft DB/KEK signatures — what stock
// Windows/shim-signed Linux validate against), then toggle enforcement.
//
//	@Summary		Configure UEFI Secure Boot
//	@Description	Minimum role: operator. The Secure Boot lifecycle on an EFI-firmware machine (bootrom efi), POWERED OFF, synchronous modifynvram sequence: optional init_var_store (DESTRUCTIVE — recreates the UEFI variable store, wiping enrolled keys and firmware boot entries; needed once on machines whose store never existed), then — when enrolling (enroll_default_keys, defaults to the enabled value) — Oracle's platform key + Microsoft's DB/KEK signatures (what stock Windows and shim-signed Linux distros validate against), then the secureboot enable/disable toggle. UI story: a Secure Boot toggle with an 'enroll standard keys' checkbox; a BIOS-firmware machine answers VirtualBox's own error — switch bootrom to efi first.
//	@Tags			Machine Management
//	@Accept			json
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Param			request	body	secureBootRequest	true	"Secure Boot configuration"
//	@Success		200	{object}	secureBootResponse	"Applied ({success, machine_name, enabled, steps[], message})"
//	@Failure		400	{object}	taskErrorBody	"Machine is not powered off"
//	@Failure		404	{object}	taskErrorBody	"Machine not found"
//	@Failure		500	{object}	taskErrorBody	"A modifynvram step failed (BIOS firmware, missing var store, ...)"
//	@Failure		503	{object}	taskErrorBody	"VirtualBox is not installed"
//	@Router			/machines/{machineName}/nvram/secureboot [post]
func (s *Server) handleSecureBoot(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	var body secureBootRequest
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	enroll := body.Enabled
	if body.EnrollDefaultKeys != nil {
		enroll = *body.EnrollDefaultKeys
	}
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}
	switch liveMachineStatus(r.Context(), machine) {
	case machines.StatusStopped, machines.StatusAborted, machines.StatusConfigured:
	default:
		taskError(w, http.StatusBadRequest, "Machine must be powered off for NVRAM changes")
		return
	}

	target := machine.VBoxTarget()
	steps := []string{}
	if body.InitVarStore {
		if err := vbox.InitUEFIVarStore(r.Context(), exe, target); err != nil {
			taskError(w, http.StatusInternalServerError, "inituefivarstore failed: "+err.Error())
			return
		}
		steps = append(steps, "init_var_store")
	}
	if enroll {
		if err := vbox.EnrollOraclePK(r.Context(), exe, target); err != nil {
			taskError(w, http.StatusInternalServerError,
				"enrollorclpk failed: "+err.Error()+" (EFI firmware required — set bootrom efi; init_var_store creates a missing store)")
			return
		}
		if err := vbox.EnrollMSSignatures(r.Context(), exe, target); err != nil {
			taskError(w, http.StatusInternalServerError, "enrollmssignatures failed: "+err.Error())
			return
		}
		steps = append(steps, "enroll_default_keys")
	}
	if err := vbox.SetSecureBoot(r.Context(), exe, target, body.Enabled); err != nil {
		taskError(w, http.StatusInternalServerError, "secureboot toggle failed: "+err.Error())
		return
	}
	steps = append(steps, "secureboot")

	slog.Info("secure boot configured", "machine", machine.Name, "enabled", body.Enabled,
		"by", auth.FromContext(r.Context()).Name)
	writeJSON(w, secureBootResponse{
		Success:     true,
		MachineName: machine.Name,
		Enabled:     body.Enabled,
		Steps:       steps,
		Message:     "Secure Boot configuration applied",
	})
}

type guestControlRunRequest struct {
	Path           string   `json:"path"`
	Args           []string `json:"args"`
	Username       string   `json:"username"`
	Password       string   `json:"password"`
	TimeoutSeconds int      `json:"timeout_seconds"`
}

type guestControlRunResponse struct {
	Success     bool   `json:"success"`
	MachineName string `json:"machine_name"`
	ExitCode    int    `json:"exit_code"`
	Stdout      string `json:"stdout"`
	Stderr      string `json:"stderr"`
}

// handleGuestControlRun serves POST /machines/{machineName}/guestcontrol/run
// — execute a program in a running guest through Guest Additions
// (guestcontrol run): the credentialed sibling of the QGA exec channel.
// Guest Additions take password auth ONLY; credentials default from the
// stored settings.vagrant_user family.
//
//	@Summary		Run a command via Guest Additions
//	@Description	Minimum role: operator. Synchronous guestcontrol run against the RUNNING guest — the credentialed sibling of the QGA exec channel (use /guest/exec when qemu-ga is wired; this one needs Guest Additions running in the guest). path is the guest executable (absolute); args pass after VBoxManage's -- separator (some guests want the program name repeated as the first argument — VirtualBox quirk). Credentials: Guest Additions take PASSWORD auth only — body username/password, defaulting from the stored settings.vagrant_user family; no password anywhere answers 400. timeout_seconds bounds the guest process (default 60, max 3600). exit_code is VBoxManage's own — guest exit codes ride through for plain runs.
//	@Tags			Machine Management
//	@Accept			json
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Param			request	body	guestControlRunRequest	true	"Guest command and credentials"
//	@Success		200	{object}	guestControlRunResponse	"Run finished ({success, machine_name, exit_code, stdout, stderr})"
//	@Failure		400	{object}	taskErrorBody	"Missing path, no password available, or machine not running"
//	@Failure		404	{object}	taskErrorBody	"Machine not found"
//	@Failure		502	{object}	taskErrorBody	"guestcontrol failed to start (Guest Additions absent?)"
//	@Failure		503	{object}	taskErrorBody	"VirtualBox is not installed"
//	@Router			/machines/{machineName}/guestcontrol/run [post]
func (s *Server) handleGuestControlRun(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	var body guestControlRunRequest
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.Path == "" {
		taskError(w, http.StatusBadRequest, "path is required (the guest executable)")
		return
	}
	if body.Username == "" || body.Password == "" {
		credentials := machines.ExtractCredentials(machines.ParseConfiguration(machine).Section("settings"))
		if body.Username == "" {
			body.Username = credentials.Username
		}
		if body.Password == "" {
			body.Password = credentials.Password
		}
	}
	if body.Username == "" || body.Password == "" {
		taskError(w, http.StatusBadRequest,
			"Guest Additions exec needs username AND password (key auth has no analog) — send them or store settings.vagrant_user/vagrant_user_pass")
		return
	}
	if body.TimeoutSeconds <= 0 {
		body.TimeoutSeconds = 60
	}
	if body.TimeoutSeconds > 3600 {
		body.TimeoutSeconds = 3600
	}
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}
	if liveMachineStatus(r.Context(), machine) != machines.StatusRunning {
		taskError(w, http.StatusBadRequest, "Machine is not running")
		return
	}

	result, err := vbox.GuestControlRun(r.Context(), exe, machine.VBoxTarget(),
		body.Username, body.Password, body.Path, body.Args, body.TimeoutSeconds*1000)
	if err != nil {
		slog.Error("guestcontrol run", "machine", machine.Name, "error", err)
		taskError(w, http.StatusBadGateway, "guestcontrol run failed: "+err.Error())
		return
	}
	writeJSON(w, guestControlRunResponse{
		Success:     true,
		MachineName: machine.Name,
		ExitCode:    result.ExitCode,
		Stdout:      result.Stdout,
		Stderr:      result.Stderr,
	})
}
