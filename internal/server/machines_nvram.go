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

// handleSecureBoot serves POST /machines/{machineName}/nvram/secureboot —
// the Secure Boot lifecycle on an EFI-firmware machine, powered off:
// optionally (re)initialize the UEFI variable store (DESTRUCTIVE — wipes
// enrolled keys and boot entries), optionally enroll the standard keys
// (Oracle platform key + Microsoft DB/KEK signatures — what stock
// Windows/shim-signed Linux validate against), then toggle enforcement.
func (s *Server) handleSecureBoot(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	body := struct {
		Enabled           bool  `json:"enabled"`
		EnrollDefaultKeys *bool `json:"enroll_default_keys"`
		InitVarStore      bool  `json:"init_var_store"`
	}{}
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
	writeJSON(w, map[string]any{
		"success":      true,
		"machine_name": machine.Name,
		"enabled":      body.Enabled,
		"steps":        steps,
		"message":      "Secure Boot configuration applied",
	})
}

// handleGuestControlRun serves POST /machines/{machineName}/guestcontrol/run
// — execute a program in a running guest through Guest Additions
// (guestcontrol run): the credentialed sibling of the QGA exec channel.
// Guest Additions take password auth ONLY; credentials default from the
// stored settings.vagrant_user family.
func (s *Server) handleGuestControlRun(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	var body struct {
		Path           string   `json:"path"`
		Args           []string `json:"args"`
		Username       string   `json:"username"`
		Password       string   `json:"password"`
		TimeoutSeconds int      `json:"timeout_seconds"`
	}
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
	writeJSON(w, map[string]any{
		"success":      true,
		"machine_name": machine.Name,
		"exit_code":    result.ExitCode,
		"stdout":       result.Stdout,
		"stderr":       result.Stderr,
	})
}
