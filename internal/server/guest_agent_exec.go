package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/qga"
)

// guestExecStatus is guest-exec-status' answer with the base64 output fields
// decoded for the wire.
type guestExecStatus struct {
	Exited   bool   `json:"exited"`
	ExitCode *int   `json:"exitcode,omitempty"`
	Signal   *int   `json:"signal,omitempty"`
	OutData  string `json:"out-data,omitempty"`
	ErrData  string `json:"err-data,omitempty"`
}

// decodeExecStatus parses guest-exec-status and decodes its base64 halves.
func decodeExecStatus(raw json.RawMessage) (map[string]any, error) {
	var status guestExecStatus
	if err := json.Unmarshal(raw, &status); err != nil {
		return nil, err
	}
	result := map[string]any{"exited": status.Exited}
	if status.ExitCode != nil {
		result["exitcode"] = *status.ExitCode
	}
	if status.Signal != nil {
		result["signal"] = *status.Signal
	}
	if status.OutData != "" {
		if decoded, err := base64.StdEncoding.DecodeString(status.OutData); err == nil {
			result["stdout"] = string(decoded)
		}
	}
	if status.ErrData != "" {
		if decoded, err := base64.StdEncoding.DecodeString(status.ErrData); err == nil {
			result["stderr"] = string(decoded)
		}
	}
	return result, nil
}

// guestExecRequest is POST /machines/{machineName}/guest/exec's body.
type guestExecRequest struct {
	// The guest executable (absolute path; no shell)
	Path string `json:"path"`
	// Arguments passed to the executable
	Args []string `json:"args"`
	// Poll to completion (default true); false answers the pid immediately
	Wait *bool `json:"wait"`
	// Poll budget in seconds (default 30, max 600)
	TimeoutSeconds int `json:"timeout_seconds"`
}

// handleGuestExec serves POST /machines/{name}/guest/exec: run a command in
// the guest (guest-exec). wait (default true) polls guest-exec-status until
// exit or timeout_seconds (default 30, max 600); wait:false answers the pid
// for GET /machines/{name}/guest/exec/{pid}.
//
//	@Summary		Run a command in the guest
//	@Description	Minimum role: operator. guest-exec with capture-output: path is the guest executable (absolute; no shell — wrap in /bin/sh -c or cmd.exe /c yourself for shell syntax), args[] its arguments. wait (default true) polls guest-exec-status until exit or timeout_seconds (default 30, max 600) and answers {exitcode, stdout, stderr} (base64 decoded); wait:false answers {pid} immediately for GET /machines/{name}/guest/exec/{pid}. Credential-less by design — the channel itself is the authority (operator role + the machine's own host).
//	@Tags			Guest Agent
//	@Accept			json
//	@Produce		json
//	@Param			machineName	path		string				true	"Machine name"
//	@Param			request		body		guestExecRequest	true	"Command to run in the guest"
//	@Success		200			{object}	map[string]interface{}	"Exit status with decoded output (wait), the pid (wait:false), or a still-running notice past the timeout"
//	@Failure		400			{object}	taskErrorBody		"Missing path, or machine is not running"
//	@Failure		404			{object}	taskErrorBody		"Machine not found"
//	@Failure		502			{object}	taskErrorBody		"Guest agent did not answer"
//	@Failure		503			{object}	taskErrorBody		"Guest agent channel is disabled"
//	@Router			/machines/{machineName}/guest/exec [post]
func (s *Server) handleGuestExec(w http.ResponseWriter, r *http.Request) {
	var body guestExecRequest
	if err := decodeBody(r, &body); err != nil || body.Path == "" {
		taskError(w, http.StatusBadRequest, "Body needs path (the guest executable) and optional args[]")
		return
	}
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	if machine.Hypervisor == machines.HypervisorUTM {
		if body.Wait != nil && !*body.Wait {
			taskError(w, http.StatusBadRequest,
				"utmctl exec is synchronous — wait:false is not supported on utm machines")
			return
		}
		timeout := body.TimeoutSeconds
		if timeout <= 0 {
			timeout = 30
		}
		if timeout > 600 {
			timeout = 600
		}
		output, ok := s.utmGuestExec(w, r, machine, time.Duration(timeout)*time.Second,
			append([]string{body.Path}, body.Args...)...)
		if !ok {
			return
		}
		slog.Info("guest exec", "machine", machine.Name, "path", body.Path,
			"by", auth.FromContext(r.Context()).Name)
		writeJSON(w, map[string]any{
			"success":      true,
			"machine_name": machine.Name,
			"exited":       true,
			"stdout":       output,
		})
		return
	}
	result, machine := s.guestCommand(w, r, machine, "guest-exec", map[string]any{
		"path":           body.Path,
		"arg":            body.Args,
		"capture-output": true,
	}, 10*time.Second)
	if machine == nil {
		return
	}
	var started struct {
		PID int `json:"pid"`
	}
	if err := json.Unmarshal(result, &started); err != nil {
		taskError(w, http.StatusBadGateway, "Guest agent answered an unexpected exec shape")
		return
	}
	slog.Info("guest exec", "machine", machine.Name, "path", body.Path,
		"pid", started.PID, "by", auth.FromContext(r.Context()).Name)

	if body.Wait != nil && !*body.Wait {
		writeJSON(w, map[string]any{
			"success":      true,
			"machine_name": machine.Name,
			"pid":          started.PID,
			"message":      "Command started — poll GET /machines/{name}/guest/exec/" + strconv.Itoa(started.PID),
		})
		return
	}

	timeout := body.TimeoutSeconds
	if timeout <= 0 {
		timeout = 30
	}
	if timeout > 600 {
		timeout = 600
	}
	pipe, perr := s.machineQGAPipe(machine)
	if perr != nil {
		taskError(w, http.StatusInternalServerError, "Failed to resolve the guest-agent channel")
		return
	}
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	for {
		pollCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		raw, err := qga.Do(pollCtx, pipe, "guest-exec-status", map[string]any{"pid": started.PID})
		cancel()
		if err != nil {
			taskError(w, http.StatusBadGateway, "Guest agent stopped answering while waiting: "+err.Error())
			return
		}
		status, derr := decodeExecStatus(raw)
		if derr != nil {
			taskError(w, http.StatusBadGateway, "Guest agent answered an unexpected status shape")
			return
		}
		if exited, _ := status["exited"].(bool); exited {
			status["success"] = true
			status["machine_name"] = machine.Name
			status["pid"] = started.PID
			writeJSON(w, status)
			return
		}
		if time.Now().After(deadline) {
			writeJSON(w, map[string]any{
				"success":      true,
				"machine_name": machine.Name,
				"pid":          started.PID,
				"exited":       false,
				"message":      "Still running after " + strconv.Itoa(timeout) + "s — poll GET /machines/{name}/guest/exec/" + strconv.Itoa(started.PID),
			})
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(time.Second):
		}
	}
}

// handleGuestExecStatus serves GET /machines/{name}/guest/exec/{pid}.
//
//	@Summary		Poll a guest command
//	@Description	Minimum role: viewer. guest-exec-status for a pid from POST /guest/exec: {exited, exitcode?, stdout?, stderr?} — output arrives once the process exits.
//	@Tags			Guest Agent
//	@Produce		json
//	@Param			machineName	path		string					true	"Machine name"
//	@Param			pid			path		int						true	"Guest process id"
//	@Success		200			{object}	map[string]interface{}	"Process status"
//	@Failure		400			{object}	taskErrorBody			"Invalid pid, or machine is not running"
//	@Failure		404			{object}	taskErrorBody			"Machine not found"
//	@Failure		502			{object}	taskErrorBody			"Guest agent did not answer"
//	@Failure		503			{object}	taskErrorBody			"Guest agent channel is disabled"
//	@Router			/machines/{machineName}/guest/exec/{pid} [get]
func (s *Server) handleGuestExecStatus(w http.ResponseWriter, r *http.Request) {
	pid, err := strconv.Atoi(r.PathValue("pid"))
	if err != nil || pid <= 0 {
		taskError(w, http.StatusBadRequest, "Invalid pid")
		return
	}
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	if machine.Hypervisor == machines.HypervisorUTM {
		taskError(w, http.StatusBadRequest, "not supported on utm machines (utmctl exec is synchronous)")
		return
	}
	result, machine := s.guestCommand(w, r, machine, "guest-exec-status", map[string]any{"pid": pid}, 5*time.Second)
	if machine == nil {
		return
	}
	status, derr := decodeExecStatus(result)
	if derr != nil {
		taskError(w, http.StatusBadGateway, "Guest agent answered an unexpected status shape")
		return
	}
	status["machine_name"] = machine.Name
	status["pid"] = pid
	writeJSON(w, status)
}
