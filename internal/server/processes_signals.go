package server

import (
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"
)

// processSignalRequest is POST /system/processes/{pid}/signal's body.
type processSignalRequest struct {
	// TERM|KILL|HUP|INT|USR1|USR2|STOP|CONT (default TERM); Windows honors only TERM/KILL
	Signal string `json:"signal"`
}

// processSignalResponse is POST /system/processes/{pid}/signal's answer.
type processSignalResponse struct {
	Message   string `json:"message"`
	Pid       int32  `json:"pid"`
	Signal    string `json:"signal"`
	Success   bool   `json:"success"`
	Timestamp string `json:"timestamp"`
}

// handleProcessSignal mirrors POST /system/processes/{pid}/signal. Signals
// outside the platform's vocabulary answer 400 (Windows delivers only TERM
// and KILL — there are no POSIX signals to send).
//
//	@Summary		Send a signal to a process
//	@Description	Minimum role: operator. On Windows only TERM and KILL exist (delivered via TerminateProcess); other signals answer 400 — never a silent no-op.
//	@Tags			Processes
//	@Accept			json
//	@Produce		json
//	@Param			pid		path	int						true	"Process ID"
//	@Param			request	body	processSignalRequest	false	"Signal to send (defaults to TERM)"
//	@Success		200	{object}	processSignalResponse	"Signal sent"
//	@Failure		400	{object}	wrappedError			"Invalid process ID or unsupported signal"
//	@Failure		404	{object}	wrappedError			"Process not found"
//	@Failure		500	{object}	wrappedError			"Failed to send signal"
//	@Router			/system/processes/{pid}/signal [post]
func (s *Server) handleProcessSignal(w http.ResponseWriter, r *http.Request) {
	p := s.findProcess(w, r)
	if p == nil {
		return
	}
	var body processSignalRequest
	if err := decodeBody(r, &body); err != nil {
		errorResponse(w, http.StatusBadRequest, "Invalid process ID or signal", "Invalid JSON body")
		return
	}
	if body.Signal == "" {
		body.Signal = "TERM"
	}
	sig, supported := signalByName(body.Signal)
	if !supported {
		errorResponse(w, http.StatusBadRequest, "Invalid process ID or signal",
			"signal "+body.Signal+" is not supported on this platform")
		return
	}
	if err := p.SendSignalWithContext(r.Context(), sig); err != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to send signal", err.Error())
		return
	}
	writeJSON(w, processSignalResponse{
		Message:   "Signal " + body.Signal + " sent to process " + strconv.Itoa(int(p.Pid)),
		Pid:       p.Pid,
		Signal:    body.Signal,
		Success:   true,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

// processKillRequest is POST /system/processes/{pid}/kill's body.
type processKillRequest struct {
	// force=true kills immediately (SIGKILL-equivalent) instead of a graceful terminate
	Force bool `json:"force"`
}

// processKillResponse is POST /system/processes/{pid}/kill's answer.
type processKillResponse struct {
	Force     bool   `json:"force"`
	Message   string `json:"message"`
	Pid       int32  `json:"pid"`
	Success   bool   `json:"success"`
	Timestamp string `json:"timestamp"`
}

// handleProcessKill mirrors POST /system/processes/{pid}/kill: graceful
// terminate, or SIGKILL-equivalent with force=true.
//
//	@Summary		Kill a process
//	@Description	Minimum role: operator. Graceful terminate; force=true kills immediately.
//	@Tags			Processes
//	@Accept			json
//	@Produce		json
//	@Param			pid		path	int					true	"Process ID"
//	@Param			request	body	processKillRequest	false	"force=true kills immediately"
//	@Success		200	{object}	processKillResponse	"Process killed"
//	@Failure		400	{object}	wrappedError		"Invalid process ID"
//	@Failure		404	{object}	wrappedError		"Process not found"
//	@Failure		500	{object}	wrappedError		"Failed to kill process"
//	@Router			/system/processes/{pid}/kill [post]
func (s *Server) handleProcessKill(w http.ResponseWriter, r *http.Request) {
	p := s.findProcess(w, r)
	if p == nil {
		return
	}
	var body processKillRequest
	if err := decodeBody(r, &body); err != nil {
		errorResponse(w, http.StatusBadRequest, "Invalid process ID", "Invalid JSON body")
		return
	}

	var err error
	if body.Force {
		err = p.KillWithContext(r.Context())
	} else {
		err = p.TerminateWithContext(r.Context())
	}
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to kill process", err.Error())
		return
	}
	writeJSON(w, processKillResponse{
		Force:     body.Force,
		Message:   "Process " + strconv.Itoa(int(p.Pid)) + " killed successfully",
		Pid:       p.Pid,
		Success:   true,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

// batchKillRequest is POST /system/processes/batch-kill's body.
type batchKillRequest struct {
	Pattern string `json:"pattern"`
	User    string `json:"user"`
	// TERM|KILL|HUP|INT|USR1|USR2|STOP|CONT (default TERM); Windows honors only TERM/KILL
	Signal string `json:"signal"`
}

// batchKillFailure is one refused/failed target in the batch-kill answer.
type batchKillFailure struct {
	Error string `json:"error"`
	Pid   int32  `json:"pid"`
}

// batchKillResponse is POST /system/processes/batch-kill's answer.
type batchKillResponse struct {
	Errors  []batchKillFailure `json:"errors"`
	Killed  []int32            `json:"killed"`
	Message string             `json:"message"`
	Pattern string             `json:"pattern"`
	Success bool               `json:"success"`
}

// handleBatchKillProcesses mirrors POST /system/processes/batch-kill. The
// agent's own process is refused — a batch pattern must not shoot the agent.
//
//	@Summary		Signal multiple processes by pattern
//	@Description	Minimum role: operator. The agent's own process is always refused. On Windows only TERM and KILL exist.
//	@Tags			Processes
//	@Accept			json
//	@Produce		json
//	@Param			request	body	batchKillRequest	true	"Match pattern, optional user filter, and signal"
//	@Success		200	{object}	batchKillResponse	"Batch results"
//	@Failure		400	{object}	wrappedError		"Missing pattern or unsupported signal"
//	@Router			/system/processes/batch-kill [post]
func (s *Server) handleBatchKillProcesses(w http.ResponseWriter, r *http.Request) {
	var body batchKillRequest
	if err := decodeBody(r, &body); err != nil || body.Pattern == "" {
		errorResponse(w, http.StatusBadRequest, "Missing pattern parameter", "")
		return
	}
	compiled, err := regexp.Compile(body.Pattern)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, "Missing pattern parameter",
			"invalid pattern: "+err.Error())
		return
	}
	if body.Signal == "" {
		body.Signal = "TERM"
	}
	sig, supported := signalByName(body.Signal)
	if !supported {
		errorResponse(w, http.StatusBadRequest, "Missing pattern parameter",
			"signal "+body.Signal+" is not supported on this platform")
		return
	}

	matched, err := matchProcesses(r.Context(), body.User, compiled)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to kill processes", err.Error())
		return
	}

	// int32→int widens (never narrows), so the comparison needs no
	// overflow-prone conversion of the OS pid.
	self := os.Getpid()
	killed := []int32{}
	failures := []batchKillFailure{}
	for _, p := range matched {
		if int(p.Pid) == self {
			failures = append(failures, batchKillFailure{
				Error: "refusing to signal the agent's own process",
				Pid:   p.Pid,
			})
			continue
		}
		if serr := p.SendSignalWithContext(r.Context(), sig); serr != nil {
			failures = append(failures, batchKillFailure{Error: serr.Error(), Pid: p.Pid})
			continue
		}
		killed = append(killed, p.Pid)
	}

	writeJSON(w, batchKillResponse{
		Errors: failures,
		Killed: killed,
		Message: fmt.Sprintf("Signal %s sent to %d process(es), %d failed",
			body.Signal, len(killed), len(failures)),
		Pattern: body.Pattern,
		Success: true,
	})
}
