package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/process"
)

// Host process endpoints (/system/processes, the `processes` capability
// token — architecture roadmap item 15, Mark's ruling 2026-07-05): the Node
// agent's Processes group spoken in gopsutil instead of illumos ps/pgrep.
// The zone concept does not exist on this host: the `zone` field is absent
// and the `?zone=` filter is accepted and ignored. Deliberately absent —
// documented, never stubbed: /{pid}/stack and /{pid}/limits (pstack/plimit
// are illumos tools with no cross-platform analog) and trace/start (DTrace).

// processRow builds one process listing entry. detailed adds the CPU and
// memory statistics (the Node agent's detailed=true ps auxww columns).
func processRow(p *process.Process, detailed bool) map[string]any {
	row := map[string]any{"pid": p.Pid}
	if ppid, err := p.Ppid(); err == nil {
		row["ppid"] = ppid
	}
	if username, err := p.Username(); err == nil {
		row["username"] = username
	}
	command, cerr := p.Cmdline()
	if cerr != nil || command == "" {
		if name, nerr := p.Name(); nerr == nil {
			command = name
		}
	}
	row["command"] = command

	if !detailed {
		return row
	}
	if cpuPct, err := p.CPUPercent(); err == nil {
		row["cpu_percent"] = round2(cpuPct)
	}
	if memPct, err := p.MemoryPercent(); err == nil {
		row["memory_percent"] = round2(float64(memPct))
	}
	if info, err := p.MemoryInfo(); err == nil && info != nil {
		row["vsz"] = info.VMS / 1024
		row["rss"] = info.RSS / 1024
	}
	if status, err := p.Status(); err == nil {
		row["state"] = strings.Join(status, "")
	}
	if createdMs, err := p.CreateTime(); err == nil {
		row["start_time"] = time.UnixMilli(createdMs).UTC().Format(time.RFC3339)
	}
	if times, err := p.Times(); err == nil && times != nil {
		row["cpu_time"] = formatCPUTime(times.User + times.System)
	}
	return row
}

func round2(v float64) float64 {
	return float64(int(v*100+0.5)) / 100
}

// formatCPUTime renders consumed CPU seconds as H:MM:SS (the ps TIME column).
func formatCPUTime(seconds float64) string {
	total := int64(seconds)
	return fmt.Sprintf("%d:%02d:%02d", total/3600, (total%3600)/60, total%60)
}

// matchProcesses lists processes passing the user/command filters.
func matchProcesses(ctx context.Context, user string, command *regexp.Regexp) ([]*process.Process, error) {
	all, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, err
	}
	matched := make([]*process.Process, 0, len(all))
	for _, p := range all {
		if user != "" {
			username, uerr := p.Username()
			if uerr != nil || !strings.EqualFold(username, user) {
				continue
			}
		}
		if command != nil {
			line, cerr := p.Cmdline()
			if cerr != nil || line == "" {
				if name, nerr := p.Name(); nerr == nil {
					line = name
				}
			}
			if !command.MatchString(line) {
				continue
			}
		}
		matched = append(matched, p)
	}
	return matched, nil
}

// handleListProcesses mirrors GET /system/processes: bare array response,
// user/command filters, detailed statistics on request.
func (s *Server) handleListProcesses(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	detailed := query.Get("detailed") == "true"
	limit := 100
	if raw := query.Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 1 && parsed <= 1000 {
			limit = parsed
		}
	}

	var command *regexp.Regexp
	if pattern := query.Get("command"); pattern != "" {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			errorResponse(w, http.StatusBadRequest, "Failed to retrieve processes",
				"invalid command pattern: "+err.Error())
			return
		}
		command = compiled
	}

	matched, err := matchProcesses(r.Context(), query.Get("user"), command)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to retrieve processes", err.Error())
		return
	}
	if len(matched) > limit {
		matched = matched[:limit]
	}

	rows := make([]map[string]any, 0, len(matched))
	for _, p := range matched {
		rows = append(rows, processRow(p, detailed))
	}
	writeJSON(w, rows)
}

// findProcess resolves the {pid} path value, answering the Node agent's
// 400/404 split.
func (s *Server) findProcess(w http.ResponseWriter, r *http.Request) *process.Process {
	pid, err := strconv.ParseInt(r.PathValue("pid"), 10, 32)
	if err != nil || pid <= 0 {
		errorResponse(w, http.StatusBadRequest, "Invalid process ID", "")
		return nil
	}
	p, err := process.NewProcessWithContext(r.Context(), int32(pid))
	if err != nil {
		errorResponse(w, http.StatusNotFound, "Process not found", "")
		return nil
	}
	return p
}

// handleProcessDetails mirrors GET /system/processes/{pid}.
func (s *Server) handleProcessDetails(w http.ResponseWriter, r *http.Request) {
	p := s.findProcess(w, r)
	if p == nil {
		return
	}
	row := processRow(p, true)
	sample := ""
	if files, err := p.OpenFilesWithContext(r.Context()); err == nil {
		paths := make([]string, 0, len(files))
		for i, f := range files {
			if i >= 10 {
				break
			}
			paths = append(paths, f.Path)
		}
		sample = strings.Join(paths, "\n")
	}
	row["open_files_sample"] = sample
	writeJSON(w, row)
}

// handleProcessSignal mirrors POST /system/processes/{pid}/signal. Signals
// outside the platform's vocabulary answer 400 (Windows delivers only TERM
// and KILL — there are no POSIX signals to send).
func (s *Server) handleProcessSignal(w http.ResponseWriter, r *http.Request) {
	p := s.findProcess(w, r)
	if p == nil {
		return
	}
	var body struct {
		Signal string `json:"signal"`
	}
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
	successResponse(w, "Signal "+body.Signal+" sent to process "+strconv.Itoa(int(p.Pid)), map[string]any{
		"pid":    p.Pid,
		"signal": body.Signal,
	})
}

// handleProcessKill mirrors POST /system/processes/{pid}/kill: graceful
// terminate, or SIGKILL-equivalent with force=true.
func (s *Server) handleProcessKill(w http.ResponseWriter, r *http.Request) {
	p := s.findProcess(w, r)
	if p == nil {
		return
	}
	var body struct {
		Force bool `json:"force"`
	}
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
	successResponse(w, "Process "+strconv.Itoa(int(p.Pid))+" killed successfully", map[string]any{
		"pid":   p.Pid,
		"force": body.Force,
	})
}

// handleProcessFiles mirrors GET /system/processes/{pid}/files. Platforms
// where gopsutil cannot enumerate per-process files degrade to an empty
// list rather than failing the endpoint.
func (s *Server) handleProcessFiles(w http.ResponseWriter, r *http.Request) {
	p := s.findProcess(w, r)
	if p == nil {
		return
	}
	entries := []map[string]any{}
	if files, err := p.OpenFilesWithContext(r.Context()); err == nil {
		for _, f := range files {
			entries = append(entries, map[string]any{
				"fd":          f.Fd,
				"description": f.Path,
			})
		}
	}
	writeJSON(w, entries)
}

// handleFindProcesses mirrors GET /system/processes/find.
func (s *Server) handleFindProcesses(w http.ResponseWriter, r *http.Request) {
	pattern := r.URL.Query().Get("pattern")
	if pattern == "" {
		errorResponse(w, http.StatusBadRequest, "Missing pattern parameter", "")
		return
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, "Missing pattern parameter",
			"invalid pattern: "+err.Error())
		return
	}

	matched, err := matchProcesses(r.Context(), r.URL.Query().Get("user"), compiled)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to find processes", err.Error())
		return
	}
	pids := make([]int32, 0, len(matched))
	for _, p := range matched {
		pids = append(pids, p.Pid)
	}
	writeJSON(w, map[string]any{
		"pattern": pattern,
		"pids":    pids,
		"count":   len(pids),
	})
}

// handleBatchKillProcesses mirrors POST /system/processes/batch-kill. The
// agent's own process is refused — a batch pattern must not shoot the agent.
func (s *Server) handleBatchKillProcesses(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Pattern string `json:"pattern"`
		User    string `json:"user"`
		Signal  string `json:"signal"`
	}
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
	failures := []map[string]any{}
	for _, p := range matched {
		if int(p.Pid) == self {
			failures = append(failures, map[string]any{
				"pid":   p.Pid,
				"error": "refusing to signal the agent's own process",
			})
			continue
		}
		if serr := p.SendSignalWithContext(r.Context(), sig); serr != nil {
			failures = append(failures, map[string]any{"pid": p.Pid, "error": serr.Error()})
			continue
		}
		killed = append(killed, p.Pid)
	}

	writeJSON(w, map[string]any{
		"success": true,
		"pattern": body.Pattern,
		"killed":  killed,
		"errors":  failures,
		"message": fmt.Sprintf("Signal %s sent to %d process(es), %d failed",
			body.Signal, len(killed), len(failures)),
	})
}

// handleProcessStats mirrors GET /system/processes/stats (the prstat view):
// processes ranked by CPU usage. One instant sample — gopsutil's process
// CPU percentage is computed over the process lifetime, no sampling wait.
func (s *Server) handleProcessStats(w http.ResponseWriter, r *http.Request) {
	matched, err := matchProcesses(r.Context(), "", nil)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to retrieve process statistics", err.Error())
		return
	}

	type statRow struct {
		pid      int32
		username string
		cpuPct   float64
		vszKB    uint64
		rssKB    uint64
		command  string
	}
	rows := make([]statRow, 0, len(matched))
	for _, p := range matched {
		row := statRow{pid: p.Pid}
		if cpuPct, cerr := p.CPUPercent(); cerr == nil {
			row.cpuPct = cpuPct
		}
		if username, uerr := p.Username(); uerr == nil {
			row.username = username
		}
		if info, merr := p.MemoryInfo(); merr == nil && info != nil {
			row.vszKB = info.VMS / 1024
			row.rssKB = info.RSS / 1024
		}
		if name, nerr := p.Name(); nerr == nil {
			row.command = name
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].cpuPct > rows[j].cpuPct })
	if len(rows) > 30 {
		rows = rows[:30]
	}

	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{
			"pid":         row.pid,
			"username":    row.username,
			"cpu_percent": round2(row.cpuPct),
			"size":        formatKB(row.vszKB),
			"rss":         formatKB(row.rssKB),
			"command":     row.command,
		})
	}
	writeJSON(w, out)
}

// formatKB renders a kilobyte count the prstat way (K/M/G suffix).
func formatKB(kb uint64) string {
	switch {
	case kb >= 1024*1024:
		return fmt.Sprintf("%.1fG", float64(kb)/(1024*1024))
	case kb >= 1024:
		return fmt.Sprintf("%.1fM", float64(kb)/1024)
	default:
		return fmt.Sprintf("%dK", kb)
	}
}
