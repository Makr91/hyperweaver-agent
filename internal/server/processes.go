package server

import (
	"context"
	"net/http"
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

// processInfo is one process listing entry (GET /system/processes item and
// GET /system/processes/{pid}). Every optional field is a pointer so a failed
// gopsutil probe OMITS its key rather than emitting a zero value (the map
// response this replaced added keys only when the probe succeeded).
// detailed=false leaves the statistics block nil; open_files_sample is set
// only on the single-process detail read.
type processInfo struct {
	Command string `json:"command"`
	// detailed=true only
	CPUPercent *float64 `json:"cpu_percent,omitempty"`
	// Consumed CPU time in seconds (detailed=true only)
	CPUTime       *int64   `json:"cpu_time,omitempty"`
	MemoryPercent *float64 `json:"memory_percent,omitempty"`
	// Detail read only: up to 10 open file paths ([] on platforms where per-process file enumeration is unsupported)
	OpenFilesSample *[]string `json:"open_files_sample,omitempty"`
	Pid             int32     `json:"pid"`
	Ppid            *int32    `json:"ppid,omitempty"`
	// Resident size in KB
	RSS       *uint64 `json:"rss,omitempty"`
	StartTime *string `json:"start_time,omitempty"`
	State     *string `json:"state,omitempty"`
	Username  *string `json:"username,omitempty"`
	// Virtual size in KB
	VSZ *uint64 `json:"vsz,omitempty"`
}

// processRow builds one process listing entry. detailed adds the CPU and
// memory statistics (the Node agent's detailed=true ps auxww columns).
func processRow(p *process.Process, detailed bool) processInfo {
	row := processInfo{Pid: p.Pid}
	if ppid, err := p.Ppid(); err == nil {
		row.Ppid = &ppid
	}
	if username, err := p.Username(); err == nil {
		row.Username = &username
	}
	command, cerr := p.Cmdline()
	if cerr != nil || command == "" {
		if name, nerr := p.Name(); nerr == nil {
			command = name
		}
	}
	row.Command = command

	if !detailed {
		return row
	}
	if cpuPct, err := p.CPUPercent(); err == nil {
		v := round2(cpuPct)
		row.CPUPercent = &v
	}
	if memPct, err := p.MemoryPercent(); err == nil {
		v := round2(float64(memPct))
		row.MemoryPercent = &v
	}
	if info, err := p.MemoryInfo(); err == nil && info != nil {
		vsz := info.VMS / 1024
		rss := info.RSS / 1024
		row.VSZ = &vsz
		row.RSS = &rss
	}
	if status, err := p.Status(); err == nil {
		st := strings.Join(status, "")
		row.State = &st
	}
	if createdMs, err := p.CreateTime(); err == nil {
		t := time.UnixMilli(createdMs).UTC().Format(time.RFC3339)
		row.StartTime = &t
	}
	if times, err := p.Times(); err == nil && times != nil {
		ct := int64(times.User + times.System)
		row.CPUTime = &ct
	}
	return row
}

func round2(v float64) float64 {
	return float64(int(v*100+0.5)) / 100
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
//
//	@Summary		List processes
//	@Description	Minimum role: viewer. Bare array response. detailed=true adds CPU/memory statistics (process-lifetime CPU percentage — instant, no sampling wait).
//	@Tags			Processes
//	@Produce		json
//	@Param			user		query	string	false	"Filter by username"
//	@Param			command		query	string	false	"Filter by command pattern (regex)"
//	@Param			detailed	query	bool	false	"Add CPU and memory statistics"	default(false)
//	@Param			limit		query	int		false	"Maximum rows to return"		minimum(1)	maximum(1000)	default(100)
//	@Success		200	{array}		processInfo		"Processes"
//	@Failure		400	{object}	wrappedError	"Invalid command pattern"
//	@Router			/system/processes [get]
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

	rows := make([]processInfo, 0, len(matched))
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
//
//	@Summary		Process details
//	@Description	Minimum role: viewer. Detailed statistics plus a sample of open files (empty on platforms where per-process file enumeration is unsupported).
//	@Tags			Processes
//	@Produce		json
//	@Param			pid	path	int	true	"Process ID"
//	@Success		200	{object}	processInfo		"Process details"
//	@Failure		400	{object}	wrappedError	"Invalid process ID"
//	@Failure		404	{object}	wrappedError	"Process not found"
//	@Router			/system/processes/{pid} [get]
func (s *Server) handleProcessDetails(w http.ResponseWriter, r *http.Request) {
	p := s.findProcess(w, r)
	if p == nil {
		return
	}
	row := processRow(p, true)
	sample := []string{}
	if files, err := p.OpenFilesWithContext(r.Context()); err == nil {
		for i, f := range files {
			if i >= 10 {
				break
			}
			sample = append(sample, f.Path)
		}
	}
	row.OpenFilesSample = &sample
	writeJSON(w, row)
}

// processOpenFile is one entry in GET /system/processes/{pid}/files.
type processOpenFile struct {
	Description string `json:"description"`
	Fd          uint64 `json:"fd"`
}

// handleProcessFiles mirrors GET /system/processes/{pid}/files. Platforms
// where gopsutil cannot enumerate per-process files degrade to an empty
// list rather than failing the endpoint.
//
//	@Summary		Open files for a process
//	@Description	Minimum role: viewer. Degrades to an empty list on platforms where gopsutil cannot enumerate per-process files (Windows).
//	@Tags			Processes
//	@Produce		json
//	@Param			pid	path	int	true	"Process ID"
//	@Success		200	{array}		processOpenFile	"Open files"
//	@Failure		404	{object}	wrappedError	"Process not found"
//	@Router			/system/processes/{pid}/files [get]
func (s *Server) handleProcessFiles(w http.ResponseWriter, r *http.Request) {
	p := s.findProcess(w, r)
	if p == nil {
		return
	}
	entries := []processOpenFile{}
	if files, err := p.OpenFilesWithContext(r.Context()); err == nil {
		for _, f := range files {
			entries = append(entries, processOpenFile{
				Description: f.Path,
				Fd:          f.Fd,
			})
		}
	}
	writeJSON(w, entries)
}

// findProcessesResponse is GET /system/processes/find's answer.
type findProcessesResponse struct {
	Count   int     `json:"count"`
	Pattern string  `json:"pattern"`
	Pids    []int32 `json:"pids"`
}

// handleFindProcesses mirrors GET /system/processes/find.
//
//	@Summary		Find processes by pattern
//	@Description	Minimum role: viewer.
//	@Tags			Processes
//	@Produce		json
//	@Param			pattern	query	string	true	"Command pattern (regex)"
//	@Param			user	query	string	false	"Filter by username"
//	@Success		200	{object}	findProcessesResponse	"Matching process IDs"
//	@Failure		400	{object}	wrappedError			"Missing or invalid pattern"
//	@Router			/system/processes/find [get]
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
	writeJSON(w, findProcessesResponse{
		Count:   len(pids),
		Pattern: pattern,
		Pids:    pids,
	})
}

// processStatRow is one row in GET /system/processes/stats (the prstat view).
type processStatRow struct {
	Command    string  `json:"command"`
	CPUPercent float64 `json:"cpu_percent"`
	Pid        int32   `json:"pid"`
	// Resident set size in bytes
	RSS uint64 `json:"rss"`
	// Virtual size in bytes
	Size     uint64 `json:"size"`
	Username string `json:"username"`
}

// handleProcessStats mirrors GET /system/processes/stats (the prstat view):
// processes ranked by CPU usage. One instant sample — gopsutil's process
// CPU percentage is computed over the process lifetime, no sampling wait.
//
//	@Summary		Process statistics (top by CPU)
//	@Description	Minimum role: viewer. Processes ranked by CPU usage (top 30) — one instant sample.
//	@Tags			Processes
//	@Produce		json
//	@Success		200	{array}	processStatRow	"Process statistics"
//	@Router			/system/processes/stats [get]
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
		vszBytes uint64
		rssBytes uint64
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
			row.vszBytes = info.VMS
			row.rssBytes = info.RSS
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

	out := make([]processStatRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, processStatRow{
			Command:    row.command,
			CPUPercent: round2(row.cpuPct),
			Pid:        row.pid,
			RSS:        row.rssBytes,
			Size:       row.vszBytes,
			Username:   row.username,
		})
	}
	writeJSON(w, out)
}
