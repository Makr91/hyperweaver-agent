package machines

import (
	"encoding/json"
	"strings"
)

// STARTcloud ansible progress adoption — the callback-plugin contract
// (Provisioner AI, 2026-07-09, replacing the retired per-role progress role):
// the packages' startcloud_progress callback prints one machine-readable
// line per completed role:
//
//	PROGRESS::{"completed": N, "total": T, "percent": P,
//	           "running": "<fqcn|null>", "index": I, "done": <bool>,
//	           "label": "<Role>"}
//
// 100% (done: true) fires only at play end. That stdout is the ONLY channel
// the guest's progress reaches the agent. progressScanner watches the
// playbook's streamed output for the marker and reports each payload; the
// executor maps them into the task's progress_info.
const progressMarker = "PROGRESS::"

// progressPayload is the callback's JSON document.
type progressPayload struct {
	Percent float64 `json:"percent"`
	Done    bool    `json:"done"`
	Label   string  `json:"label"`
	Running *string `json:"running"`
}

// progressScanner line-buffers a task's streamed stdout and fires report for
// every callback marker line. Chunks arrive at arbitrary boundaries (SSH
// stream), so a partial trailing line waits for its remainder.
type progressScanner struct {
	buf    strings.Builder
	report func(percent int, description string)
}

func newProgressScanner(report func(percent int, description string)) *progressScanner {
	return &progressScanner{report: report}
}

// Scan consumes one output chunk. Only stdout carries ansible's callback
// rendering; stderr never holds progress lines.
func (s *progressScanner) Scan(stream, data string) {
	if stream != "stdout" {
		return
	}
	s.buf.WriteString(data)
	text := s.buf.String()
	for {
		newline := strings.IndexByte(text, '\n')
		if newline < 0 {
			break
		}
		s.scanLine(text[:newline])
		text = text[newline+1:]
	}
	// Newline-less streams (progress-bar style output) must not grow the
	// buffer unboundedly — keep a tail comfortably larger than any marker
	// payload; a line that long is never a progress line anyway.
	if len(text) > 64*1024 {
		text = text[len(text)-4096:]
	}
	s.buf.Reset()
	s.buf.WriteString(text)
}

// scanLine matches one complete line: everything after the marker is the
// callback's JSON (trimmed to its closing brace in case the surrounding
// renderer appended a tail).
func (s *progressScanner) scanLine(line string) {
	start := strings.Index(line, progressMarker)
	if start < 0 {
		return
	}
	payload := line[start+len(progressMarker):]
	if end := strings.LastIndexByte(payload, '}'); end >= 0 {
		payload = payload[:end+1]
	}
	var progress progressPayload
	if err := json.Unmarshal([]byte(payload), &progress); err != nil {
		return
	}
	if progress.Percent < 0 || progress.Percent > 100 {
		return
	}
	description := strings.TrimSpace(progress.Label)
	if description == "" && progress.Running != nil {
		description = *progress.Running
	}
	if progress.Done && description == "" {
		description = "completed"
	}
	if description == "" {
		return
	}
	s.report(int(progress.Percent+0.5), description)
}
