// Package config loads and provides the agent's YAML configuration.
package config

// TaskOutputConfig controls task output buffering and persistence (the Node
// agent's provisioning.task_output block).
type TaskOutputConfig struct {
	Enabled              bool   `yaml:"enabled"                json:"enabled"`
	Mode                 string `yaml:"mode"                   json:"mode"`
	CircularMaxLines     int    `yaml:"circular_max_lines"     json:"circular_max_lines"`
	FlushIntervalSeconds int    `yaml:"flush_interval_seconds" json:"flush_interval_seconds"`
	PersistLogFile       bool   `yaml:"persist_log_file"       json:"persist_log_file"`
	// LogDirectory receives per-task log files; empty means
	// <config dir>/logs/tasks.
	LogDirectory string `yaml:"log_directory" json:"log_directory"`
}

// TasksConfig controls the task queue (the Node agent's zones.* task knobs +
// provisioning.task_output, regrouped under one section).
type TasksConfig struct {
	// PollIntervalSeconds is the queue tick (the Node agent hardcodes 2).
	PollIntervalSeconds int `yaml:"poll_interval_seconds" json:"poll_interval_seconds"`
	// MaxConcurrent caps simultaneously running tasks (Node:
	// zones.max_concurrent_tasks).
	MaxConcurrent int `yaml:"max_concurrent" json:"max_concurrent"`
	// DefaultPaginationLimit is GET /tasks' default limit (Node:
	// zones.default_pagination_limit).
	DefaultPaginationLimit int `yaml:"default_pagination_limit" json:"default_pagination_limit"`
	// RetentionDays: finished tasks older than this are deleted by the
	// periodic cleanup (Node: host_monitoring.retention.tasks).
	RetentionDays int `yaml:"retention_days" json:"retention_days"`
	// ResumePendingOnStart keeps pending tasks across an agent restart (the
	// resumable queue). Default false: pending rows from a previous run are
	// CANCELLED at boot — the base's startup clear (Mark's ruling 2026-07-07:
	// yesterday's queued stop must never fire on today's start).
	ResumePendingOnStart bool             `yaml:"resume_pending_on_start" json:"resume_pending_on_start"`
	Output               TaskOutputConfig `yaml:"output"                  json:"output"`
}
