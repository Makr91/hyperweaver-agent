// Package config loads and provides the agent's YAML configuration.
package config

// MonitoringConfig controls the host telemetry surface (/monitoring/*, the
// `monitoring` capability token — the Node agent's host_monitoring block,
// reshaped per Mark's 2026-07-05 ruling): the endpoints always serve REALTIME
// samples; enabling storage adds a background collector writing time series
// into per-datatype database files (monitoring-cpu.sqlite,
// monitoring-memory.sqlite, monitoring-network.sqlite) so telemetry write
// churn never contends with the main databases — the single-file IO
// contention zoneweaver hits.
type MonitoringConfig struct {
	// StorageEnabled turns the background collector on. Off (default) means
	// realtime-only: every request samples the OS live, history queries
	// return just the current sample.
	StorageEnabled bool `yaml:"storage_enabled" json:"storage_enabled"`
	// CollectionInterval is seconds between collector samples.
	CollectionInterval int `yaml:"collection_interval" json:"collection_interval"`
	// RetentionDays: stored samples older than this are deleted by the
	// periodic cleanup.
	RetentionDays int `yaml:"retention_days" json:"retention_days"`
}

// HostPowerConfig gates the host power-management surface (/system/host/*,
// the `host-power` capability token): remote shutdown/restart of the machine
// the agent runs on — half the point of a headless datacenter host, an
// obvious kill-switch candidate on a desktop.
type HostPowerConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// PreventSleep keeps the host awake while the agent runs (SHI's
	// preventsystemfromsleep, default false) using each OS's native
	// power-management API — SetThreadExecutionState / IOKit power assertion /
	// systemd-logind inhibitor. System sleep only; the display may still
	// sleep and lock.
	PreventSleep bool `yaml:"prevent_sleep" json:"prevent_sleep"`
}
