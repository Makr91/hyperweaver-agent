// Package config loads and provides the agent's YAML configuration.
package config

// SnapshotTierConfig is one rotation tier's keep count.
type SnapshotTierConfig struct {
	Keep int `yaml:"keep" json:"keep"`
}

// SnapshotPolicyConfig is one snapshot retention policy — the shared
// vocabulary with zoneweaver (its snapshots.default_policy and the per-zone
// configuration.snapshots override; Mark's ruling 2026-07-12: same shape on
// both agents, VBox-tuned CONSERVATIVE defaults here — VirtualBox snapshot
// creation is CoW-thin but prune is a physical merge and online snapshots
// carry RAM state).
type SnapshotPolicyConfig struct {
	// Type: none | simple (keep newest N auto-*) | age (delete auto-* older
	// than max_age_days) | rotation (hourly/daily/weekly tiers, Snapshoter.sh
	// schedule).
	Type string `yaml:"type" json:"type"`
	// Quiesce runs qga fsfreeze around each snapshot when the guest agent
	// answers (application-consistent; crash-consistent otherwise).
	Quiesce bool `yaml:"quiesce" json:"quiesce"`
	// Keep is simple's newest-N count.
	Keep int `yaml:"keep" json:"keep"`
	// MaxAgeDays is age's cutoff.
	MaxAgeDays int `yaml:"max_age_days" json:"max_age_days"`
	// Tiers are rotation's per-tier keep counts (hourly/daily/weekly).
	Tiers map[string]SnapshotTierConfig `yaml:"tiers" json:"tiers"`
}

// SnapshotsConfig controls the scheduled snapshot rotation service —
// zoneweaver's snapshots block (its Snapshoter.sh replacement) on this
// hypervisor's VBoxManage snapshot family. Per-machine override: the PUT
// /machines/{name} `snapshots` field (configuration.snapshots; type none
// disables per machine, null clears back to this default).
type SnapshotsConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// IntervalMinutes is the simple/age cadence (rotation rides the fixed
	// hourly/daily/weekly wall-clock schedule).
	IntervalMinutes int                  `yaml:"interval_minutes" json:"interval_minutes"`
	DefaultPolicy   SnapshotPolicyConfig `yaml:"default_policy"   json:"default_policy"`
}
