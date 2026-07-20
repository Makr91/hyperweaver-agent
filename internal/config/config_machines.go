// Package config loads and provides the agent's YAML configuration.
package config

// ResourceThresholdsConfig are the warn/critical utilization percentages a
// validator annotates (warnings never block; the hard checks do).
type ResourceThresholdsConfig struct {
	Warning  float64 `yaml:"warning"  json:"warning"`
	Critical float64 `yaml:"critical" json:"critical"`
}

// ResourceCheckConfig is one validator's knobs (the base's
// zones.resource_validation.storage/memory blocks). Strategy: "committed"
// projects against the sum of every machine's CONFIGURED allocation;
// "actual" checks against the host's current free amount.
type ResourceCheckConfig struct {
	Enabled    bool                     `yaml:"enabled"    json:"enabled"`
	Strategy   string                   `yaml:"strategy"   json:"strategy"`
	Thresholds ResourceThresholdsConfig `yaml:"thresholds" json:"thresholds"`
}

// CPUValidationConfig adds the overcommit hard limit (vCPUs may legitimately
// exceed physical cores — the limit is a percentage of them).
type CPUValidationConfig struct {
	Enabled    bool                     `yaml:"enabled"    json:"enabled"`
	Strategy   string                   `yaml:"strategy"   json:"strategy"`
	HardLimit  float64                  `yaml:"hard_limit" json:"hard_limit"`
	Thresholds ResourceThresholdsConfig `yaml:"thresholds" json:"thresholds"`
}

// ResourceValidationConfig gates the pre-flight resource checks on create,
// clone, and modify (the base's zones.resource_validation, VirtualBox terms:
// disk free where the media land, host RAM, CPU overcommit). Failing checks
// answer 400 {error: "Insufficient resources", details[]}; passing checks may
// still annotate resource_warnings[].
type ResourceValidationConfig struct {
	Enabled bool                `yaml:"enabled" json:"enabled"`
	Storage ResourceCheckConfig `yaml:"storage" json:"storage"`
	Memory  ResourceCheckConfig `yaml:"memory"  json:"memory"`
	CPU     CPUValidationConfig `yaml:"cpu"     json:"cpu"`
}

// OrchestrationConfig controls ordered machine startup/shutdown (the base's
// zones.orchestration): machines carry settings.boot_priority (1-100, default
// 95, the base's zonecfg attr in this agent's spec vocabulary); at agent
// startup, autostart machines boot highest-priority first; at agent exit
// (keep_running_on_exit false) machines stop lowest-first.
type OrchestrationConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Strategy shapes the shutdown/test plan: sequential |
	// parallel_by_priority | staggered.
	Strategy string `yaml:"strategy" json:"strategy"`
	// PriorityDelay is seconds between priority groups (staggered strategy,
	// and the test plan's duration estimate).
	PriorityDelay int `yaml:"priority_delay" json:"priority_delay"`
}

// MachinesConfig controls the machine registry (the Node agent's zones.*
// discovery knobs).
type MachinesConfig struct {
	// AutoDiscovery enables the periodic discover tasks (Node:
	// zones.auto_discovery). The startup discovery task always runs.
	AutoDiscovery bool `yaml:"auto_discovery" json:"auto_discovery"`
	// DiscoveryInterval is seconds between periodic discover tasks (Node:
	// zones.discovery_interval). Discovery reconciles the registry against
	// VirtualBox and vagrant — external-shutdown detection included.
	DiscoveryInterval int `yaml:"discovery_interval" json:"discovery_interval"`
	// ServerIDStart is the lowest auto-assigned server_id (Node:
	// zones.server_id_start).
	ServerIDStart int `yaml:"server_id_start" json:"server_id_start"`
	// PrefixMachineNames derives created machines' names as
	// <server_id>--<hostname>.<domain> when no explicit name is given
	// (zoneweaver's prefix_zone_names — Mark's partition-id convention).
	// Explicit names always win: machine names stay free-form (design D-G).
	PrefixMachineNames bool `yaml:"prefix_machine_names" json:"prefix_machine_names"`
	// ShutdownTimeout is how many seconds a graceful stop waits for the
	// guest to power off after the ACPI signal before forcing poweroff
	// (Node: zones.orchestration.timeouts.zone_shutdown).
	ShutdownTimeout int `yaml:"shutdown_timeout" json:"shutdown_timeout"`
	// KeepRunningOnExit keeps provisioned machines running when the agent
	// exits (SHI's keepserversrunning, default true). false force-powers-off
	// every spec-carrying machine at shutdown — machines discovered from
	// VirtualBox are never touched.
	KeepRunningOnExit bool `yaml:"keep_running_on_exit" json:"keep_running_on_exit"`
	// ResourceValidation are the pre-flight resource checks on
	// create/clone/modify.
	ResourceValidation ResourceValidationConfig `yaml:"resource_validation" json:"resource_validation"`
	// Orchestration is ordered startup/shutdown by settings.boot_priority.
	Orchestration OrchestrationConfig `yaml:"orchestration" json:"orchestration"`
	// ProvisionOnStart makes a machine's VERY FIRST start (a stored
	// provisioner document, never provisioned) run the full provision
	// pipeline instead of a bare boot — SHI's dormant provisionserversonstart
	// preference, Mark's semantics 2026-07-07. Later starts, document-less
	// machines, restarts, and provision-chain boot children are never
	// affected. Default false.
	ProvisionOnStart bool `yaml:"provision_on_start" json:"provision_on_start"`
}

// GuestAgentConfig gates the QEMU guest-agent channel (the `guest-agent`
// capability token — Mark's go 2026-07-10): the MASTER gate over the
// per-machine UART option (zones.guest_agent at create, the PUT toggle, the
// setup endpoint) and the /machines/{name}/guest/* surface — credential-less
// live IPs, exec, clean shutdown with no SSH and no Guest Additions.
type GuestAgentConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}
