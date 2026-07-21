package server

var schemaApplications = map[string]any{
	"description":      "External launcher applications (GET /applications, the host-launchers token): user-chosen desktop tools (PuTTY, WinSCP, mstsc, ...) the agent launches on its own host against a machine — SHI's per-server app buttons generalized (the UI's per-machine launch menu, POST /machines/{name}/applications/{appName}/launch). Each entry: {name, path, args[]}. args placeholders {host}/{port}/{user}/{password} resolve per machine through the SSH transport ladder and stored credentials, {machine} is the machine name; substitution is per-argument (no quoting). A missing executable is refused, never spawned. Direct-mode desktop contract; a headless service opens them on the service host's desktop",
	"requires_restart": true,
	"type":             "array",
	"items":            "object",
	"default":          []map[string]any{},
}

var schemaTicketSystem = map[string]any{
	"description":      "Help & Support link in the UI's profile dropdown (BoxVault's ticket_system pattern; served publicly at GET /api/config/ticket)",
	"requires_restart": true,
	"properties": map[string]any{
		"enabled": map[string]any{
			"type":        "boolean",
			"description": "Enable the ticket/support link (renders only when base_url is also set)",
			"default":     true,
		},
		"base_url": map[string]any{
			"type":        "string",
			"description": "Base URL for the ticket system",
			"default":     "https://xd.prominic.net/app/apprequest.nsf/router?openagent",
		},
		"req_type": map[string]any{
			"type":        "string",
			"description": "Default request type parameter",
			"default":     "sso",
		},
		"context": map[string]any{
			"type":        "string",
			"description": "Context URL for the ticket system (usually the repository URL)",
			"default":     "https://github.com/Makr91/hyperweaver-agent",
		},
	},
}

var schemaCleanup = map[string]any{
	"description":      "Periodic cleanup service configuration",
	"requires_restart": true,
	"properties": map[string]any{
		"interval": map[string]any{
			"type":        "integer",
			"description": "Cleanup cycle interval in seconds (task retention runs on it)",
			"default":     300,
			"min":         60,
			"max":         86400,
		},
	},
}

var schemaMonitoring = map[string]any{
	"description":      "Host telemetry configuration (/monitoring endpoints always serve realtime samples; storage adds history)",
	"requires_restart": true,
	"properties": map[string]any{
		"storage_enabled": map[string]any{
			"type":        "boolean",
			"description": "Store telemetry time series in per-datatype database files (monitoring-cpu/-memory/-network.sqlite) for history charts; off = realtime samples only",
			"default":     false,
		},
		"collection_interval": map[string]any{
			"type":        "integer",
			"description": "Seconds between collector samples (when storage is enabled)",
			"default":     60,
			"min":         5,
			"max":         3600,
		},
		"retention_days": map[string]any{
			"type":        "integer",
			"description": "Stored samples older than this many days are deleted by the periodic cleanup",
			"default":     7,
			"min":         1,
			"max":         365,
		},
	},
}

var schemaHostPower = map[string]any{
	"description":      "Host power management (/system/host endpoints, the host-power capability token, and sleep prevention)",
	"requires_restart": true,
	"properties": map[string]any{
		"enabled": map[string]any{
			"type":        "boolean",
			"description": "Serve the host power endpoints: status/uptime plus admin-only shutdown, restart, poweroff, and halt of the machine this agent runs on",
			"default":     true,
		},
		"prevent_sleep": map[string]any{
			"type":        "boolean",
			"description": "Keep the host awake while the agent runs, via the OS's native power-management API (SetThreadExecutionState / IOKit power assertion / systemd-logind inhibitor); system sleep only — the display may still sleep and lock (SHI's preventsystemfromsleep)",
			"default":     false,
		},
	},
}
