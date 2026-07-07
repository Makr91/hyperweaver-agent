package server

// settingsSchema describes this agent's configuration sections: types,
// descriptions, defaults, ranges, and restart requirements (the Node agent's
// /settings/schema shape).
var settingsSchema = map[string]any{
	"server": map[string]any{
		"description":      "HTTP/HTTPS server configuration",
		"requires_restart": true,
		"properties": map[string]any{
			"bind_address": map[string]any{
				"type":        "string",
				"description": "Address the web server binds to (keep 127.0.0.1 for local-only access)",
				"default":     "127.0.0.1",
			},
			"port": map[string]any{
				"type":        "integer",
				"description": "HTTP server port",
				"default":     9420,
				"min":         1,
				"max":         65535,
			},
			"https_port": map[string]any{
				"type":        "integer",
				"description": "HTTPS server port (bound only when ssl.enabled)",
				"default":     9421,
				"min":         1,
				"max":         65535,
			},
		},
	},
	"ssl": map[string]any{
		"description":      "SSL/TLS certificate configuration",
		"requires_restart": true,
		"properties": map[string]any{
			"enabled": map[string]any{
				"type":        "boolean",
				"description": "Enable HTTPS on server.https_port (certificate problems leave the agent HTTP-only, never down)",
				"default":     true,
			},
			"force_secure": map[string]any{
				"type":        "boolean",
				"description": "With SSL enabled, the plain-HTTP port serves only redirects to HTTPS; false keeps it serving the full app alongside HTTPS (for clients that cannot follow redirects)",
				"default":     true,
			},
			"generate_ssl": map[string]any{
				"type":        "boolean",
				"description": "Auto-generate the server certificate when none exists, signed by the CA (generated too when absent)",
				"default":     true,
			},
			"key_path": map[string]any{
				"type":        "string",
				"description": "Path to the server SSL private key file (empty = <config dir>/ssl/server.key)",
				"default":     "",
			},
			"cert_path": map[string]any{
				"type":        "string",
				"description": "Path to the server SSL certificate file (empty = <config dir>/ssl/server.crt)",
				"default":     "",
			},
			"ca_cert_path": map[string]any{
				"type":        "string",
				"description": "CA certificate that signs the generated server certificate — provide your own CA here (empty = <config dir>/ssl/ca.crt)",
				"default":     "",
			},
			"ca_key_path": map[string]any{
				"type":        "string",
				"description": "CA private key (empty = <config dir>/ssl/ca.key)",
				"default":     "",
			},
		},
	},
	"cors": map[string]any{
		"description":      "Cross-Origin Resource Sharing configuration",
		"requires_restart": true,
		"properties": map[string]any{
			"allow_all": map[string]any{
				"type":        "boolean",
				"description": "Answer any browser Origin (the API key is the access boundary); false falls back to the whitelist",
				"default":     true,
			},
			"whitelist": map[string]any{
				"type":        "array",
				"items":       "string",
				"description": "Allowed origins for CORS requests when allow_all is false",
				"default":     []string{},
			},
		},
	},
	"ui": map[string]any{
		"description":      "Hyperweaver UI serving configuration",
		"requires_restart": true,
		"properties": map[string]any{
			"enabled": map[string]any{
				"type":        "boolean",
				"description": "Serve the Hyperweaver UI at /ui/",
				"default":     true,
			},
			"path": map[string]any{
				"type":        "string",
				"description": "Serve the UI from this directory instead of the embedded copy (empty = embedded)",
				"default":     "",
			},
		},
	},
	"browser": map[string]any{
		"description":      "Browser launching (tray Open and the startup open; desktop mode only)",
		"requires_restart": false,
		"properties": map[string]any{
			"path": map[string]any{
				"type":        "string",
				"description": "Browser executable (or macOS .app) the tray Open action and the startup open launch (empty = system default)",
				"default":     "",
			},
			"open_on_start": map[string]any{
				"type":        "boolean",
				"description": "Open the signed-in UI in the browser when the desktop agent starts (ignored in headless mode)",
				"default":     true,
			},
		},
	},
	"logging": map[string]any{
		"description":      "Application logging configuration",
		"requires_restart": true,
		"properties": map[string]any{
			"level": map[string]any{
				"type":        "string",
				"description": "Log level",
				"default":     "info",
				"enum":        []string{"error", "warn", "info", "debug"},
			},
			"console": map[string]any{
				"type":        "boolean",
				"description": "Also log human-readable output to the console",
				"default":     true,
			},
			"file": map[string]any{
				"type":        "string",
				"description": "Log file location (empty = <config dir>/logs/agent.log)",
				"default":     "",
			},
			"max_size_mb": map[string]any{
				"type":        "integer",
				"description": "Maximum log file size in MB before rotation",
				"default":     20,
				"min":         1,
			},
			"max_backups": map[string]any{
				"type":        "integer",
				"description": "Number of rotated log files to keep",
				"default":     5,
				"min":         0,
			},
			"compression": map[string]any{
				"type":        "boolean",
				"description": "Gzip rotated log files",
				"default":     true,
			},
			"categories": map[string]any{
				"type":        "object",
				"description": "Per-category log levels overriding the global level (map of category name to level)",
				// A free-form map, not fixed fields: keys are category names,
				// values are levels. The vocabularies the editor needs:
				"keys":   []string{"app", "api_requests", "auth", "tasks", "machines", "monitoring", "provisioning", "assets"},
				"values": []string{"error", "warn", "info", "debug"},
			},
		},
	},
	"api_keys": map[string]any{
		"description":      "API key authentication configuration",
		"requires_restart": false,
		"properties": map[string]any{
			"bootstrap_enabled": map[string]any{
				"type":        "boolean",
				"description": "Enable bootstrap key generation endpoint",
				"default":     true,
			},
			"bootstrap_auto_disable": map[string]any{
				"type":        "boolean",
				"description": "Auto-disable bootstrap after the first key exists",
				"default":     true,
			},
			"bootstrap_require_claim_token": map[string]any{
				"type":        "boolean",
				"description": "Require the setup (claim) token as proof of host ownership",
				"default":     true,
			},
			"key_length": map[string]any{
				"type":        "integer",
				"description": "Random byte length for API key generation",
				"default":     64,
				"min":         16,
				"max":         256,
			},
			"hash_rounds": map[string]any{
				"type":        "integer",
				"description": "bcrypt hash rounds for API key storage",
				"default":     12,
				"min":         4,
				"max":         20,
			},
		},
	},
	"updates": map[string]any{
		"description":      "Application update checking configuration",
		"requires_restart": false,
		"properties": map[string]any{
			"versioninfo_url": map[string]any{
				"type":        "string",
				"description": "URL to the remote versioninfo document for update checking (empty disables)",
				"default":     "https://github.com/Makr91/hyperweaver-agent/releases/latest/download/update-info.json",
			},
		},
	},
	"api_docs": map[string]any{
		"description":      "Interactive API documentation (Swagger UI)",
		"requires_restart": true,
		"properties": map[string]any{
			"enabled": map[string]any{
				"type":        "boolean",
				"description": "Serve the Agent API documentation at /api-docs",
				"default":     true,
			},
		},
	},
	"stats": map[string]any{
		"description":      "Server statistics endpoint configuration",
		"requires_restart": true,
		"properties": map[string]any{
			"public_access": map[string]any{
				"type":        "boolean",
				"description": "Allow unauthenticated access to the /stats endpoint",
				"default":     false,
			},
		},
	},
	"data": map[string]any{
		"description":      "Data storage locations",
		"requires_restart": true,
		"properties": map[string]any{
			"dir": map[string]any{
				"type":        "string",
				"description": "Root directory for agent data — databases now; machine directories, provisioners, and the file cache later (empty = per-OS local app-data default)",
				"default":     "",
			},
		},
	},
	"database": map[string]any{
		"description":      "SQLite tuning applied to both agent databases",
		"requires_restart": true,
		"properties": map[string]any{
			"sqlite_options": map[string]any{
				"type":        "object",
				"description": "SQLite session pragmas",
				"properties": map[string]any{
					"journal_mode": map[string]any{
						"type":        "string",
						"description": "Journal mode",
						"default":     "WAL",
						"enum":        []string{"DELETE", "TRUNCATE", "PERSIST", "MEMORY", "WAL", "OFF"},
					},
					"synchronous": map[string]any{
						"type":        "string",
						"description": "Durability/speed trade-off",
						"default":     "NORMAL",
						"enum":        []string{"OFF", "NORMAL", "FULL", "EXTRA"},
					},
					"cache_size_mb": map[string]any{
						"type":        "integer",
						"description": "Page cache size in megabytes",
						"default":     128,
						"min":         1,
						"max":         8192,
					},
					"temp_store": map[string]any{
						"type":        "string",
						"description": "Where temporary tables and indexes live",
						"default":     "MEMORY",
						"enum":        []string{"DEFAULT", "FILE", "MEMORY"},
					},
					"mmap_size_mb": map[string]any{
						"type":        "integer",
						"description": "Memory-mapped I/O window in megabytes (0 disables)",
						"default":     512,
						"min":         0,
						"max":         16384,
					},
					"busy_timeout_ms": map[string]any{
						"type":        "integer",
						"description": "Milliseconds to wait on a locked database",
						"default":     30000,
						"min":         100,
						"max":         600000,
					},
					"wal_autocheckpoint": map[string]any{
						"type":        "integer",
						"description": "WAL checkpoint threshold in pages (0 disables automatic checkpoints)",
						"default":     1000,
						"min":         0,
						"max":         1000000,
					},
					"optimize": map[string]any{
						"type":        "boolean",
						"description": "Run PRAGMA optimize when opening each database",
						"default":     true,
					},
				},
			},
		},
	},
	"tasks": map[string]any{
		"description":      "Task queue configuration",
		"requires_restart": true,
		"properties": map[string]any{
			"poll_interval_seconds": map[string]any{
				"type":        "integer",
				"description": "Seconds between task-queue polls",
				"default":     2,
				"min":         1,
				"max":         60,
			},
			"max_concurrent": map[string]any{
				"type":        "integer",
				"description": "Maximum number of tasks running at once",
				"default":     5,
				"min":         1,
				"max":         64,
			},
			"default_pagination_limit": map[string]any{
				"type":        "integer",
				"description": "Default limit for GET /tasks when the request does not send one",
				"default":     50,
				"min":         1,
				"max":         1000,
			},
			"retention_days": map[string]any{
				"type":        "integer",
				"description": "Completed/failed/cancelled tasks older than this many days are deleted by the periodic cleanup",
				"default":     30,
				"min":         1,
				"max":         3650,
			},
			"output": map[string]any{
				"type":        "object",
				"description": "Task output capture (live streaming + persistence)",
				"properties": map[string]any{
					"enabled": map[string]any{
						"type":        "boolean",
						"description": "Capture task output",
						"default":     true,
					},
					"mode": map[string]any{
						"type":        "string",
						"description": "full keeps every output line; circular caps the in-memory buffer, dropping the oldest",
						"default":     "full",
						"enum":        []string{"full", "circular"},
					},
					"circular_max_lines": map[string]any{
						"type":        "integer",
						"description": "Buffer cap for circular mode",
						"default":     10000,
						"min":         100,
					},
					"flush_interval_seconds": map[string]any{
						"type":        "integer",
						"description": "Seconds between database flushes of a running task's output",
						"default":     10,
						"min":         1,
						"max":         300,
					},
					"persist_log_file": map[string]any{
						"type":        "boolean",
						"description": "Also write a plain-text per-task log file when a task finishes",
						"default":     true,
					},
					"log_directory": map[string]any{
						"type":        "string",
						"description": "Directory for per-task log files (empty = <config dir>/logs/tasks)",
						"default":     "",
					},
				},
			},
		},
	},
	"machines": map[string]any{
		"description":      "Machine registry configuration",
		"requires_restart": true,
		"properties": map[string]any{
			"auto_discovery": map[string]any{
				"type":        "boolean",
				"description": "Create a periodic background discover task that reconciles the registry against VirtualBox and vagrant (the startup discovery always runs)",
				"default":     true,
			},
			"discovery_interval": map[string]any{
				"type":        "integer",
				"description": "Seconds between periodic discover tasks",
				"default":     300,
				"min":         10,
				"max":         86400,
			},
			"server_id_start": map[string]any{
				"type":        "integer",
				"description": "Lowest auto-assigned server_id",
				"default":     1,
				"min":         1,
				"max":         99999999,
			},
			"prefix_machine_names": map[string]any{
				"type":        "boolean",
				"description": "Derive created machines' names as <server_id>--<hostname>.<domain> when no explicit name is given; explicit names always win (machine names stay free-form)",
				"default":     false,
			},
			"shutdown_timeout": map[string]any{
				"type":        "integer",
				"description": "Seconds a graceful stop waits for the guest to power off after the ACPI signal before forcing poweroff",
				"default":     120,
				"min":         5,
				"max":         3600,
			},
			"keep_running_on_exit": map[string]any{
				"type":        "boolean",
				"description": "Keep provisioned machines running when the agent exits (SHI's keepserversrunning); false force-powers-off every machine this agent created on the way out",
				"default":     true,
			},
		},
	},
	"provisioning": map[string]any{
		"description":      "Provisioning engine configuration (package registry, machine working directories, and the SSH/ansible pipeline)",
		"requires_restart": true,
		"properties": map[string]any{
			"provisioners_dir": map[string]any{
				"type":        "string",
				"description": "Directory holding provisioner packages (SHI's on-disk format); installer-bundled packages are extracted here on startup without ever overwriting existing versions (empty = <data dir>/provisioners)",
				"default":     "",
			},
			"machines_dir": map[string]any{
				"type":        "string",
				"description": "Root of the per-machine working directories — the materialized provisioner copy, rendered Hosts.yml, id-files, installers, ssls trees, and the machine's media (empty = <data dir>/machines)",
				"default":     "",
			},
			"default_sync_method": map[string]any{
				"type":        "string",
				"description": "Sync method for machines whose spec sets none (folders[].type in the rendered document); platform rules still apply on top",
				"default":     "rsync",
				"enum":        []string{"rsync", "scp"},
			},
			"default_network_interface": map[string]any{
				"type":        "string",
				"description": "Host bridge interface injected into templates as DEFAULT_NETWORK_INTERFACE when the spec sets none; values from GET /provisioning/bridged-interfaces",
				"default":     "",
			},
			"playbook_timeout_seconds": map[string]any{
				"type":        "integer",
				"description": "Timeout for a single in-guest ansible-playbook run",
				"default":     21600,
				"min":         60,
			},
			"ansible_install_timeout_seconds": map[string]any{
				"type":        "integer",
				"description": "Timeout for the in-guest ansible/collection installation steps",
				"default":     300,
				"min":         60,
			},
			"ssh": map[string]any{
				"type":        "object",
				"description": "Provisioning SSH access to guests",
				"properties": map[string]any{
					"key_path": map[string]any{
						"type":        "string",
						"description": "The agent's own provisioning private key — the auth fallback when the document supplies neither a key nor a password; generated (ed25519) when absent (empty = <config dir>/ssh/provision_key)",
						"default":     "",
					},
					"timeout_seconds": map[string]any{
						"type":        "integer",
						"description": "Total wait for a guest's SSH to become available (the document's settings.setup_wait wins when larger)",
						"default":     300,
						"min":         10,
					},
					"poll_interval_seconds": map[string]any{
						"type":        "integer",
						"description": "Interval between SSH availability checks",
						"default":     10,
						"min":         1,
					},
				},
			},
			"network": map[string]any{
				"type":        "object",
				"description": "Dedicated provisioning network: one VirtualBox host-only interface (identified by host_ip — VirtualBox assigns interface names itself) plus its DHCP server; host-type networks[] entries ride it and their addresses pin as fixed leases",
				"properties": map[string]any{
					"enabled": map[string]any{
						"type":        "boolean",
						"description": "Enable the provisioning network (setup runs via POST /provisioning/network/setup)",
						"default":     true,
					},
					"subnet": map[string]any{
						"type":        "string",
						"description": "Provisioning network subnet (CIDR)",
						"default":     "10.190.190.0/24",
					},
					"host_ip": map[string]any{
						"type":        "string",
						"description": "Host address on the provisioning network — the interface's identity",
						"default":     "10.190.190.1",
					},
					"netmask": map[string]any{
						"type":        "string",
						"description": "Provisioning network netmask",
						"default":     "255.255.255.0",
					},
					"dhcp_server_ip": map[string]any{
						"type":        "string",
						"description": "The VirtualBox DHCP server's own address (must differ from host_ip)",
						"default":     "10.190.190.2",
					},
					"dhcp_range_start": map[string]any{
						"type":        "string",
						"description": "First DHCP-assignable provisioning IP (fixed leases and the clone allocator draw from the range)",
						"default":     "10.190.190.10",
					},
					"dhcp_range_end": map[string]any{
						"type":        "string",
						"description": "Last DHCP-assignable provisioning IP",
						"default":     "10.190.190.254",
					},
				},
			},
		},
	},
	"template_sources": map[string]any{
		"description":      "Box-template registry: downloaded box disk images machines clone from, and the registries serving them",
		"requires_restart": true,
		"properties": map[string]any{
			"local_storage_path": map[string]any{
				"type":        "string",
				"description": "Template storage root, <root>/<organization>/<box>/<version>/ (empty = <data dir>/templates)",
				"default":     "",
			},
			"sources": map[string]any{
				"type":        "array",
				"items":       "object",
				"description": "Configured Vagrant/BoxVault-compatible registries: {name, url, enabled, default, auth_token}. The entry named \"Default Registry\" (or flagged default) serves requests that name no source; auth_token authenticates private boxes",
				"default":     []map[string]any{{"name": "Default Registry", "url": "https://boxvault.startcloud.com", "enabled": true, "default": true, "auth_token": ""}},
			},
		},
	},
	"assets": map[string]any{
		"description":      "Installer file cache (the artifacts capability token): hash-verified installer/fixpack/hotfix files machines mount at start",
		"requires_restart": true,
		"properties": map[string]any{
			"enabled": map[string]any{
				"type":        "boolean",
				"description": "Serve the /artifacts surface and enforce cache verification at machine prepare; disabled skips mounting and verification with a loud warning",
				"default":     true,
			},
			"dir": map[string]any{
				"type":        "string",
				"description": "Cache root, <dir>/<role>/{installers,fixpacks,hotfixes}/<file> (empty = <data dir>/file-cache)",
				"default":     "",
			},
			"max_upload_gb": map[string]any{
				"type":        "integer",
				"description": "Upload size cap in GiB",
				"default":     50,
				"min":         1,
				"max":         1024,
			},
		},
	},
	"cleanup": map[string]any{
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
	},
	"monitoring": map[string]any{
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
	},
	"host_power": map[string]any{
		"description":      "Host power management (/system/host endpoints and the host-power capability token)",
		"requires_restart": true,
		"properties": map[string]any{
			"enabled": map[string]any{
				"type":        "boolean",
				"description": "Serve the host power endpoints: status/uptime plus admin-only shutdown, restart, poweroff, and halt of the machine this agent runs on",
				"default":     true,
			},
		},
	},
}
