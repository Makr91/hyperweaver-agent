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
			"shi_mode": map[string]any{
				"type":        "boolean",
				"description": "\"I Can't Believe it's not Super.Human.Installer\" mode: the UI renders the opinionated SHI-style theme/flow in Direct mode (the agent only carries the flag, advertised as shi_mode on GET /api/status)",
				"default":     false,
			},
		},
	},
	"startup": map[string]any{
		"description":      "How the agent itself starts (desktop login; headless installs boot via their service manager)",
		"requires_restart": true,
		"properties": map[string]any{
			"start_at_login": map[string]any{
				"type":        "boolean",
				"description": "Register the agent with the OS's native login-item mechanism (Windows Run key, macOS LaunchAgent, Linux XDG autostart); converged at every agent boot — false removes the registration",
				"default":     false,
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
			"resume_pending_on_start": map[string]any{
				"type":        "boolean",
				"description": "Keep pending tasks across an agent restart (the resumable queue). Off (default), pending tasks from a previous run are cancelled at boot — a queued stop from yesterday never fires on today's start",
				"default":     false,
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
				"description": "Derive created machines' names as <server_id>--<hostname>.<domain> when no explicit name is given; explicit names always win (machine names stay free-form). When on, settings.server_id is required at create (GET /machines/ids/next feeds it)",
				"default":     true,
			},
			"shutdown_timeout": map[string]any{
				"type":        "integer",
				"description": "Seconds a graceful stop waits for the guest to power off after the graceful signal (guest-agent shutdown when the channel answers, else the ACPI power button) before forcing poweroff",
				"default":     120,
				"min":         5,
				"max":         3600,
			},
			"keep_running_on_exit": map[string]any{
				"type":        "boolean",
				"description": "Keep provisioned machines running when the agent exits (SHI's keepserversrunning); false force-powers-off every machine this agent created on the way out",
				"default":     true,
			},
			"provision_on_start": map[string]any{
				"type":        "boolean",
				"description": "Run the full provision pipeline on a machine's VERY FIRST start (stored provisioner document, never provisioned) instead of a bare boot; later starts, restarts, and document-less machines always boot plainly (SHI's provisionserversonstart)",
				"default":     false,
			},
			"orchestration": map[string]any{
				"type":        "object",
				"description": "Ordered machine startup/shutdown by settings.boot_priority (1-100, default 95): at agent startup, autostart machines boot highest-priority first; at agent exit with keep_running_on_exit false, machines stop lowest-first",
				"properties": map[string]any{
					"enabled": map[string]any{
						"type":        "boolean",
						"description": "Boot autostart machines in priority order at agent startup (also togglable via POST /machines/orchestration/enable|disable)",
						"default":     false,
					},
					"strategy": map[string]any{
						"type":        "string",
						"description": "Shapes the shutdown/test plan",
						"default":     "parallel_by_priority",
						"enum":        []string{"sequential", "parallel_by_priority", "staggered"},
					},
					"priority_delay": map[string]any{
						"type":        "integer",
						"description": "Seconds between priority groups (staggered strategy and the test plan's duration estimate)",
						"default":     30,
						"min":         0,
						"max":         300,
					},
				},
			},
			"resource_validation": map[string]any{
				"type":        "object",
				"description": "Pre-flight resource checks on machine create/clone/modify: failing checks answer 400 Insufficient resources before anything queues; passing checks may annotate resource_warnings",
				"properties": map[string]any{
					"enabled": map[string]any{
						"type":        "boolean",
						"description": "Master switch for all resource validation",
						"default":     true,
					},
					"storage": map[string]any{
						"type":        "object",
						"description": "Disk space validation on the volume holding the machine working directories",
						"properties": map[string]any{
							"enabled": map[string]any{
								"type":        "boolean",
								"description": "Validate requested disk sizes",
								"default":     true,
							},
							"strategy": map[string]any{
								"type":        "string",
								"description": "actual checks against current free space; committed projects the sum of every machine's configured disk allocations (VirtualBox media are sparse — committed over-rejects on desktop hosts)",
								"default":     "actual",
								"enum":        []string{"actual", "committed"},
							},
							"thresholds": map[string]any{
								"type":        "object",
								"description": "Utilization percentages that annotate warnings (never block)",
								"properties": map[string]any{
									"warning":  map[string]any{"type": "number", "description": "Warning threshold percent", "default": 70, "min": 0, "max": 100},
									"critical": map[string]any{"type": "number", "description": "Critical threshold percent", "default": 80, "min": 0, "max": 100},
								},
							},
						},
					},
					"memory": map[string]any{
						"type":        "object",
						"description": "Host RAM validation",
						"properties": map[string]any{
							"enabled": map[string]any{
								"type":        "boolean",
								"description": "Validate requested memory",
								"default":     true,
							},
							"strategy": map[string]any{
								"type":        "string",
								"description": "committed projects the sum of every machine's configured memory against host RAM; actual checks against currently free RAM",
								"default":     "committed",
								"enum":        []string{"committed", "actual"},
							},
							"thresholds": map[string]any{
								"type":        "object",
								"description": "Utilization percentages that annotate warnings (never block)",
								"properties": map[string]any{
									"warning":  map[string]any{"type": "number", "description": "Warning threshold percent", "default": 80, "min": 0, "max": 100},
									"critical": map[string]any{"type": "number", "description": "Critical threshold percent", "default": 90, "min": 0, "max": 100},
								},
							},
						},
					},
					"cpu": map[string]any{
						"type":        "object",
						"description": "vCPU overcommit validation against physical cores",
						"properties": map[string]any{
							"enabled": map[string]any{
								"type":        "boolean",
								"description": "Validate requested vCPUs",
								"default":     true,
							},
							"strategy": map[string]any{
								"type":        "string",
								"description": "committed sums every machine's configured vCPUs; actual sums running machines only",
								"default":     "committed",
								"enum":        []string{"committed", "actual"},
							},
							"hard_limit": map[string]any{
								"type":        "number",
								"description": "Overcommit ceiling as a percentage of physical cores — requests projecting past it are rejected",
								"default":     400,
								"min":         100,
							},
							"thresholds": map[string]any{
								"type":        "object",
								"description": "Utilization percentages that annotate warnings (never block)",
								"properties": map[string]any{
									"warning":  map[string]any{"type": "number", "description": "Warning threshold percent", "default": 150, "min": 0},
									"critical": map[string]any{"type": "number", "description": "Critical threshold percent", "default": 300, "min": 0},
								},
							},
						},
					},
				},
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
				"description": "Configured Vagrant/BoxVault-compatible registries: {name, url, enabled, default, auth_token, ca_file}. The entry flagged default serves requests that name no source; names are display-only. auth_token is the registry API key (a BoxVault service-account token), sent as Bearer on every call — the ONLY credential. ca_file adds a PEM CA bundle to the trust store for self-signed registries (verification always stays on)",
				"default":     []map[string]any{{"name": "STARTcloud BoxVault", "url": "https://boxvault.startcloud.com", "enabled": true, "default": true, "auth_token": "", "ca_file": ""}},
			},
		},
	},
	"artifact_storage": map[string]any{
		"description":      "Merged artifact system (the artifacts capability token): typed storage locations — iso, image, installer, fixpack, hotfix — with one scan, one SHA-256 checksum store, one /artifacts surface",
		"requires_restart": true,
		"properties": map[string]any{
			"enabled": map[string]any{
				"type":        "boolean",
				"description": "Serve the /artifacts surface and enforce hash verification at machine prepare; disabled skips mounting and verification with a loud warning",
				"default":     true,
			},
			"dir": map[string]any{
				"type":        "string",
				"description": "Parent of the built-in locations: <dir>/isos, images, installers, fixpacks, hotfixes (empty = <data dir>/artifacts)",
				"default":     "",
			},
			"max_upload_gb": map[string]any{
				"type":        "integer",
				"description": "Upload size cap in GiB",
				"default":     50,
				"min":         1,
				"max":         1024,
			},
			"download": map[string]any{
				"type":        "object",
				"description": "URL download tuning",
				"properties": map[string]any{
					"timeout_seconds": map[string]any{
						"type":        "integer",
						"description": "Timeout for one URL download",
						"default":     3600,
						"min":         60,
					},
				},
			},
			"scanning": map[string]any{
				"type":        "object",
				"description": "Location scan tuning",
				"properties": map[string]any{
					"periodic_scan_interval": map[string]any{
						"type":        "integer",
						"description": "Seconds between automatic location scans (0 disables; startup always scans once)",
						"default":     300,
						"min":         0,
						"max":         86400,
					},
					"supported_extensions": map[string]any{
						"type":        "object",
						"description": "Extensions the iso/image scans register, per type (empty = defaults: iso .iso; image .vmdk .raw .vdi .qcow2 .img .ova .ovf)",
						"keys":        []string{"iso", "image"},
						"values":      []string{},
					},
				},
			},
			"paths": map[string]any{
				"type":        "array",
				"items":       "object",
				"description": "Additional storage locations beyond the built-ins: {name, path, type, enabled} with type one of iso, image, installer, fixpack, hotfix. The storage-path API persists its entries here",
				"default":     []map[string]any{},
			},
		},
	},
	"file_browser": map[string]any{
		"description":      "Host file browser (/filesystem, the file-browser capability token): directory listing plus the mutate family — create/rename/move/copy/delete, text content read/write, upload/download, archives, permissions (the UI's path pickers and file manager)",
		"requires_restart": true,
		"properties": map[string]any{
			"enabled": map[string]any{
				"type":        "boolean",
				"description": "Serve the /filesystem surface and advertise the file-browser token; false removes the surface entirely",
				"default":     true,
			},
			"root": map[string]any{
				"type":        "string",
				"description": "Confine the surface to this directory: \"/\" maps here and anything outside answers 403. Empty = unrestricted — \"/\" lists the host's drive letters on Windows and the real filesystem root elsewhere",
				"default":     "",
			},
			"upload_size_limit_gb": map[string]any{
				"type":        "integer",
				"description": "Size cap for one POST /filesystem/upload body, in GiB",
				"default":     50,
				"min":         1,
				"max":         1024,
			},
			"security": map[string]any{
				"type":        "object",
				"description": "Path bounds applied to every /filesystem operation",
				"properties": map[string]any{
					"prevent_traversal": map[string]any{
						"type":        "boolean",
						"description": "Reject paths carrying \"..\" or \"~\"",
						"default":     true,
					},
					"max_directory_entries": map[string]any{
						"type":        "integer",
						"description": "Refuse listing directories larger than this",
						"default":     1000,
						"min":         1,
						"max":         100000,
					},
					"max_edit_size_mb": map[string]any{
						"type":        "integer",
						"description": "Files larger than this are refused by the text content read/write endpoints (download/upload stream without this bound)",
						"default":     100,
						"min":         1,
						"max":         10240,
					},
					"forbidden_paths": map[string]any{
						"type":        "array",
						"items":       "string",
						"description": "Any path underneath these prefixes is forbidden",
						"default":     []string{"/dev", "/proc", "/sys"},
					},
					"forbidden_patterns": map[string]any{
						"type":        "array",
						"items":       "string",
						"description": "Glob-style patterns (* matches anything) that forbid matching paths",
						"default":     []string{},
					},
				},
			},
			"archive": map[string]any{
				"type":        "object",
				"description": "Archive creation/extraction (task-queued)",
				"properties": map[string]any{
					"enabled": map[string]any{
						"type":        "boolean",
						"description": "Serve the /filesystem/archive endpoints",
						"default":     true,
					},
					"max_archive_size_mb": map[string]any{
						"type":        "integer",
						"description": "A created archive larger than this is deleted and the task fails",
						"default":     10240,
						"min":         1,
					},
					"supported_formats": map[string]any{
						"type":        "array",
						"items":       "string",
						"description": "Formats archive creation accepts — this agent creates zip, tar, and tar.gz natively (Go's bzip2 is decompress-only); extraction additionally handles tar.bz2 and .gz regardless",
						"default":     []string{"zip", "tar", "tar.gz"},
					},
				},
			},
		},
	},
	"guest_agent": map[string]any{
		"description":      "QEMU guest-agent channel (/machines/{name}/guest/*, the guest-agent capability token): guests run qemu-ga on a COM2 UART → host pipe — credential-less live IPs, exec, and clean shutdown without SSH or Guest Additions. The UART is a per-machine option: zones.guest_agent at create (default false — the Proxmox model, shared with zoneweaver) or POST /machines/{name}/guest-agent/setup",
		"requires_restart": true,
		"properties": map[string]any{
			"enabled": map[string]any{
				"type":        "boolean",
				"description": "MASTER gate: allow per-machine UART wiring (zones.guest_agent / the setup endpoint), serve /machines/{name}/guest/*, and advertise the guest-agent token; false disables wiring and removes the surface entirely",
				"default":     true,
			},
		},
	},
	"snapshots": map[string]any{
		"description":      "Scheduled machine snapshot rotation (zoneweaver's snapshots vocabulary on VBoxManage snapshots). Defaults are deliberately CONSERVATIVE for VirtualBox: creation is CoW-thin, but pruning is a physical disk merge and snapshots of running machines carry RAM state",
		"requires_restart": true,
		"properties": map[string]any{
			"enabled": map[string]any{
				"type":        "boolean",
				"description": "Run the snapshot rotation service",
				"default":     false,
			},
			"interval_minutes": map[string]any{
				"type":        "integer",
				"description": "Cadence for simple/age default policies (rotation uses the fixed hourly/daily/weekly schedule)",
				"default":     60,
				"min":         5,
				"max":         10080,
			},
			"default_policy": map[string]any{
				"type":        "object",
				"description": "Retention policy applied to EVERY machine unless the machine overrides it (the PUT /machines/{name} `snapshots` field — configuration.snapshots; type none disables per machine, null clears back to this default). Types: none | simple (keep newest N) | age (delete older than max_age_days) | rotation (hourly/daily/weekly tiers, Snapshoter.sh schedule: hourly :00 hours 1-23, daily 00:00 Sun-Fri, weekly 00:00 Sat). quiesce runs qga fsfreeze around each snapshot when the guest agent answers",
				"properties": map[string]any{
					"type": map[string]any{
						"type":        "string",
						"description": "Retention type",
						"default":     "none",
						"enum":        []string{"none", "simple", "age", "rotation"},
					},
					"quiesce": map[string]any{
						"type":        "boolean",
						"description": "qga fsfreeze around snapshots (application-consistent when available; crash-consistent otherwise, never blocking)",
						"default":     false,
					},
					"keep": map[string]any{
						"type":        "integer",
						"description": "simple: newest N auto snapshots to keep",
						"default":     3,
						"min":         1,
					},
					"max_age_days": map[string]any{
						"type":        "integer",
						"description": "age: delete auto snapshots older than this",
						"default":     7,
						"min":         1,
					},
					"tiers": map[string]any{
						"type":        "object",
						"description": "rotation: per-tier keep counts",
						"properties": map[string]any{
							"hourly": map[string]any{
								"type":        "object",
								"description": "Hourly tier",
								"properties": map[string]any{
									"keep": map[string]any{"type": "integer", "description": "Snapshots to keep", "default": 2, "min": 1},
								},
							},
							"daily": map[string]any{
								"type":        "object",
								"description": "Daily tier",
								"properties": map[string]any{
									"keep": map[string]any{"type": "integer", "description": "Snapshots to keep", "default": 3, "min": 1},
								},
							},
							"weekly": map[string]any{
								"type":        "object",
								"description": "Weekly tier",
								"properties": map[string]any{
									"keep": map[string]any{"type": "integer", "description": "Snapshots to keep", "default": 2, "min": 1},
								},
							},
						},
					},
				},
			},
		},
	},
	"applications": map[string]any{
		"description":      "External launcher applications (GET /applications, the host-launchers token): user-chosen desktop tools (PuTTY, WinSCP, mstsc, ...) the agent launches on its own host against a machine — SHI's per-server app buttons generalized (the UI's per-machine launch menu, POST /machines/{name}/applications/{appName}/launch). Each entry: {name, path, args[]}. args placeholders {host}/{port}/{user}/{password} resolve per machine through the SSH transport ladder and stored credentials, {machine} is the machine name; substitution is per-argument (no quoting). A missing executable is refused, never spawned. Direct-mode desktop contract; a headless service opens them on the service host's desktop",
		"requires_restart": true,
		"type":             "array",
		"items":            "object",
		"default":          []map[string]any{},
	},
	"ticket_system": map[string]any{
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
	},
}
