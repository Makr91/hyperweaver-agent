package server

var schemaTasks = map[string]any{
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
}

var schemaMachines = map[string]any{
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
}

var schemaProvisioning = map[string]any{
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
		"host_hooks": map[string]any{
			"type":        "boolean",
			"description": "Allow sequence hooks (provisioning.pre[]/post[] in a machine's document) with target: host to run scripts ON THIS HOST; guest-target hooks are always allowed. Machines rendered from packages the installer did NOT ship additionally confirm once per machine before host hooks run",
			"default":     true,
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
}
