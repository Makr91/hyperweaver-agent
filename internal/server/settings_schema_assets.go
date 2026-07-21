package server

var schemaTemplateSources = map[string]any{
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
}

var schemaCatalogSources = map[string]any{
	"description":      "Provisioner catalogs (the HACS model): agents fetch catalog.json, list families/versions, download the immutable versioned asset, verify its sha256, and import into the local registry. Fork the catalog repo as a template to run your own and add it as another source",
	"requires_restart": true,
	"properties": map[string]any{
		"sources": map[string]any{
			"type":        "array",
			"items":       "object",
			"description": "Configured catalogs: {name, url, enabled, default, ca_file}. The entry flagged default serves requests that name no source. ca_file adds a PEM CA bundle to the trust store for self-hosted forks (verification always stays on)",
			"default":     []map[string]any{{"name": "STARTcloud Provisioner Catalog", "url": "https://provisioner-catalog.startcloud.com/catalog.json", "enabled": true, "default": true, "ca_file": ""}},
		},
	},
}

var schemaArtifactStorage = map[string]any{
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
}

var schemaFileBrowser = map[string]any{
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
}

var schemaGuestAgent = map[string]any{
	"description":      "QEMU guest-agent channel (/machines/{name}/guest/*, the guest-agent capability token): guests run qemu-ga on a COM2 UART → host pipe — credential-less live IPs, exec, and clean shutdown without SSH or Guest Additions. The UART is a per-machine option: vbox.guest_agent at create (default false — the Proxmox model) or POST /machines/{name}/guest-agent/setup",
	"requires_restart": true,
	"properties": map[string]any{
		"enabled": map[string]any{
			"type":        "boolean",
			"description": "MASTER gate: allow per-machine UART wiring (vbox.guest_agent / the setup endpoint), serve /machines/{name}/guest/*, and advertise the guest-agent token; false disables wiring and removes the surface entirely",
			"default":     true,
		},
	},
}

var schemaSnapshots = map[string]any{
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
}
