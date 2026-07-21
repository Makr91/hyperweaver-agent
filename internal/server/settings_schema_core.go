package server

var schemaServer = map[string]any{
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
}

var schemaSSL = map[string]any{
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
}

var schemaCORS = map[string]any{
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
}

var schemaUI = map[string]any{
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
}

var schemaStartup = map[string]any{
	"description":      "How the agent itself starts (desktop login; headless installs boot via their service manager)",
	"requires_restart": true,
	"properties": map[string]any{
		"start_at_login": map[string]any{
			"type":        "boolean",
			"description": "Register the agent with the OS's native login-item mechanism (Windows Run key, macOS LaunchAgent, Linux XDG autostart); converged at every agent boot — false removes the registration",
			"default":     false,
		},
	},
}

var schemaBrowser = map[string]any{
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
}

var schemaLogging = map[string]any{
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
}

var schemaAPIKeys = map[string]any{
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
}

var schemaOIDC = map[string]any{
	"description":      "Direct-mode federated login via the OAuth device grant (RFC 8628): the UI shows a user code, the user approves it at the identity provider, and the agent mints a local admin API key. The first successful login BINDS the agent to that account (TOFU); later logins by other accounts are refused unless listed in allowed_users. Enabling also makes the agent an OIDC RESOURCE SERVER: the bound account's IdP access token is accepted directly as an Authorization Bearer credential on the whole Agent API (validated against the issuer's JWKS; the token's aud must include this client_id). Endpoints resolve from the issuer's .well-known discovery document",
	"requires_restart": true,
	"properties": map[string]any{
		"enabled": map[string]any{
			"type":        "boolean",
			"description": "Enable the device-login endpoints (/auth/oidc/device-start, /auth/oidc/device-status), accept the bound account's IdP access token as a Bearer credential on the Agent API, and advertise oidc in auth[] on GET /api/status",
			"default":     false,
		},
		"issuer": map[string]any{
			"type":        "string",
			"description": "The identity provider's issuer URL (the base origin; discovery-based — endpoints are never configured by hand)",
			"default":     "",
		},
		"client_id": map[string]any{
			"type":        "string",
			"description": "The shared public OIDC client id registered for agent device login",
			"default":     "hyperweaver-agent",
		},
		"scopes": map[string]any{
			"type":        "array",
			"items":       "string",
			"description": "Scopes requested at login (openid is required for the identity token; organizations carries the org claim BoxVault authorizes private boxes by)",
			"default":     []string{"openid", "profile", "email", "organizations"},
		},
		"allowed_users": map[string]any{
			"type":        "array",
			"items":       "string",
			"description": "Additional accounts (emails, OIDC subjects, or account UUIDs) allowed to log in after the first login bound the agent",
			"default":     []string{},
		},
	},
}

var schemaUpdates = map[string]any{
	"description":      "Application update checking configuration",
	"requires_restart": false,
	"properties": map[string]any{
		"versioninfo_url": map[string]any{
			"type":        "string",
			"description": "URL to the remote versioninfo document for update checking (empty disables)",
			"default":     "https://github.com/Makr91/hyperweaver-agent/releases/latest/download/update-info.json",
		},
	},
}

var schemaAPIDocs = map[string]any{
	"description":      "Interactive API documentation (Swagger UI)",
	"requires_restart": true,
	"properties": map[string]any{
		"enabled": map[string]any{
			"type":        "boolean",
			"description": "Serve the Agent API documentation at /api-docs",
			"default":     true,
		},
	},
}

var schemaStats = map[string]any{
	"description":      "Server statistics endpoint configuration",
	"requires_restart": true,
	"properties": map[string]any{
		"public_access": map[string]any{
			"type":        "boolean",
			"description": "Allow unauthenticated access to the /stats endpoint",
			"default":     false,
		},
	},
}

var schemaData = map[string]any{
	"description":      "Data storage locations",
	"requires_restart": true,
	"properties": map[string]any{
		"dir": map[string]any{
			"type":        "string",
			"description": "Root directory for agent data — databases now; machine directories, provisioners, and the file cache later (empty = per-OS local app-data default)",
			"default":     "",
		},
	},
}

var schemaDatabase = map[string]any{
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
}
