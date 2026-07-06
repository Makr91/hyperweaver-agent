package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// defaultConfigYAML is written verbatim on first run so the on-disk file keeps
// its comments (a plain Marshal of Config would lose them).
const defaultConfigYAML = `# Hyperweaver Agent configuration
# https://github.com/Makr91/hyperweaver-agent

server:
  # Address the web server binds to. Keep 127.0.0.1 unless you know you want
  # the agent reachable from other machines.
  bind_address: 127.0.0.1
  port: 9420
  # Port for the HTTPS listener (bound only when ssl.enabled).
  https_port: 9421

ssl:
  # Serve HTTPS on server.https_port (on by default, like the Node agent).
  # Certificate problems never stop the agent — HTTPS is skipped with an
  # error in the log.
  enabled: true
  # With SSL enabled, the plain-HTTP port serves only redirects to HTTPS.
  # Set false to keep the HTTP port serving the full app alongside HTTPS
  # (for clients that cannot follow redirects).
  force_secure: true
  # Generate the server certificate at the paths below when none exists,
  # signed by the CA below (which is itself generated when absent).
  generate_ssl: true
  # Server private key / certificate locations. Empty =
  # <config dir>/ssl/server.key and <config dir>/ssl/server.crt
  key_path: ''
  cert_path: ''
  # CA used to sign the generated server certificate. Provide your own CA
  # pair here (wildcard-capable) and everything chains to it; absent files
  # mean a local CA is generated first. Empty = <config dir>/ssl/ca.crt and
  # <config dir>/ssl/ca.key
  ca_cert_path: ''
  ca_key_path: ''

cors:
  # This is an API-key-authenticated backend in a many-to-many mesh: the API
  # key — not the browser Origin — is the access boundary, so by default the
  # agent answers any Origin. Set allow_all: false to fall back to the
  # explicit whitelist and lock down direct browser access; proxied,
  # API-key-authenticated calls are unaffected either way.
  allow_all: true
  # Origins allowed when allow_all is false (scheme://host:port).
  whitelist: []

ui:
  # Serve the bundled Hyperweaver UI at /ui/ (and / redirects there).
  enabled: true
  # Optional: serve the UI from this directory instead of the copy embedded in
  # the binary. Leave empty for normal operation.
  path: ''

browser:
  # Optional: full path to the browser the tray "Open" action should launch
  # (an executable, or a .app bundle on macOS). Empty = system default browser.
  path: ''

logging:
  # error | warn | info | debug
  level: info
  # Also log human-readable output to the console (visible when the agent is
  # started from a terminal; GUI builds on Windows have no console).
  console: true
  # Log file location. Empty = <config dir>/logs/agent.log
  file: ''
  max_size_mb: 20
  max_backups: 5
  # Compress rotated log files (gzip).
  compression: true
  # Per-category log levels overriding the global level, e.g.
  #   categories:
  #     tasks: debug
  # Categories this agent emits: app, api_requests, auth, tasks, machines,
  # monitoring, provisioning.
  categories: {}

api_keys:
  # Allow POST /api-keys/bootstrap to create the first API key.
  bootstrap_enabled: true
  # Lock the bootstrap endpoint once any key exists.
  bootstrap_auto_disable: true
  # Require the setup (claim) token — written to setup.token beside this file
  # and printed to the startup log — as proof of host ownership.
  bootstrap_require_claim_token: true
  # Bcrypt cost for stored key hashes.
  hash_rounds: 12
  # Random bytes of key material (base64url-encoded after the hw_ prefix).
  key_length: 64

updates:
  # Version document the update check compares against (JSON: version,
  # releaseUrl, releaseDate, changelog). Empty disables update checking.
  versioninfo_url: https://github.com/Makr91/hyperweaver-agent/releases/latest/download/update-info.json

api_docs:
  # Serve the interactive Agent API documentation (Swagger UI) at /api-docs.
  enabled: true

stats:
  # Serve GET /stats without an API key.
  public_access: false

data:
  # Root directory for agent data: the SQLite databases (tasks.sqlite,
  # agent.sqlite) today; machine directories, provisioners, and the file
  # cache in later releases. Empty = the per-OS local app-data default
  # (%LOCALAPPDATA%\hyperweaver-agent on Windows,
  # ~/Library/Application Support/hyperweaver-agent on macOS,
  # ~/.local/share/hyperweaver-agent on Linux).
  dir: ''

database:
  # SQLite tuning applied to both agent databases (tasks.sqlite,
  # agent.sqlite).
  sqlite_options:
    # DELETE | TRUNCATE | PERSIST | MEMORY | WAL | OFF
    journal_mode: WAL
    # OFF | NORMAL | FULL | EXTRA
    synchronous: NORMAL
    cache_size_mb: 128
    # DEFAULT | FILE | MEMORY
    temp_store: MEMORY
    # 0 disables memory-mapped I/O.
    mmap_size_mb: 512
    busy_timeout_ms: 30000
    # WAL checkpoint threshold in pages; 0 disables automatic checkpoints.
    wal_autocheckpoint: 1000
    # Run PRAGMA optimize when opening each database.
    optimize: true

tasks:
  # Seconds between task-queue polls.
  poll_interval_seconds: 2
  # Maximum number of tasks running at once.
  max_concurrent: 5
  # Default limit for GET /tasks when the request does not send one.
  default_pagination_limit: 50
  # Completed/failed/cancelled tasks older than this many days are deleted
  # by the periodic cleanup.
  retention_days: 30
  output:
    # Capture task output (live streaming + persistence).
    enabled: true
    # full keeps every output line; circular caps the in-memory buffer at
    # circular_max_lines, dropping the oldest.
    mode: full
    circular_max_lines: 10000
    # Seconds between database flushes of a running task's output.
    flush_interval_seconds: 10
    # Also write a plain-text per-task log file when a task finishes.
    persist_log_file: true
    # Directory for those log files. Empty = <config dir>/logs/tasks
    log_directory: ''

machines:
  # Create a periodic background discover task that reconciles the registry
  # against VirtualBox and vagrant (imports machines built outside the agent,
  # detects external shutdowns). The startup discovery always runs.
  auto_discovery: true
  # Seconds between periodic discover tasks.
  discovery_interval: 300
  # Lowest auto-assigned server_id.
  server_id_start: 1
  # Seconds a graceful stop waits for the guest to power off after the ACPI
  # signal before forcing poweroff.
  shutdown_timeout: 120

provisioning:
  # Directory holding provisioner packages (SHI's on-disk format:
  # <name>/provisioner-collection.yml with <version>/provisioner.yml trees
  # beneath). Installer-bundled packages are extracted here on startup
  # without ever overwriting existing versions.
  # Empty = <data dir>/provisioners
  provisioners_dir: ''

cleanup:
  # Seconds between periodic cleanup runs (task retention).
  interval: 300

monitoring:
  # The /monitoring/* endpoints always serve realtime samples. Enabling
  # storage adds a background collector writing time series into
  # per-datatype database files (monitoring-cpu.sqlite, monitoring-memory.sqlite,
  # monitoring-network.sqlite) so history charts work.
  storage_enabled: false
  # Seconds between collector samples (when storage is enabled).
  collection_interval: 60
  # Stored samples older than this many days are deleted by the periodic
  # cleanup.
  retention_days: 7

host_power:
  # Serve the host power-management endpoints (/system/host/*): status,
  # uptime, and admin-key-gated shutdown/restart/poweroff/halt of the machine
  # this agent runs on. Set false to remove the surface entirely.
  enabled: true
`

func ensureDefaultFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat config %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	if err := safepath.WriteFile(path, []byte(defaultConfigYAML), 0o600); err != nil {
		return fmt.Errorf("write default config: %w", err)
	}
	return nil
}
