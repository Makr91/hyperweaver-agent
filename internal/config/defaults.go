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
  # Open the signed-in UI in the browser when the desktop agent starts, so a
  # fresh install lands in the app without hunting for the tray icon.
  open_on_start: true

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
  # monitoring, provisioning, assets.
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

oidc:
  # Direct-mode federated login via the OAuth device grant (RFC 8628): the
  # login page shows a user code, you approve it at the identity provider,
  # and the agent mints a local admin API key. The FIRST successful login
  # binds this agent to that account; later logins by other accounts are
  # refused unless listed in allowed_users. Endpoints come from the issuer's
  # .well-known discovery document — never configured by hand.
  enabled: false
  # The identity provider's issuer URL.
  issuer: ''
  # The shared public OIDC client id registered for agent device login.
  client_id: hyperweaver-agent
  # Additional accounts (emails or OIDC subjects) allowed to log in after the
  # first login bound the agent.
  allowed_users: []

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
  # When machine-create/clone requests carry no explicit name, derive it as
  # <server_id>--<hostname>.<domain> (the partition-id convention). Explicit
  # names always win — machine names stay free-form. With this on,
  # settings.server_id is REQUIRED at create (GET /machines/ids/next feeds it).
  prefix_machine_names: true
  # Seconds a graceful stop waits for the guest to power off after the ACPI
  # signal before forcing poweroff.
  shutdown_timeout: 120
  # Keep provisioned machines running when the agent exits (SHI's
  # keepserversrunning). false force-powers-off every machine this agent
  # created on the way out; discovered VMs are never touched.
  keep_running_on_exit: true
  # Run the full provision pipeline on a machine's VERY FIRST start (stored
  # provisioner document present, never provisioned) instead of a bare boot.
  # Later starts, restarts, and document-less machines always boot plainly.
  provision_on_start: false

provisioning:
  # Directory holding provisioner packages (SHI's on-disk format:
  # <name>/provisioner-collection.yml with <version>/provisioner.yml trees
  # beneath). Installer-bundled packages are extracted here on startup
  # without ever overwriting existing versions.
  # Empty = <data dir>/provisioners
  provisioners_dir: ''
  # Root of the per-machine working directories: the materialized provisioner
  # copy, the generated Hosts.yml, id-files, installers, and ssls trees
  # vagrant runs from. Working copies are VM-scale data — keep this off
  # roaming profiles. Empty = <data dir>/machines
  machines_dir: ''
  # Sync method for machines whose spec sets none: rsync | scp (SHI's global
  # preference; platform rules still apply — forced rsync on Windows, macOS
  # auto-fallback to SCP on the ancient Apple rsync).
  default_sync_method: rsync
  # Host bridge interface injected into templates as
  # DEFAULT_NETWORK_INTERFACE when the spec sets none. Values come from
  # GET /provisioning/bridged-interfaces (VBoxManage list bridgedifs).
  default_network_interface: ''
  # Timeout for one in-guest ansible-playbook run.
  playbook_timeout_seconds: 21600
  # Timeout for the in-guest ansible/collection installation steps.
  ansible_install_timeout_seconds: 300
  # Allow sequence hooks (provisioning.pre[]/post[] in a machine's document)
  # with target: host to run scripts ON THIS HOST. Guest-target hooks are
  # always allowed. Machines rendered from packages the installer did NOT
  # ship additionally confirm once per machine before host hooks run.
  host_hooks: true
  ssh:
    # The agent's own provisioning private key — the SSH-auth fallback when
    # the machine's document supplies neither a key nor a password; generated
    # (ed25519) at startup when absent. Empty = <config dir>/ssh/provision_key
    key_path: ''
    # Total wait for a guest's SSH to become available (the document's
    # settings.setup_wait wins when larger).
    timeout_seconds: 300
    # Interval between SSH availability checks.
    poll_interval_seconds: 10
  network:
    # Dedicated provisioning network: ONE VirtualBox host-only interface
    # (identified by host_ip — VirtualBox assigns interface names itself)
    # plus its DHCP server. Set up via POST /provisioning/network/setup.
    enabled: true
    subnet: 10.190.190.0/24
    host_ip: 10.190.190.1
    netmask: 255.255.255.0
    # The VirtualBox DHCP server's own address (must differ from host_ip).
    dhcp_server_ip: 10.190.190.2
    dhcp_range_start: 10.190.190.10
    dhcp_range_end: 10.190.190.254

template_sources:
  # Box-template registry: downloaded box disk images machines clone from.
  # Storage root (<root>/<organization>/<box>/<version>/).
  # Empty = <data dir>/templates
  local_storage_path: ''
  # Vagrant/BoxVault-compatible registries. The entry flagged default serves
  # requests that name no source; names are display-only. auth_token
  # authenticates private boxes.
  sources:
    - name: STARTcloud BoxVault
      url: https://boxvault.startcloud.com
      enabled: true
      default: true
      auth_token: ''

catalog_sources:
  # Provisioner catalogs (the HACS model): agents fetch catalog.json, list
  # families/versions, download the immutable versioned asset, verify its
  # sha256, and import into the local registry. Fork the catalog repo as a
  # template to run your own and add it here (ca_file trusts a private CA;
  # certificate verification always stays on).
  sources:
    - name: STARTcloud Provisioner Catalog
      url: https://provisioner-catalog.startcloud.com/catalog.json
      enabled: true
      default: true
      ca_file: ''

artifact_storage:
  # The merged artifact system (the artifacts capability token): typed
  # storage locations — iso, image, installer, fixpack, hotfix — with one
  # scan, one SHA-256 checksum store, one /artifacts surface. Installer-
  # family files are hash-verified before they ever reach a machine;
  # disabling removes the surface and skips mounting/verification entirely
  # (a loud warning at machine prepare).
  enabled: true
  # Parent of the built-in locations (<dir>/isos, images, installers,
  # fixpacks, hotfixes). Empty = <data dir>/artifacts
  dir: ''
  # Upload size cap in GiB.
  max_upload_gb: 50
  download:
    # Timeout for one URL download.
    timeout_seconds: 3600
  scanning:
    # Seconds between automatic location scans (0 disables; startup always
    # scans once). Scans register new files, hash them, and mark vanished
    # files missing.
    periodic_scan_interval: 300
    # Extensions the iso/image scans register. Empty = the defaults
    # (iso: .iso; image: .vmdk .raw .vdi .qcow2 .img .ova .ovf).
    supported_extensions: {}
  # Additional storage locations beyond the built-ins:
  #   paths:
  #     - name: Big ISO Shelf
  #       path: D:\isos
  #       type: iso
  #       enabled: true
  # The storage-path API persists its entries here too.
  paths: []

file_browser:
  # Host file browser (the file-browser capability token): GET /filesystem
  # lists agent-host directories, and the /filesystem mutate family edits
  # them — create/rename/move/copy/delete, text content read/write,
  # upload/download, archives, permissions (the UI's path pickers and file
  # manager). Set false to remove the whole surface.
  enabled: true
  # Confine browsing to this directory: "/" maps here and anything outside
  # answers 403. Empty = unrestricted — "/" lists the host's drive letters
  # on Windows and the real filesystem root elsewhere.
  root: ''
  # Size cap for one POST /filesystem/upload body, in GiB.
  upload_size_limit_gb: 50
  security:
    # Reject paths carrying ".." or "~".
    prevent_traversal: true
    # Refuse listing directories larger than this.
    max_directory_entries: 1000
    # Files larger than this (MB) are refused by the text content
    # read/write endpoints (download/upload stream without this bound).
    max_edit_size_mb: 100
    # Any path underneath these prefixes is forbidden.
    forbidden_paths:
      - /dev
      - /proc
      - /sys
    # Glob-style patterns (* matches anything) that forbid matching paths.
    forbidden_patterns: []
  archive:
    # Archive creation/extraction endpoints (task-queued).
    enabled: true
    # A created archive larger than this (MB) is deleted and the task fails.
    max_archive_size_mb: 10240
    # Formats POST /filesystem/archive/create accepts. This agent creates
    # zip, tar, and tar.gz natively; extraction additionally handles
    # tar.bz2 and .gz regardless of this list.
    supported_formats:
      - zip
      - tar
      - tar.gz

guest_agent:
  # QEMU guest-agent channel (the guest-agent capability token): the MASTER
  # gate. The UART itself is a per-machine option (zones.guest_agent at
  # create / the PUT guest_agent toggle / the setup endpoint, default off —
  # the Proxmox model); guests run qemu-ga on the COM2 → host-pipe channel
  # (baked into the box templates), and /machines/{name}/guest/* speaks the
  # credential-less JSON protocol — live guest IPs, exec, clean shutdown —
  # with no SSH and no Guest Additions. Set false to disable per-machine
  # wiring and remove the surface entirely.
  enabled: true

snapshots:
  # Scheduled machine snapshot rotation (zoneweaver's snapshots vocabulary on
  # VBoxManage snapshots). The default policy below applies to EVERY machine
  # unless a machine overrides it (the PUT /machines/{name} snapshots field;
  # type none disables per machine, null clears back to this default).
  # Defaults are deliberately CONSERVATIVE for VirtualBox: snapshot creation
  # is CoW-thin, but pruning is a physical disk merge and snapshots of
  # running machines carry RAM state.
  enabled: false
  # Cadence for simple/age policies in minutes; rotation ignores it and rides
  # the fixed schedule (hourly :00 hours 1-23, daily 00:00 Sun-Fri, weekly
  # 00:00 Sat).
  interval_minutes: 60
  default_policy:
    # none | simple (keep newest N auto-*) | age (delete auto-* older than
    # max_age_days) | rotation (hourly/daily/weekly tiers).
    type: none
    # Run qga fsfreeze around each snapshot when the guest agent answers
    # (application-consistent; crash-consistent otherwise, never blocking).
    quiesce: false
    # simple: newest N auto snapshots to keep.
    keep: 3
    # age: delete auto snapshots older than this many days.
    max_age_days: 7
    # rotation: per-tier keep counts.
    tiers:
      hourly:
        keep: 2
      daily:
        keep: 3
      weekly:
        keep: 2

# External applications the agent can launch on its own desktop against a
# machine (the UI's per-machine launch menu; Direct-mode desktop contract).
# Args placeholders: {host} {port} {user} {password} — resolved through the
# machine's SSH transport ladder and stored credentials — and {machine}.
#   applications:
#     - name: PuTTY
#       path: C:\Program Files\PuTTY\putty.exe
#       args: ["-ssh", "{user}@{host}", "-P", "{port}"]
applications: []

ticket_system:
  # Help & Support link in the UI's profile dropdown (served publicly at
  # GET /api/config/ticket). The link renders only when enabled AND base_url
  # are set.
  enabled: true
  # Base URL for the ticket system.
  base_url: https://xd.prominic.net/app/apprequest.nsf/router?openagent
  # Default request type parameter.
  req_type: sso
  # Context URL for the ticket system (usually the repository URL).
  context: https://github.com/Makr91/hyperweaver-agent

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
  # Keep the host awake while the agent runs, via the OS's native
  # power-management API (SetThreadExecutionState / IOKit power assertion /
  # systemd-logind inhibitor). System sleep only — the display may still
  # sleep and lock.
  prevent_sleep: false
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
