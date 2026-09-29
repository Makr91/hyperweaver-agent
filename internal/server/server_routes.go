package server

import (
	"net/http"

	"github.com/Makr91/hyperweaver-agent/internal/apidocs"
	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/webui"
)

func (s *Server) registerRoutes(mux *http.ServeMux) error {
	mux.HandleFunc("GET /api/", handleUnknownAPI)
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /api/config/ticket", s.handleTicketConfig)
	mux.HandleFunc("GET /api/rules", s.handleRules)

	// API-key surface (Agent API v1 local tier). Bootstrap is public (gated
	// by config + the setup token); everything else goes through the auth
	// middleware, whose central policy enforces the role model per path.
	requireKey := auth.Middleware(s.keys, s.oidcMgr.authenticateToken)
	mux.Handle("GET /api/events", requireKey(http.HandlerFunc(s.handleEvents)))
	mux.HandleFunc("POST /api/api-keys/bootstrap", s.handleBootstrapKey)
	mux.HandleFunc("POST /api/auth/tray-claim", s.handleTrayClaim)
	mux.HandleFunc("POST /api/auth/oidc/device-start", s.handleOIDCDeviceStart)
	mux.HandleFunc("GET /api/auth/oidc/device-status", s.handleOIDCDeviceStatus)
	mux.HandleFunc("POST /api/auth/oidc/silent-start", s.handleOIDCSilentStart)
	mux.HandleFunc("GET /api/auth/oidc/callback", s.handleOIDCCallback)
	// hwa:// single-instance handoff: public route, authenticated by the
	// per-boot secret file only a local same-user process can read.
	mux.HandleFunc("POST /api/protocol/open", s.handleProtocolOpen)
	mux.HandleFunc("POST /api/protocol/handoff", s.handleProtocolHandoff)
	mux.Handle("POST /api/api-keys/generate", requireKey(http.HandlerFunc(s.handleGenerateKey)))
	mux.Handle("GET /api/api-keys", requireKey(http.HandlerFunc(s.handleListKeys)))
	mux.Handle("GET /api/api-keys/info", requireKey(http.HandlerFunc(s.handleKeyInfo)))
	mux.Handle("DELETE /api/api-keys/{id}", requireKey(http.HandlerFunc(s.handleDeleteKey)))
	mux.Handle("PUT /api/api-keys/{id}/revoke", requireKey(http.HandlerFunc(s.handleRevokeKey)))
	mux.Handle("GET /api/user", requireKey(http.HandlerFunc(s.handleUser)))
	mux.Handle("GET /api/user/preferences", requireKey(http.HandlerFunc(s.handleGetPreferences)))
	mux.Handle("PATCH /api/user/preferences", requireKey(http.HandlerFunc(s.handlePatchPreferences)))

	// Version / update / prerequisite surfaces (Agent API v1 System group).
	mux.Handle("GET /api/version", requireKey(http.HandlerFunc(s.handleVersion)))
	mux.Handle("GET /api/app/updates/check", requireKey(http.HandlerFunc(s.handleUpdateCheck)))
	mux.Handle("POST /api/app/updates/apply", requireKey(http.HandlerFunc(s.handleUpdateApply)))
	mux.Handle("GET /api/provisioning/status", requireKey(http.HandlerFunc(s.handleProvisioningStatus)))

	// Swap information (Agent API v1 Swap Management group, read-only —
	// Mark's ruling: the Go agent serves the swap information zoneweaver
	// serves; add/remove are OmniOS semantics and deliberately absent).
	mux.Handle("GET /api/system/swap/summary", requireKey(http.HandlerFunc(s.handleSwapSummary)))
	mux.Handle("GET /api/system/swap/areas", requireKey(http.HandlerFunc(s.handleSwapAreas)))
	mux.Handle("GET /api/monitoring/hosts/low-swap", requireKey(http.HandlerFunc(s.handleLowSwapHosts)))

	// Host telemetry (Agent API v1 Host Monitoring group, the `monitoring`
	// token — spec-matching pass, arch item 16): realtime always; stored
	// history when monitoring.storage_enabled.
	mux.Handle("GET /api/monitoring/system/cpu", requireKey(http.HandlerFunc(s.handleMonitoringCPU)))
	mux.Handle("GET /api/monitoring/system/memory", requireKey(http.HandlerFunc(s.handleMonitoringMemory)))
	mux.Handle("GET /api/monitoring/system/load", requireKey(http.HandlerFunc(s.handleMonitoringLoad)))
	mux.Handle("GET /api/monitoring/host", requireKey(http.HandlerFunc(s.handleMonitoringHost)))
	mux.Handle("GET /api/monitoring/summary", requireKey(http.HandlerFunc(s.handleMonitoringSummary)))
	mux.Handle("GET /api/monitoring/status", requireKey(http.HandlerFunc(s.handleMonitoringStatus)))
	mux.Handle("GET /api/monitoring/health", requireKey(http.HandlerFunc(s.handleMonitoringHealth)))
	mux.Handle("POST /api/monitoring/collect", requireKey(http.HandlerFunc(s.handleMonitoringCollect)))
	mux.Handle("GET /api/monitoring/network/interfaces", requireKey(http.HandlerFunc(s.handleMonitoringInterfaces)))
	mux.Handle("GET /api/monitoring/network/usage", requireKey(http.HandlerFunc(s.handleMonitoringNetworkUsage)))
	mux.Handle("GET /api/monitoring/network/ipaddresses", requireKey(http.HandlerFunc(s.handleMonitoringIPAddresses)))
	// Per-machine usage metrics from VirtualBox's OWN telemetry (Mark's ask,
	// sync 2026-07-19) — the zones/usage mirror on this hypervisor.
	mux.Handle("GET /api/monitoring/machines/usage", requireKey(http.HandlerFunc(s.handleMachineUsageMetrics)))

	// Host processes (Agent API v1 Processes group, the `processes` token —
	// arch item 15). Literal segments (find, batch-kill, stats) win over the
	// {pid} wildcards in ServeMux precedence. Deliberately absent: /{pid}/stack,
	// /{pid}/limits (pstack/plimit are illumos tools), trace/start (DTrace).
	mux.Handle("GET /api/system/processes", requireKey(http.HandlerFunc(s.handleListProcesses)))
	mux.Handle("GET /api/system/processes/find", requireKey(http.HandlerFunc(s.handleFindProcesses)))
	mux.Handle("GET /api/system/processes/stats", requireKey(http.HandlerFunc(s.handleProcessStats)))
	mux.Handle("POST /api/system/processes/batch-kill", requireKey(http.HandlerFunc(s.handleBatchKillProcesses)))
	mux.Handle("GET /api/system/processes/{pid}", requireKey(http.HandlerFunc(s.handleProcessDetails)))
	mux.Handle("GET /api/system/processes/{pid}/files", requireKey(http.HandlerFunc(s.handleProcessFiles)))
	mux.Handle("POST /api/system/processes/{pid}/signal", requireKey(http.HandlerFunc(s.handleProcessSignal)))
	mux.Handle("POST /api/system/processes/{pid}/kill", requireKey(http.HandlerFunc(s.handleProcessKill)))

	// Host power management (the `host-power` token, config-gated by
	// host_power.enabled — mutations admin-only via the central policy;
	// runlevel/single-user/fast-reboot are init semantics with no analog
	// here and are deliberately absent).
	mux.Handle("GET /api/system/host/status", requireKey(s.hostPowerGate(s.handleHostStatus)))
	mux.Handle("GET /api/system/host/uptime", requireKey(s.hostPowerGate(s.handleHostUptime)))
	mux.Handle("POST /api/system/host/shutdown", requireKey(s.hostPowerGate(s.handleHostShutdown)))
	mux.Handle("POST /api/system/host/restart", requireKey(s.hostPowerGate(s.handleHostRestart)))
	mux.Handle("POST /api/system/host/poweroff", requireKey(s.hostPowerGate(s.handleHostPoweroff)))
	mux.Handle("POST /api/system/host/halt", requireKey(s.hostPowerGate(s.handleHostHalt)))

	// System hosts file (Mark's ruling 2026-07-05: the agent controls
	// /etc/hosts on all three platforms for VM name resolution) and the DNS
	// surface beside it (the converged wire, sync 2026-07-17: one wire shape
	// with zoneweaver, per-OS mechanics — resolv.conf on Unix, netsh on
	// Windows, networksetup on macOS).
	mux.Handle("GET /api/system/hosts", requireKey(http.HandlerFunc(s.handleGetHostsFile)))
	mux.Handle("PUT /api/system/hosts", requireKey(http.HandlerFunc(s.handleUpdateHostsFile)))
	mux.Handle("GET /api/system/dns", requireKey(http.HandlerFunc(s.handleGetDNS)))
	mux.Handle("PUT /api/system/dns", requireKey(http.HandlerFunc(s.handleUpdateDNS)))

	// Host network configuration (converged wire, sync 2026-07-17):
	// /network/hostname (GET live view, PUT queues set_hostname) and the
	// /network/addresses family (GET is the live listing; mutations queue
	// zoneweaver's create/delete/enable/disable_ip_address tasks — Mark's
	// build order 2026-07-19 replaced the 501 stubs). addrobj values carry
	// slashes, so DELETE takes a {addrobj...} wildcard; Go 1.22 ServeMux
	// forbids segments after "...", so the enable/disable verbs split from
	// the one PUT {rest...} wildcard inside the handler.
	mux.Handle("GET /api/network/hostname", requireKey(http.HandlerFunc(s.handleGetHostname)))
	mux.Handle("PUT /api/network/hostname", requireKey(http.HandlerFunc(s.handleSetHostname)))
	mux.Handle("GET /api/network/addresses", requireKey(http.HandlerFunc(s.handleListNetworkAddresses)))
	mux.Handle("POST /api/network/addresses", requireKey(http.HandlerFunc(s.handleCreateNetworkAddress)))
	mux.Handle("DELETE /api/network/addresses/{addrobj...}", requireKey(http.HandlerFunc(s.handleDeleteNetworkAddress)))
	mux.Handle("PUT /api/network/addresses/{rest...}", requireKey(http.HandlerFunc(s.handleNetworkAddressAction)))
	// Static-IP picker feed (the converged cross-agent wire, sync 2026-07-18):
	// free host addresses on the default-route subnet, ARP/document-informed,
	// ADVISORY only. GET = viewer via the central policy; no capability token.
	mux.Handle("GET /api/network/ip-suggestions", requireKey(http.HandlerFunc(s.handleIPSuggestions)))
	// Network spaces (the network-spaces token — the UI topology wire, sync
	// 2026-07-19): enumerate + manage VirtualBox's host-only interfaces (with
	// DHCP), host-only networks (the 7.x vmnet family), NAT networks (with
	// port forwards + loopbacks), and the implicit internal networks
	// (read-only — VirtualBox has no intnet verbs).
	mux.Handle("GET /api/network/spaces", requireKey(http.HandlerFunc(s.handleListNetworkSpaces)))
	mux.Handle("POST /api/network/spaces/hostonly", requireKey(http.HandlerFunc(s.handleCreateHostOnlySpace)))
	mux.Handle("PUT /api/network/spaces/hostonly/{name}", requireKey(http.HandlerFunc(s.handleModifyHostOnlySpace)))
	mux.Handle("DELETE /api/network/spaces/hostonly/{name}", requireKey(http.HandlerFunc(s.handleDeleteHostOnlySpace)))
	mux.Handle("POST /api/network/spaces/hostonlynet", requireKey(http.HandlerFunc(s.handleCreateHostOnlyNet)))
	mux.Handle("PUT /api/network/spaces/hostonlynet/{name}", requireKey(http.HandlerFunc(s.handleModifyHostOnlyNet)))
	mux.Handle("DELETE /api/network/spaces/hostonlynet/{name}", requireKey(http.HandlerFunc(s.handleDeleteHostOnlyNet)))
	mux.Handle("POST /api/network/spaces/natnetwork", requireKey(http.HandlerFunc(s.handleCreateNATNetwork)))
	mux.Handle("PUT /api/network/spaces/natnetwork/{name}", requireKey(http.HandlerFunc(s.handleModifyNATNetwork)))
	mux.Handle("DELETE /api/network/spaces/natnetwork/{name}", requireKey(http.HandlerFunc(s.handleDeleteNATNetwork)))
	mux.Handle("POST /api/network/spaces/natnetwork/{name}/start", requireKey(http.HandlerFunc(s.handleStartNATNetwork)))
	mux.Handle("POST /api/network/spaces/natnetwork/{name}/stop", requireKey(http.HandlerFunc(s.handleStopNATNetwork)))

	// Database management (Agent API v1 Database Management group), across
	// every open database file. Mutations admin-only via the central policy.
	mux.Handle("GET /api/database/stats", requireKey(http.HandlerFunc(s.handleDatabaseStats)))
	mux.Handle("POST /api/database/vacuum", requireKey(http.HandlerFunc(s.handleDatabaseVacuum)))
	mux.Handle("POST /api/database/analyze", requireKey(http.HandlerFunc(s.handleDatabaseAnalyze)))
	mux.Handle("POST /api/database/cleanup", requireKey(http.HandlerFunc(s.handleDatabaseCleanup)))
	// Read-only explorer drill-down (zoneweaver's contract, shared wire): the
	// literal /database/stats wins over {db} in ServeMux precedence.
	mux.Handle("GET /api/database/{db}/tables", requireKey(http.HandlerFunc(s.handleListDatabaseTables)))
	mux.Handle("GET /api/database/{db}/tables/{table}/rows", requireKey(http.HandlerFunc(s.handleBrowseDatabaseTable)))

	// Host statistics (shared v1 stats shape). stats.public_access serves it
	// without a key (the Node agent's conditional /stats registration).
	if s.cfg.Stats.PublicAccess {
		mux.HandleFunc("GET /api/stats", s.handleStats)
	} else {
		mux.Handle("GET /api/stats", requireKey(http.HandlerFunc(s.handleStats)))
	}

	// Task queue (Agent API v1 Task Management group). Literal patterns
	// (/tasks/stats, /tasks/completed) win over the {taskId} wildcards in
	// ServeMux precedence.
	// WebSocket plane (the base's model): the authenticated /ws-ticket mints
	// a 60s ticket; upgrades authenticate by ?ticket= (browser WebSocket
	// clients cannot send the API-key headers). /tasks/{id}/stream is the
	// live task-output push.
	mux.Handle("GET /api/ws-ticket", requireKey(http.HandlerFunc(s.handleWsTicket)))
	mux.HandleFunc("GET /api/tasks/{taskId}/stream", s.handleTaskStream)

	// SSH terminal sessions (the base's SSHTerminal family): REST lifecycle
	// behind the key; the /ssh/{sessionId} WebSocket authenticates by ticket.
	// Host terminal sessions (zoneweaver's /term family — a shell on the
	// agent host as the agent's own user): REST lifecycle admin-only (the
	// auth policy's /term prefix); the /term/{sessionId} WebSocket
	// authenticates by ticket, its session id mintable only by an admin.
	// Literal /term/start and /term/sessions win over {sessionId}.
	mux.Handle("POST /api/term/start", requireKey(http.HandlerFunc(s.handleStartTermSession)))
	mux.Handle("GET /api/term/sessions", requireKey(http.HandlerFunc(s.handleListTermSessions)))
	mux.Handle("GET /api/term/sessions/{sessionId}", requireKey(http.HandlerFunc(s.handleTermSessionInfo)))
	mux.Handle("DELETE /api/term/sessions/{sessionId}/stop", requireKey(http.HandlerFunc(s.handleStopTermSession)))
	mux.HandleFunc("GET /api/term/{sessionId}", s.handleTermSocket)

	mux.Handle("POST /api/machines/{machineName}/ssh/start", requireKey(http.HandlerFunc(s.handleStartSSHSession)))
	mux.Handle("GET /api/ssh/sessions", requireKey(http.HandlerFunc(s.handleListSSHSessions)))
	mux.Handle("GET /api/ssh/sessions/{sessionId}", requireKey(http.HandlerFunc(s.handleSSHSessionInfo)))
	mux.Handle("DELETE /api/ssh/sessions/{sessionId}/stop", requireKey(http.HandlerFunc(s.handleStopSSHSession)))
	mux.HandleFunc("GET /api/ssh/{sessionId}", s.handleSSHSocket)

	mux.Handle("GET /api/tasks", requireKey(http.HandlerFunc(s.handleListTasks)))
	mux.Handle("GET /api/tasks/stats", requireKey(http.HandlerFunc(s.handleTaskStats)))
	mux.Handle("GET /api/tasks/{taskId}", requireKey(http.HandlerFunc(s.handleTaskDetails)))
	mux.Handle("GET /api/tasks/{taskId}/output", requireKey(http.HandlerFunc(s.handleTaskOutput)))
	mux.Handle("DELETE /api/tasks/completed", requireKey(http.HandlerFunc(s.handleClearCompletedTasks)))
	mux.Handle("DELETE /api/tasks/{taskId}", requireKey(http.HandlerFunc(s.handleCancelTask)))

	// Machines (Agent API v1, canonical /machines/* noun only — design D-E).
	// Literal segments (ids, bulk) win over {machineName} in ServeMux
	// precedence.
	mux.Handle("GET /api/machines", requireKey(http.HandlerFunc(s.handleListMachines)))
	mux.Handle("POST /api/machines", requireKey(http.HandlerFunc(s.handleCreateMachine)))
	// Orchestration family (ordered startup/shutdown by settings.boot_priority
	// — the base's zones.orchestration).
	mux.Handle("GET /api/machines/orchestration/status", requireKey(http.HandlerFunc(s.handleOrchestrationStatus)))
	mux.Handle("POST /api/machines/orchestration/enable", requireKey(http.HandlerFunc(s.handleOrchestrationEnable)))
	mux.Handle("POST /api/machines/orchestration/disable", requireKey(http.HandlerFunc(s.handleOrchestrationDisable)))
	mux.Handle("POST /api/machines/orchestration/test", requireKey(http.HandlerFunc(s.handleOrchestrationTest)))
	mux.Handle("GET /api/machines/priorities", requireKey(http.HandlerFunc(s.handleMachinePriorities)))
	// Create-time defaults document (the wizard's "(default: …)" labels).
	mux.Handle("GET /api/machines/defaults", requireKey(http.HandlerFunc(s.handleMachineCreateDefaults)))
	// Guest OS type vocabulary (the wizard's settings.os_type dropdown).
	mux.Handle("GET /api/machines/ostypes", requireKey(http.HandlerFunc(s.handleMachineOSTypes)))
	mux.Handle("GET /api/machines/ids", requireKey(http.HandlerFunc(s.handleServerIDs)))
	mux.Handle("GET /api/machines/ids/next", requireKey(http.HandlerFunc(s.handleNextServerID)))
	mux.Handle("POST /api/machines/bulk/start", requireKey(http.HandlerFunc(s.handleBulkStart)))
	mux.Handle("POST /api/machines/bulk/stop", requireKey(http.HandlerFunc(s.handleBulkStop)))
	// OVA/OVF appliance import — export's pair (Mark's verb-survey go
	// 2026-07-12).
	mux.Handle("POST /api/machines/import", requireKey(http.HandlerFunc(s.handleImportMachine)))
	// Unattended OS install: ISO probe + the per-machine install below.
	mux.Handle("GET /api/machines/unattended/detect", requireKey(http.HandlerFunc(s.handleUnattendedDetect)))
	mux.Handle("GET /api/machines/{machineName}", requireKey(http.HandlerFunc(s.handleMachineDetails)))
	mux.Handle("PUT /api/machines/{machineName}", requireKey(http.HandlerFunc(s.handleModifyMachine)))
	// Accrue-changes cancel + apply-now (the agreed contract, 2026-07-09):
	// DELETE clears the pending set a PUT against a non-powered-off machine
	// stored; POST applies it immediately to a powered-off machine.
	mux.Handle("DELETE /api/machines/{machineName}/pending-changes", requireKey(http.HandlerFunc(s.handleClearPendingChanges)))
	mux.Handle("POST /api/machines/{machineName}/pending-changes/apply", requireKey(http.HandlerFunc(s.handleApplyPendingChanges)))
	mux.Handle("GET /api/machines/{machineName}/config", requireKey(http.HandlerFunc(s.handleMachineConfig)))
	mux.Handle("POST /api/machines/{machineName}/start", requireKey(http.HandlerFunc(s.handleStartMachine)))
	mux.Handle("POST /api/machines/{machineName}/stop", requireKey(http.HandlerFunc(s.handleStopMachine)))
	mux.Handle("POST /api/machines/{machineName}/restart", requireKey(http.HandlerFunc(s.handleRestartMachine)))
	mux.Handle("POST /api/machines/{machineName}/suspend", requireKey(http.HandlerFunc(s.handleSuspendMachine)))
	mux.Handle("POST /api/machines/{machineName}/reset", requireKey(http.HandlerFunc(s.handleResetMachine)))
	mux.Handle("POST /api/machines/{machineName}/pause", requireKey(http.HandlerFunc(s.handlePauseMachine)))
	mux.Handle("POST /api/machines/{machineName}/resume", requireKey(http.HandlerFunc(s.handleResumeMachine)))
	// NMI injection (zoneweaver's diagnostic extra, mirrored on Mark's go
	// 2026-07-12: debugvm injectnmi ↔ bhyvectl --inject-nmi). Synchronous.
	mux.Handle("POST /api/machines/{machineName}/nmi", requireKey(http.HandlerFunc(s.handleInjectNMI)))
	// movevm relocation + the guest display resize hint (verb survey).
	mux.Handle("POST /api/machines/{machineName}/move", requireKey(http.HandlerFunc(s.handleMoveMachine)))
	mux.Handle("POST /api/machines/{machineName}/display", requireKey(http.HandlerFunc(s.handleSetDisplay)))
	// USB passthrough: host device list + live attach/detach + persistent
	// capture filters (verb survey).
	mux.Handle("GET /api/system/usb", requireKey(http.HandlerFunc(s.handleListHostUSB)))
	mux.Handle("POST /api/machines/{machineName}/usb/attach", requireKey(http.HandlerFunc(s.handleUSBAttach)))
	mux.Handle("POST /api/machines/{machineName}/usb/detach", requireKey(http.HandlerFunc(s.handleUSBDetach)))
	mux.Handle("GET /api/machines/{machineName}/usb/filters", requireKey(http.HandlerFunc(s.handleListUSBFilters)))
	mux.Handle("POST /api/machines/{machineName}/usb/filters", requireKey(http.HandlerFunc(s.handleAddUSBFilter)))
	mux.Handle("DELETE /api/machines/{machineName}/usb/filters/{filterIndex}", requireKey(http.HandlerFunc(s.handleRemoveUSBFilter)))
	// UEFI Secure Boot lifecycle + Guest Additions exec (verb survey).
	mux.Handle("POST /api/machines/{machineName}/nvram/secureboot", requireKey(http.HandlerFunc(s.handleSecureBoot)))
	mux.Handle("POST /api/machines/{machineName}/guestcontrol/run", requireKey(http.HandlerFunc(s.handleGuestControlRun)))
	// Unattended OS install onto an existing machine.
	mux.Handle("POST /api/machines/{machineName}/unattended", requireKey(http.HandlerFunc(s.handleUnattendedInstall)))
	// Snapshot family (VBoxManage snapshot — yardstick 2) + the no-session
	// console screenshot (controlvm screenshotpng).
	mux.Handle("GET /api/machines/{machineName}/snapshots", requireKey(http.HandlerFunc(s.handleListSnapshots)))
	mux.Handle("POST /api/machines/{machineName}/snapshots", requireKey(http.HandlerFunc(s.handleTakeSnapshot)))
	mux.Handle("POST /api/machines/{machineName}/snapshots/{snapshotName}/restore", requireKey(http.HandlerFunc(s.handleRestoreSnapshot)))
	// snapshot_modify — rename/description-edit (the converged D14 wire,
	// sync 2026-07-17: PUT {new_name?, description?}; zoneweaver's op name).
	mux.Handle("PUT /api/machines/{machineName}/snapshots/{snapshotName}", requireKey(http.HandlerFunc(s.handleModifySnapshot)))
	mux.Handle("DELETE /api/machines/{machineName}/snapshots/{snapshotName}", requireKey(http.HandlerFunc(s.handleDeleteSnapshot)))
	mux.Handle("GET /api/machines/{machineName}/vnc/screenshot", requireKey(http.HandlerFunc(s.handleMachineScreenshot)))
	mux.Handle("GET /api/machines/{machineName}/vnc", requireKey(http.HandlerFunc(s.handleVncInfo)))
	mux.HandleFunc("GET /api/machines/{machineName}/vnc/websockify", s.handleVncWebsockify)
	mux.Handle("GET /api/machines/{machineName}/guest-properties", requireKey(http.HandlerFunc(s.handleGuestProperties)))
	// Machine launchers (SHI's Open Directory / Open FTP, Direct-mode
	// desktop): the POSTs launch on the AGENT host; GET /ftp feeds a remote
	// UI's own sftp:// handoff.
	mux.Handle("GET /api/machines/{machineName}/ftp", requireKey(http.HandlerFunc(s.handleMachineFTPInfo)))
	mux.Handle("POST /api/machines/{machineName}/open-ftp", requireKey(http.HandlerFunc(s.handleOpenMachineFTP)))
	mux.Handle("POST /api/machines/{machineName}/open-directory", requireKey(http.HandlerFunc(s.handleOpenMachineDirectory)))
	// External-applications launcher registry (config applications[] — SHI's
	// per-server app buttons, generalized): the list feeds the UI's launch
	// menu; the launch spawns the chosen tool on the agent host against the
	// machine with the connection placeholders resolved.
	mux.Handle("GET /api/applications", requireKey(http.HandlerFunc(s.handleListApplications)))
	mux.Handle("POST /api/machines/{machineName}/applications/{appName}/launch", requireKey(http.HandlerFunc(s.handleLaunchApplication)))
	// RDP launcher (Mark's settled two-target design 2026-07-09): the VRDE
	// console (base VRDP, no extpack) and a guest's own RDP service.
	mux.Handle("GET /api/machines/{machineName}/rdp", requireKey(http.HandlerFunc(s.handleMachineRDPInfo)))
	mux.Handle("POST /api/machines/{machineName}/open-rdp", requireKey(http.HandlerFunc(s.handleOpenMachineRDP)))
	// Browser-RDP (the IronRDP web client): the RDCleanPath WebSocket bridge
	// onto the VRDE port (ticket-authed) + the turnkey VRDE TLS setup
	// Enhanced security demands.
	mux.HandleFunc("GET /api/machines/{machineName}/rdp-bridge", s.handleRDPBridge)
	mux.Handle("POST /api/machines/{machineName}/vrde-tls", requireKey(http.HandlerFunc(s.handleVRDETLSSetup)))
	// The QEMU guest-agent channel (the guest-agent token, config-gated by
	// guest_agent.enabled): credential-less guest control over the COM2→pipe
	// UART — live IPs, exec, clean shutdown; no SSH, no Guest Additions.
	mux.Handle("GET /api/machines/{machineName}/guest/ping", requireKey(s.guestAgentGate(s.handleGuestPing)))
	mux.Handle("GET /api/machines/{machineName}/guest/osinfo", requireKey(s.guestAgentGate(s.handleGuestOSInfo)))
	mux.Handle("GET /api/machines/{machineName}/guest/network", requireKey(s.guestAgentGate(s.handleGuestNetwork)))
	mux.Handle("POST /api/machines/{machineName}/guest/exec", requireKey(s.guestAgentGate(s.handleGuestExec)))
	mux.Handle("GET /api/machines/{machineName}/guest/exec/{pid}", requireKey(s.guestAgentGate(s.handleGuestExecStatus)))
	mux.Handle("POST /api/machines/{machineName}/guest/shutdown", requireKey(s.guestAgentGate(s.handleGuestShutdown)))
	mux.Handle("POST /api/machines/{machineName}/guest-agent/setup", requireKey(s.guestAgentGate(s.handleGuestAgentSetup)))
	mux.Handle("POST /api/machines/{machineName}/clone", requireKey(http.HandlerFunc(s.handleCloneMachine)))
	mux.Handle("POST /api/machines/{machineName}/provision", requireKey(http.HandlerFunc(s.handleProvisionMachine)))
	mux.Handle("GET /api/machines/{machineName}/provision/status", requireKey(http.HandlerFunc(s.handleProvisionStatus)))
	mux.Handle("POST /api/machines/{machineName}/run-provisioners", requireKey(http.HandlerFunc(s.handleRunProvisioners)))
	mux.Handle("POST /api/machines/{machineName}/sync", requireKey(http.HandlerFunc(s.handleSyncMachine)))
	mux.Handle("DELETE /api/machines/{machineName}", requireKey(http.HandlerFunc(s.handleDeleteMachine)))

	// Box-template registry (zoneweaver's template model on this hypervisor:
	// downloaded boxes as clonable disk images).
	mux.Handle("GET /api/templates", requireKey(http.HandlerFunc(s.handleListTemplates)))
	mux.Handle("POST /api/templates/pull", requireKey(http.HandlerFunc(s.handlePullTemplate)))
	mux.Handle("POST /api/templates/export", requireKey(http.HandlerFunc(s.handleExportTemplate)))
	mux.Handle("POST /api/templates/publish", requireKey(http.HandlerFunc(s.handlePublishTemplate)))
	mux.Handle("GET /api/templates/{templateId}", requireKey(http.HandlerFunc(s.handleGetTemplate)))
	mux.Handle("DELETE /api/templates/{templateId}", requireKey(http.HandlerFunc(s.handleDeleteTemplate)))
	mux.Handle("POST /api/templates/{templateId}/move", requireKey(http.HandlerFunc(s.handleMoveTemplate)))
	// Host disk-medium inventory (typed disk spec, converged sync 2026-07-17):
	// every registered hdd with its provenance stamp and holders — the delete
	// flow's stamp rule made visible. GET-only, viewer via the central policy
	// (no capability token of its own).
	mux.Handle("GET /api/media", requireKey(http.HandlerFunc(s.handleListMedia)))
	// Remote-registry discovery (zoneweaver's TemplateSourceController — the
	// wizard's box-catalog feed).
	mux.Handle("GET /api/templates/sources", requireKey(http.HandlerFunc(s.handleListTemplateSources)))
	mux.Handle("GET /api/templates/remote/{sourceName}", requireKey(http.HandlerFunc(s.handleRemoteTemplates)))
	mux.Handle("GET /api/templates/remote/{sourceName}/{org}/{boxName}", requireKey(http.HandlerFunc(s.handleRemoteTemplateDetails)))
	mux.Handle("GET /api/machines/{machineName}/hosts-yml", requireKey(http.HandlerFunc(s.handleGetHostsYAML)))
	mux.Handle("PUT /api/machines/{machineName}/hosts-yml", requireKey(http.HandlerFunc(s.handlePutHostsYAML)))
	mux.Handle("GET /api/machines/{machineName}/notes", requireKey(http.HandlerFunc(s.handleGetMachineNotes)))
	mux.Handle("PUT /api/machines/{machineName}/notes", requireKey(http.HandlerFunc(s.handleUpdateMachineNotes)))
	mux.Handle("GET /api/machines/{machineName}/tags", requireKey(http.HandlerFunc(s.handleGetMachineTags)))
	mux.Handle("PUT /api/machines/{machineName}/tags", requireKey(http.HandlerFunc(s.handleUpdateMachineTags)))

	// Provisioner package registry (Agent API v1 provisioning surface, the
	// `provisioning` token — architecture §8, first slice of the
	// provisioning engine). The literal "import" segment wins over {name} in
	// ServeMux precedence.
	mux.Handle("GET /api/provisioning/bridged-interfaces", requireKey(http.HandlerFunc(s.handleBridgedInterfaces)))
	mux.Handle("GET /api/provisioning/network/status", requireKey(http.HandlerFunc(s.handleProvisioningNetworkStatus)))
	mux.Handle("POST /api/provisioning/network/setup", requireKey(http.HandlerFunc(s.handleProvisioningNetworkSetup)))
	mux.Handle("DELETE /api/provisioning/network/teardown", requireKey(http.HandlerFunc(s.handleProvisioningNetworkTeardown)))
	mux.Handle("GET /api/provisioning/provisioners", requireKey(http.HandlerFunc(s.handleListProvisioners)))
	mux.Handle("POST /api/provisioning/provisioners/import", requireKey(http.HandlerFunc(s.handleImportProvisioner)))
	mux.Handle("POST /api/provisioning/provisioners/import-upload", requireKey(http.HandlerFunc(s.handleImportUploadProvisioner)))
	mux.Handle("POST /api/provisioning/provisioners/refresh-specs", requireKey(http.HandlerFunc(s.handleRefreshProvisionerSpecs)))
	mux.Handle("POST /api/provisioning/provisioners/{name}/refresh-from-source", requireKey(http.HandlerFunc(s.handleRefreshProvisionerFromSource)))
	mux.Handle("GET /api/provisioning/provisioners/{name}", requireKey(http.HandlerFunc(s.handleProvisionerDetails)))
	mux.Handle("DELETE /api/provisioning/provisioners/{name}", requireKey(http.HandlerFunc(s.handleDeleteProvisioner)))
	mux.Handle("GET /api/provisioning/provisioners/{name}/versions/{version}", requireKey(http.HandlerFunc(s.handleProvisionerVersion)))
	mux.Handle("DELETE /api/provisioning/provisioners/{name}/versions/{version}", requireKey(http.HandlerFunc(s.handleDeleteProvisionerVersion)))
	// Share + catalog (design §7): export a version as one verified archive;
	// browse configured catalogs and install from them.
	mux.Handle("POST /api/provisioning/provisioners/{name}/versions/{version}/export", requireKey(http.HandlerFunc(s.handleExportProvisionerVersion)))
	mux.Handle("GET /api/provisioning/catalog", requireKey(http.HandlerFunc(s.handleGetCatalog)))
	mux.Handle("GET /api/provisioning/catalog/sources", requireKey(http.HandlerFunc(s.handleListCatalogSources)))
	mux.Handle("POST /api/provisioning/catalog/install", requireKey(http.HandlerFunc(s.handleCatalogInstall)))

	// The merged artifact system (the `artifacts` token, config-gated by
	// artifact_storage.enabled — Mark's ruling 2026-07-09): zoneweaver's
	// /artifacts wire contract with the merged type vocabulary, plus the SHI
	// extras (hcl-download, register). Literal segments win over {id} in
	// ServeMux precedence.
	mux.Handle("GET /api/storage/paths", requireKey(http.HandlerFunc(s.handleListLibraryPaths)))
	mux.Handle("POST /api/storage/paths", requireKey(http.HandlerFunc(s.handleCreateLibraryPath)))
	mux.Handle("PUT /api/storage/paths/{type}/{id}", requireKey(http.HandlerFunc(s.handleUpdateLibraryPath)))
	mux.Handle("DELETE /api/storage/paths/{type}/{id}", requireKey(http.HandlerFunc(s.handleDeleteLibraryPath)))
	mux.Handle("GET /api/artifacts/storage/paths", requireKey(s.assetsGate(s.handleListStoragePaths)))
	mux.Handle("POST /api/artifacts/storage/paths", requireKey(s.assetsGate(s.handleCreateStoragePath)))
	mux.Handle("PUT /api/artifacts/storage/paths/{id}", requireKey(s.assetsGate(s.handleUpdateStoragePath)))
	mux.Handle("DELETE /api/artifacts/storage/paths/{id}", requireKey(s.assetsGate(s.handleDeleteStoragePath)))
	mux.Handle("GET /api/artifacts", requireKey(s.assetsGate(s.handleListArtifacts)))
	mux.Handle("GET /api/artifacts/iso", requireKey(s.assetsGate(s.handleListISOArtifacts)))
	mux.Handle("GET /api/artifacts/image", requireKey(s.assetsGate(s.handleListImageArtifacts)))
	mux.Handle("GET /api/artifacts/stats", requireKey(s.assetsGate(s.handleArtifactStats)))
	mux.Handle("GET /api/artifacts/service/status", requireKey(s.assetsGate(s.handleArtifactServiceStatus)))
	mux.Handle("GET /api/artifacts/{id}", requireKey(s.assetsGate(s.handleArtifactDetails)))
	mux.Handle("GET /api/artifacts/{id}/download", requireKey(s.assetsGate(s.handleDownloadArtifactFile)))
	// move/copy share one {action} pattern: separate /artifacts/{id}/move and
	// /artifacts/{id}/copy patterns CONFLICT with /artifacts/upload/{taskId}
	// (neither is more specific — ServeMux panics at registration); the
	// {id}/{action} shape is a strict superset the upload pattern wins over.
	mux.Handle("POST /api/artifacts/{id}/{action}", requireKey(s.assetsGate(s.handleArtifactAction)))
	mux.Handle("POST /api/artifacts/download", requireKey(s.assetsGate(s.handleArtifactDownloadFromURL)))
	mux.Handle("POST /api/artifacts/upload/prepare", requireKey(s.assetsGate(s.handlePrepareArtifactUpload)))
	mux.Handle("POST /api/artifacts/upload/{taskId}", requireKey(s.assetsGate(s.handleUploadArtifactToTask)))
	mux.Handle("POST /api/artifacts/scan", requireKey(s.assetsGate(s.handleScanArtifacts)))
	mux.Handle("DELETE /api/artifacts/files", requireKey(s.assetsGate(s.handleDeleteArtifactFiles)))
	mux.Handle("POST /api/artifacts/hcl-download", requireKey(s.assetsGate(s.handleHCLDownload)))
	mux.Handle("POST /api/artifacts/register", requireKey(s.assetsGate(s.handleRegisterArtifact)))

	// Host file browser (the `file-browser` token, config-gated by
	// file_browser.enabled — zoneweaver's full browse + mutate/archive
	// family, Mark's 1:1 go 2026-07-12; operator-only via the central
	// policy's /filesystem rule).
	mux.Handle("GET /api/filesystem", requireKey(s.fileBrowserGate(s.handleBrowseFilesystem)))
	mux.Handle("DELETE /api/filesystem", requireKey(s.fileBrowserGate(s.handleDeleteFileItem)))
	mux.Handle("POST /api/filesystem/folder", requireKey(s.fileBrowserGate(s.handleCreateFolder)))
	mux.Handle("GET /api/filesystem/content", requireKey(s.fileBrowserGate(s.handleReadFileContent)))
	mux.Handle("PUT /api/filesystem/content", requireKey(s.fileBrowserGate(s.handleWriteFileContent)))
	mux.Handle("GET /api/filesystem/download", requireKey(s.fileBrowserGate(s.handleDownloadFile)))
	mux.Handle("POST /api/filesystem/upload", requireKey(s.fileBrowserGate(s.handleUploadFile)))
	mux.Handle("PATCH /api/filesystem/rename", requireKey(s.fileBrowserGate(s.handleRenameItem)))
	mux.Handle("PUT /api/filesystem/move", requireKey(s.fileBrowserGate(s.handleTransferItem(opFileMove, "move"))))
	mux.Handle("POST /api/filesystem/copy", requireKey(s.fileBrowserGate(s.handleTransferItem(opFileCopy, "copy"))))
	mux.Handle("POST /api/filesystem/archive/create", requireKey(s.fileBrowserGate(s.handleCreateArchive)))
	mux.Handle("POST /api/filesystem/archive/extract", requireKey(s.fileBrowserGate(s.handleExtractArchive)))
	mux.Handle("PATCH /api/filesystem/permissions", requireKey(s.fileBrowserGate(s.handleChangePermissions)))
	s.registerFilesystemExecutors()

	// Global secrets store (architecture D-C, SHI's SecretsPage categories) —
	// admin-only via the central role policy; separate from /api/config so
	// those routes keep serving just the configuration files.
	mux.Handle("GET /api/secrets", requireKey(http.HandlerFunc(s.handleGetSecrets)))
	mux.Handle("PUT /api/secrets", requireKey(http.HandlerFunc(s.handleUpdateSecrets)))

	// Configuration surface (the config contract): the engine's routes plus
	// the backup history — admin-only via the central role policy.
	s.mountConfigRoutes(mux, requireKey)

	// Interactive Agent API documentation (Swagger UI), Node-agent parity:
	// public /api-docs page + /api-docs/swagger.json, gated by configuration.
	if s.cfg.APIDocs.Enabled {
		if err := apidocs.Mount(mux); err != nil {
			return err
		}
	}

	uiFS, err := webui.FS(s.cfg.UI.Path)
	if err != nil {
		return err
	}

	// The docs site rides inside the UI artifact but is served independent of
	// ui.enabled — a docs-only (headless UI) setup still exposes /docs, same
	// as the Node agent.
	mountDocs(mux, uiFS)

	if s.cfg.UI.Enabled {
		if err := s.mountUI(mux, uiFS); err != nil {
			return err
		}
	} else {
		mux.HandleFunc("GET /{$}", s.handleRootInfo)
	}
	return nil
}
