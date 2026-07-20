// Package machines implements the agent's machine registry and lifecycle
// (Agent API v1 machines surface): VirtualBox VMs registered in
// agent.sqlite, kept truthful by queued discover tasks (VirtualBox
// authoritative, SHI's getRealStatus rule), and operated through tasks
// executed by the queue. Lifecycle is hypervisor commands only — the Node
// agent's ZoneManager model spoken in VBoxManage; vagrant identifies which
// project owns a VM (provenance for the provisioning phase) and never drives
// lifecycle. Machines built OUTSIDE the agent (the VirtualBox GUI, an old
// SHI install) are first-class: discovery imports them.
package machines

import (
	"encoding/json"
	"time"
)

// Machine statuses. VirtualBox state names map onto these; "configured"
// means a registry row with no VM behind it yet (SHI's clone model: no VM
// until first start).
const (
	StatusConfigured = "configured"
	StatusRunning    = "running"
	StatusStopped    = "stopped"
	StatusSuspended  = "suspended"
	StatusPaused     = "paused"
	StatusAborted    = "aborted"
	StatusStarting   = "starting"
	StatusStopping   = "stopping"
	StatusUnknown    = "unknown"
)

// Machine backings — provenance metadata (lifecycle always drives VBoxManage
// directly).
const (
	// BackingVagrant machines are owned by a vagrant project (Home) — the
	// provisioning operations run there.
	BackingVagrant = "vagrant"
	// BackingVBox machines exist only in VirtualBox.
	BackingVBox = "vbox"
)

// Machine hypervisors — the per-machine identity lifecycle dispatch keys on
// (backing stays provenance: who created the VM, never which engine drives
// it).
const (
	HypervisorVirtualBox = "virtualbox"
	HypervisorUTM        = "utm"
)

// Machine is one registry row (the Agent API v1 Machine schema); backing and
// home are this agent's dual-path fields. Configuration is the LIVE view
// (VirtualBox's machinereadable map, refreshed by reconciliation); Spec is
// the machine-create request document (settings/networks/roles/properties +
// the provisioner reference) — the user's intent, never overwritten by
// discovery.
type Machine struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	// Hostname of the machine's host
	Host string `json:"host"`
	// VirtualBox is authoritative; configured means a registry row with no VM behind it yet
	Status string `json:"status"`
	// Provenance metadata: vagrant means a vagrant project (home) owns this VM — used by provisioning operations. Lifecycle always drives VBoxManage directly.
	Backing string `json:"backing"`
	// The machine's hypervisor identity — lifecycle, modify, snapshots, and clone dispatch on it (backing stays provenance). utm machines exist on macOS agents only.
	Hypervisor string `json:"hypervisor"`
	// Vagrant project directory (vagrant-owned machines)
	Home *string `json:"home"`
	// VirtualBox machine UUID
	UUID *string `json:"uuid"`
	// Numeric server identifier (assigned at creation; see /machines/ids)
	ServerID *string `json:"server_id"`
	// In the registry but no longer present in VirtualBox
	IsOrphaned bool `json:"is_orphaned"`
	// Imported by the reconciliation sweep rather than created through the agent
	AutoDiscovered bool            `json:"auto_discovered"`
	LastSeen       *time.Time      `json:"last_seen"`
	Notes          *string         `json:"notes"`
	Tags           json.RawMessage `json:"tags"`
	// Live machine configuration (VBoxManage showvminfo --machinereadable key/value map on this agent). RUNNING machines additionally carry guest_info — the discovery sweep's stored LIVE-IP observation {ips: ["192.168.1.50"], source: "guest-agent"|"additions"|"", agent_responding: bool, checked_at}: QGA channel first, Guest Additions properties as fallback, NEVER the provisioning-plan control IP. The UI gates direct RDP/SSH/connect buttons on a non-empty ips[] straight from this LIST data (never query per machine); non-running machines lose the section. Refreshed every machines.discovery_interval sweep; connect-time target resolution stays live.
	Configuration json.RawMessage `json:"configuration"`
	// The creation document (machines this agent created; discovered VMs have none) — the user's intent, never overwritten by discovery. THE DOCUMENT SHAPE (the Hosts.yml-shaped MachineSpec, design §4), stored verbatim on the machine row. The provisioner reference is OPTIONAL — a machine is just a machine, provisioning is optional (the base's provisioner-free create). WITH a provisioner: machine_prepare renders the package's Jinja2 templates/Hosts.template.yml — at create and again before every provision — and the rendered hosts[0] drives everything: its settings/networks/disks build the VM natively (VBoxManage), and its folders/provisioning/vars/roles become the stored provisioner document the pipeline consumes. WITHOUT one: no prepare/render step exists, the spec's own settings/networks build the VM directly, finalize persists no provisioner, and a provisioner document can attach later via PUT /machines/{name} + POST /provision. Template context precedence (package-based creates): settings (also flattened UPPERCASE) → per-role <ROLE>_INSTALLER/_INSTALLER_HASH/_INSTALLER_VERSION/_FIXPACK*/_HOTFIX* vars + boolean role flags (both casings) → the Field DSL's contribution (metadata.configuration {groups, fields} — defaults merge BEFORE conditional evaluation, answers apply by exact field name, hidden fields are ABSENT from the context) → SECRETS_* vars. Structured settings/networks/disks/roles ride alongside — disks joined the context 2026-07-17 (the converged ask, the networks model exactly): the request's disks section, structured and VERBATIM, inert until a template echoes it (the agent guarantees no keys; the Provisioner's next release adds the echo). Answers are validated authoritatively pre-render: a failing create answers 422 whose body IS the {FIELD: message} map (design §3.1, ruled 2026-07-16). KEY VOCABULARY — provisioner: OPTIONAL package reference; omit it entirely for a provisioner-less machine; when present, both name and version are required and must exist in the registry. hypervisor: OPTIONAL per-machine hypervisor selection (default virtualbox); utm requires a macOS agent host and a box template (settings.box — the .box carries a box.utm bundle imported whole); other boot types are not yet supported on utm. settings: Hosts.yml settings vocabulary. hostname and domain are REQUIRED (machine_domain optionally overrides the naming domain); with machines.prefix_machine_names server_id is REQUIRED too (numeric 1-8 digits, padded to 4 — never auto-assigned; GET /machines/ids/next prefills it). box/box_version/box_arch/box_url select the template (package defaults apply); vcpus/memory/os_type/firmware_type/consoleport/consolehost/setup_wait/vagrant_user* drive the build and the pipeline. boot_order: ordered list of floppy|dvd|disk|net|none → --boot1..4 (remaining slots cleared) — the ISO-first install story with disks.cdroms. firmware_type (BIOS|UEFI) is generic — both hypervisors consume it (Hosts.rb reads it for the virtualbox AND zone providers). THE COMMUNICATOR FAMILY (the winrm convergence, sync 2026-07-17): communicator selects the guest transport — ssh (default) or winrm (Windows guests); winrm_port (default 5985, 5986 when winrm_transport is ssl), winrm_transport (default negotiate), and winrm_ssl_peer_verification (default true) tune it. Each of these FOUR keys has a RULED vagrant_-prefixed alias (vagrant_communicator, vagrant_winrm_port, vagrant_winrm_transport, vagrant_winrm_ssl_peer_verification) — these four pairs ONLY, a ruled exception to the no-alias rule; the new spelling WINS when both are present and the shadowed key is narrated as a {step: 'communicator_keys_shadowed', keys: []} task_chain entry on the provision response. networks: Hosts.yml networks vocabulary; entry i rides adapter i+2 (adapter 1 is the reserved NAT transport). dns DECLARE-normalizes at ad-hoc create: wire strings become the document's map shape [{nameserver: ip}] (converged contract, sync 2026-07-18 — the networking role hard-consumes dns[0]['nameserver']; packaged renders already emit maps). disks: OPTIONAL disks section at create (omit entirely = the SPELLED default: boot type template when settings.box is present, else none — a DISKLESS stub; attach media later via modify). THE TYPED DISK SPEC (Mark's word, sync 2026-07-17 — the ZERO-inference model): boot.type is REQUIRED whenever boot is present and is the ONLY dispatcher — template (clone settings.box's image; size = the grow-to; takes no path) | image (attach the EXISTING file at path AS-IS — never created/deleted/resized; size/volume_name refused; force: true skips the task-time attached-elsewhere pre-check) | blank (fresh VDI; size REQUIRED; sparse?/volume_name? legal; takes no path) | none (diskless; no other keys). THE DIRECTORY ADDENDUM (converged, sync 2026-07-17 — the pool/dataset mirror for VBox): blank and template entries may additionally carry directory — the agent-host folder the CREATED disk file lands in; ABSENT = the machine folder (the spelled default). The folder must already exist and be absolute — the agent NEVER creates it (task-time refusal: `<where> directory <path> is not an absolute existing directory on this host`); image entries refuse the key outright (`<where> type image does not take directory` — an image's own path already places it). Template clones name their file by volume_name (absent = "boot"), keeping the template's own extension. THE CLONE STRATEGY (frozen, sync 2026-07-19 — the converged cross-platform vocabulary): a template boot may carry clone_strategy — copy (DEFAULT everywhere, Mark's ruling: an independent full copy of the template image, exactly today's behavior) | clone (a differencing child off the template's shared multiattach clone base: the base materializes ONCE beside the template image as clone-base.vdi — a one-time full copy, promoted to multiattach — and every clone machine links from it, so creates are near-instant and siblings share the base's blocks; VirtualBox creates the child in the machine folder at the template's size, so clone takes NO size, volume_name, or directory — each is refused; the child is stamped template like any agent-created boot, and template delete gains a children gate). localize is zfs vocabulary (the cross-pool cure — no analog here, clonemedium already crosses drives) and is REFUSED, never warned; a clone_strategy on a non-template boot is refused too. additional_disks[]: type REQUIRED, image|blank only, same per-type rules — {type: "blank", size, volume_name?, sparse?, directory?, controller?, port?, device?} or {type: "image", path, force?, controller?, port?, device?} (refusal indexes are 1-based). Unknown keys in disk entries are never read for behavior and always preserved verbatim. Agent-created media (template clones, blank VDIs) are provenance-stamped at materialization (hyperweaver:source property / .hw-source sidecar — GET /media lists the stamps; delete destroys ONLY stamped media). THE DEVICE MODEL (VirtualBox's real storage surface): controllers[] declares the storage controllers ({name?, type: ide|sata|scsi|sas|nvme|virtio|usb|floppy, ports?, bootable?} — name defaults per type, e.g. "NVMe Controller"); every media entry may address one by `controller` name plus `port`/`device` (device matters on IDE — two devices per port). Omitting controllers[] creates ONE controller named "SATA Controller" of type sata — the original shape. boot lands on the FIRST controller port 0 unless it names its own controller/port/device. cdroms[]: [{path: agent-host ISO path | iso: a cached-ISO FILENAME resolved through the artifact registry (GET /artifacts/iso lists them; the file must exist in an enabled location) — EXACTLY one of the two, controller?, port?, device?}] — the attach-an-ISO-and-install-yourself flow. With a provisioner package the render's disks win. zones: DEAD ON THIS AGENT (Mark's ruling, sync 2026-07-19): zones is Solaris/bhyve configuration — zoneweaver's own section. This agent reads NOTHING from it; a document carrying one stores and survives verbatim, inert (foreign-hypervisor vocabulary, preserved like bhyve disk keys). The keys it used to drive have per-hypervisor homes now: diskif → disks.controllers[].type, bootrom → settings.firmware_type, netif → networks[].nic_type per entry (generic — Hosts.rb consumes those for both providers), and the rest under the vbox key: hostbridge → vbox.platform.chipset, acpi → vbox.platform.acpi, xhci → vbox.usb.xhci, vnc → vbox.vrde.enabled, autostart → vbox.autostart.enabled, guest_agent → vbox.guest_agent, post_provision_boot → vbox.post_provision_boot. cloud_init: OPTIONAL cloud-init section at create (enabled/dns_domain/password/resolvers/sshkey — set as guest properties under /Hyperweaver/CloudInit/). vbox: OPTIONAL vbox section at create — VirtualBox's own PER-HYPERVISOR key (Mark's ruling, sync 2026-07-19: zones is bhyve's, vbox is VirtualBox's, utm reserved; the former top-level hardware key is DEAD — its whole tree lives here now). Contents: (1) the first-class knob vocabulary, vbox.<section>.<key> grouped by VBoxManage's own usage sections: cpu (hotplug, execution_cap, profile, pae, long_mode, hwvirtex, nested_paging, large_pages, nested_hw_virt, virt_vmsave_vmload, vtx_vpid, vtx_ux, apic, x2apic, hpet, spec_ctrl, ibpb_on_vm_exit/entry, l1d_flush_on_sched/vm_entry, mds_clear_on_sched/vm_entry, arm_gic_its, cpuid_portability_level) · memory (vram, page_fusion, balloon) · graphics (controller, monitor_count, accelerate_3d) · audio (enabled, driver, controller, codec, in, out) · usb (ohci, ehci, xhci, card_reader) · integration (clipboard_mode, clipboard_file_transfers, drag_and_drop, mouse, keyboard) · platform (acpi, chipset, iommu, tpm_type, tpm_location, rtc_use_utc, paravirt_provider, ioapic, triple_fault_reset, hardware_uuid, system_uuid_le, snapshot_folder, description, groups, icon_file, default_frontend, vm_process_priority, vm_execution_engine) · firmware (boot_menu, apic, logo_fade_in/out, logo_display_time, logo_image_path, system_time_offset, pxe_debug) · recording (enabled, screens, file, max_size_mb, max_time_seconds, opts, video_fps, video_rate, video_res) · vrde (enabled, port — range strings allowed, extpack, address, auth_type, auth_library, multi_con, reuse_con, video_channel, video_channel_quality) · autostart (enabled, delay — enabled also drives the agent's startup orchestration) · serial[] ({port 1-4, io_base|"off", irq, mode, type}) · parallel[] ({port 1-2, io_base|"off", irq, device}) — values pass to VirtualBox UNVALIDATED, unknown sections/keys fail honestly; (2) directives[] = [{directive, value}], the generic modifyvm passthrough (any --flag=value) and the FINAL word after the knobs — the passthrough-only exotica (teleporter, cpuid-set, tracing/testing, guest-debug, pci-attach, plug/unplug-cpu) rides it; (3) guest_agent (boolean, default false — the QEMU guest-agent UART opt-in, the Proxmox model, under the guest_agent.enabled master gate; a document claiming serial port 2 itself always wins) and post_provision_boot (boolean, default false — cycle the machine stop→start after a successful provision run). networks[] entries additionally take per-adapter cable_connected, promisc (deny|allow-vms|allow-all), speed (kbps), boot_prio (0-4), bandwidth_group, nic_type (raw VirtualBox adapter type). notes: free-form notes, persisted onto the machine row at finalize (the base's create contract). tags: tags, persisted at finalize. roles[].files: installer assignments, resolved against the artifact registry at every prepare (artifact_storage.enabled): the named file must exist under (role, type, filename) and pass SHA-256 verification or the start FAILS; hashes are auto-filled from the registry into the template vars, and a spec-supplied hash must match the stored one. Files mount into the working copy's installers/<role>/ tree as hard links or hash-verified copies. properties: THE answers map — one flat map keyed by each Field-DSL field's EXACT name (multiselect answers are native lists). The old basic/advanced split (advanced_properties) died in the one cut. Validated authoritatively pre-render: failures answer 422 {FIELD: message}. sync_method: per-machine file-sync preference (SHI's Rsync/SCP setting), default rsync. Platform rules apply at render time: forced rsync on Windows hosts; macOS auto-falls back to SCP when the system rsync is the ancient Apple 2.x build. The EFFECTIVE value reaches the template context as settings.sync_method / SYNC_METHOD; the stored spec keeps the preference. safe_id_path: agent-host path of a Domino safe-ID file, placed under id-files per the package's id_files metadata (safe_id_dir, keep_original_name). start_after_create: POST /machines only — queue the first start immediately. remove_transport_on_completion: the wizard's per-create transport signal (the converged cross-agent key, sync 2026-07-18): true asks the provision pipeline to remove the provisioning transport NIC (the intrinsic NAT, adapter 1 — it has no networks[] entry, so a per-entry flag can never express it) after the whole-walk stamp, via the pipeline-owned power cycle (Mark's execution ruling — stop → machine_transport_remove → start; the post-removal boot gates on NOTHING). ABSENT = this agent's ruled default FALSE (keep — the home/dev model, vagrant-ssh keeps working; zoneweaver's absent-default is true, the datacenter model — knob_defaults['transport.remove_on_completion'] serves each agent's own). Finalize persists the chosen value at configuration.settings.remove_transport_on_completion; flip it later via PUT nics[] {adapter: 1, remove_on_completion}. Document networks[] entries additionally take a per-entry remove_on_completion boolean targeting their own adapters (i+2), same semantics, same cycle.
	Spec      json.RawMessage `json:"spec"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updatedAt"`
}

// VBoxTarget returns the identifier VBoxManage commands address this machine
// by: the VirtualBox UUID once known, else the machine name. Provisioned
// machines NEED the UUID — Hosts.rb names the VM itself, so the VirtualBox
// name and the registry name differ.
func (m *Machine) VBoxTarget() string {
	if m.UUID != nil && *m.UUID != "" {
		return *m.UUID
	}
	return m.Name
}

// Provisioned reports whether this machine is driven by the provisioning
// pipeline: it carries a creation spec and a working directory — lifecycle
// start goes through vagrant so the unchanged Hosts.rb does the real work.
func (m *Machine) Provisioned() bool {
	return len(m.Spec) > 0 && m.Home != nil && *m.Home != ""
}

// MapVBoxState translates a VirtualBox VMState into the machine status
// vocabulary.
func MapVBoxState(state string) string {
	switch state {
	case "running":
		return StatusRunning
	case "poweroff", "powered off":
		return StatusStopped
	case "saved":
		return StatusSuspended
	case "paused":
		return StatusPaused
	case "aborted", "aborted-saved":
		return StatusAborted
	case "starting", "restoring":
		return StatusStarting
	case "stopping", "saving":
		return StatusStopping
	default:
		return StatusUnknown
	}
}
