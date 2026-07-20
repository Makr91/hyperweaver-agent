// Package config loads and provides the agent's YAML configuration.
package config

// ProvisioningNetworkConfig controls the dedicated provisioning network (the
// base's provisioning.network block — etherstub + host VNIC + static IP +
// dhcpd on illumos). VirtualBox collapses that triple into ONE host-only
// interface, identified by host_ip because VirtualBox assigns interface names
// itself; its own DHCP server carries the base's dhcpd role, so the base's
// etherstub_name/host_vnic_name fields have no analog here. The base's
// NAT/forwarding pieces (provisioning-NIC egress) live elsewhere on
// VirtualBox: the provisioning NIC is the NAT adapter pinned at create
// (adapter 1, ssh port-forward transport — Mark's architecture 2026-07-07).
// This host-only machinery stays dormant-but-available for host-type
// networks[] entries and build-it-yourself setups.
type ProvisioningNetworkConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Subnet is the provisioning network in CIDR form.
	Subnet string `yaml:"subnet" json:"subnet"`
	// HostIP is the host's address on the network — the interface identity.
	HostIP string `yaml:"host_ip" json:"host_ip"`
	// Netmask is the network mask.
	Netmask string `yaml:"netmask" json:"netmask"`
	// DHCPServerIP is the VirtualBox DHCP server's OWN address (VirtualBox
	// requires one distinct from the interface's — the base's dhcpd binds the
	// host IP itself, which has no analog here).
	DHCPServerIP string `yaml:"dhcp_server_ip" json:"dhcp_server_ip"`
	// DHCPRangeStart/DHCPRangeEnd bound the assignable pool; fixed leases and
	// the clone allocator draw from it.
	DHCPRangeStart string `yaml:"dhcp_range_start" json:"dhcp_range_start"`
	DHCPRangeEnd   string `yaml:"dhcp_range_end"   json:"dhcp_range_end"`
}

// ProvisioningSSHConfig controls the pipeline's SSH access to guests (the
// base's provisioning.ssh block).
type ProvisioningSSHConfig struct {
	// KeyPath is the agent's own provisioning private key (generated at
	// startup when absent — ed25519). Empty selects ssh/provision_key beside
	// the configuration file.
	KeyPath string `yaml:"key_path" json:"key_path"`
	// TimeoutSeconds bounds the total wait for a guest's SSH to answer.
	TimeoutSeconds int `yaml:"timeout_seconds" json:"timeout_seconds"`
	// PollIntervalSeconds is the wait between SSH availability checks.
	PollIntervalSeconds int `yaml:"poll_interval_seconds" json:"poll_interval_seconds"`
}

// ProvisioningConfig controls the provisioning engine (architecture §8, the
// zoneweaver mechanism): the package registry, per-machine working
// directories, and the SSH/ansible pipeline knobs.
type ProvisioningConfig struct {
	// ProvisionersDir holds provisioner packages in SHI's on-disk format
	// (<name>/provisioner-collection.yml with <version>/provisioner.yml
	// trees beneath). Installer-bundled packages are extracted here on
	// startup without ever overwriting existing versions. Empty selects
	// provisioners under the data root.
	ProvisionersDir string `yaml:"provisioners_dir" json:"provisioners_dir"`
	// DefaultSyncMethod is the sync method machines without an explicit
	// spec.sync_method use (rsync | scp; SHI's global syncmethod preference).
	// Platform rules still apply on top.
	DefaultSyncMethod string `yaml:"default_sync_method" json:"default_sync_method"`
	// DefaultNetworkInterface names the host bridge interface injected into
	// the template context (DEFAULT_NETWORK_INTERFACE) when the spec sets
	// none — SHI's defaultNetworkInterface fallback, fed by
	// `VBoxManage list bridgedifs`.
	DefaultNetworkInterface string `yaml:"default_network_interface" json:"default_network_interface"`
	// MachinesDir holds the per-machine working directories: the
	// materialized provisioner copy, the rendered Hosts.yml, id-files,
	// installers, ssls trees, and the machine's media. Empty selects
	// machines under the data root.
	MachinesDir string `yaml:"machines_dir" json:"machines_dir"`
	// PlaybookTimeoutSeconds bounds one ansible-playbook run in the guest.
	PlaybookTimeoutSeconds int `yaml:"playbook_timeout_seconds" json:"playbook_timeout_seconds"`
	// AnsibleInstallTimeoutSeconds bounds the in-guest ansible/collection
	// installation steps.
	AnsibleInstallTimeoutSeconds int `yaml:"ansible_install_timeout_seconds" json:"ansible_install_timeout_seconds"`
	// HostHooks allows sequence hooks (provisioning.pre[]/post[] in a
	// machine's document) with target: host to run scripts ON THE AGENT HOST
	// (design §5, ruled 2026-07-16 — default ON for this agent; zoneweaver
	// defaults OFF, its hosts are shared). Guest-target hooks are always
	// allowed. Non-seeded packages additionally confirm once per machine.
	HostHooks bool `yaml:"host_hooks" json:"host_hooks"`
	// SSH is the pipeline's guest-access configuration.
	SSH ProvisioningSSHConfig `yaml:"ssh" json:"ssh"`
	// Network is the dedicated provisioning network.
	Network ProvisioningNetworkConfig `yaml:"network" json:"network"`
}
