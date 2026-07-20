package machines

import (
	"encoding/json"
	"strconv"
	"strings"
)

// The provisioner document layer — zoneweaver's lib/ProvisionerConfigBuilder.js
// ported 1:1 (Mark's ruling: the Go agent recreates zoneweaver's mechanisms
// exactly). A machine's configuration carries the Hosts.yml document sections
// (settings/zones/networks/disks/metadata — stored by create's finalize child)
// plus `provisioner` (stored verbatim by PUT /machines/{name}) and
// `provisioner_state` (stamped by successful provision runs).
//
// Every Store configuration write here is SURGICAL (rawdoc.go): the untouched
// sections ride as verbatim bytes and only the section being written
// re-encodes — a whole-map round-trip would alphabetize the stored
// provisioner document's key order, and the document is the program.

// Credentials is the SSH credential triple extracted from settings
// (extractCredentialsFromSettings): vagrant_user / vagrant_user_pass /
// vagrant_user_private_key_path.
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
	// SSHKeyPath may be relative — resolved against the machine's
	// provisioning base path (the working directory) at use time.
	SSHKeyPath string `json:"ssh_key_path,omitempty"`
}

// MachineConfig is the parsed configuration document.
type MachineConfig map[string]any

// ParseConfiguration reads a machine row's configuration JSON (empty map when
// absent or unparsable — the base never fails on a bad config document, it
// warns and continues).
func ParseConfiguration(machine *Machine) MachineConfig {
	config := MachineConfig{}
	if len(machine.Configuration) == 0 {
		return config
	}
	if err := json.Unmarshal(machine.Configuration, &config); err != nil {
		mlog().Warn("failed to parse machine configuration", "machine", machine.Name, "error", err)
		return MachineConfig{}
	}
	return config
}

// Section returns a map-valued configuration section ({} when absent).
func (c MachineConfig) Section(key string) map[string]any {
	if section, ok := c[key].(map[string]any); ok {
		return section
	}
	return map[string]any{}
}

// List returns an array-valued configuration section (nil when absent).
func (c MachineConfig) List(key string) []any {
	if list, ok := c[key].([]any); ok {
		return list
	}
	return nil
}

// Provisioner returns the stored provisioner document (PUT /machines/{name}).
func (c MachineConfig) Provisioner() map[string]any {
	return c.Section("provisioner")
}

// ExtractCredentials reads the SSH credentials from a settings section —
// extractCredentialsFromSettings verbatim (username defaults to root only at
// use sites; validation requires vagrant_user like the base).
func ExtractCredentials(settings map[string]any) Credentials {
	credentials := Credentials{}
	if user, ok := settings["vagrant_user"].(string); ok {
		credentials.Username = user
	}
	if pass, ok := settings["vagrant_user_pass"].(string); ok {
		credentials.Password = pass
	}
	if key, ok := settings["vagrant_user_private_key_path"].(string); ok {
		credentials.SSHKeyPath = key
	}
	return credentials
}

// WinRMSettings is the resolved winrm communicator selection from settings
// (zoneweaver's shipped winrm shape, sync 2026-07-17: W-Q1..W-Q5): Enabled
// when the communicator selector says winrm; Port names the GUEST winrm port
// (ruled, no veto); Transport and SSLPeerVerification carry the document's
// winrm knobs with zoneweaver's defaults. Credentials stay the existing
// vagrant_user/vagrant_user_pass pair — the ruled alias scope is the four
// winrm key pairs ONLY, never the credential keys.
type WinRMSettings struct {
	Enabled             bool
	Port                int
	Transport           string
	SSLPeerVerification bool
}

// ExtractWinRM reads the winrm communicator settings — the alias pairs
// settings.communicator ≡ settings.vagrant_communicator, winrm_port ≡
// vagrant_winrm_port, winrm_transport ≡ vagrant_winrm_transport, and
// winrm_ssl_peer_verification ≡ vagrant_winrm_ssl_peer_verification —
// resolved at READ time only (stored documents never rewrite). When BOTH
// spellings ride the document the NEW (non-vagrant_) spelling wins and the
// shadowed vagrant_* key is reported for the caller's narration channel.
// Defaults: transport negotiate, ssl_peer_verification true, port 5985 —
// or 5986 when the RESOLVED transport is ssl and no explicit port exists.
func ExtractWinRM(settings map[string]any) (winrm WinRMSettings, shadowedKeys []string) {
	resolve := func(key string) (any, bool) {
		newValue, newOK := settings[key]
		oldValue, oldOK := settings["vagrant_"+key]
		if newOK && oldOK {
			shadowedKeys = append(shadowedKeys, "vagrant_"+key)
		}
		if newOK {
			return newValue, true
		}
		return oldValue, oldOK
	}
	winrm = WinRMSettings{Transport: "negotiate", SSLPeerVerification: true}
	if value, ok := resolve("communicator"); ok {
		winrm.Enabled = strings.EqualFold(stringOr(value, ""), "winrm")
	}
	if value, ok := resolve("winrm_transport"); ok {
		if transport := stringOr(value, ""); transport != "" {
			winrm.Transport = strings.ToLower(transport)
		}
	}
	if value, ok := resolve("winrm_ssl_peer_verification"); ok {
		switch v := value.(type) {
		case bool:
			winrm.SSLPeerVerification = v
		case string:
			if parsed, perr := strconv.ParseBool(strings.ToLower(v)); perr == nil {
				winrm.SSLPeerVerification = parsed
			}
		}
	}
	// Port AFTER transport: the ssl default (5986) keys off the RESOLVED
	// transport, and an explicit port always wins.
	if winrm.Transport == "ssl" {
		winrm.Port = 5986
	} else {
		winrm.Port = 5985
	}
	if value, ok := resolve("winrm_port"); ok {
		if port := intOr(value, 0); port > 0 {
			winrm.Port = int(port)
		}
	}
	return winrm, shadowedKeys
}

// ExtractControlIP resolves the machine's provisioning IP from networks[]:
// is_control → provisional → first-with-address ("" when none) —
// extractControlIP verbatim.
func ExtractControlIP(networks []any) string {
	byFlag := func(flag string) string {
		for _, entry := range networks {
			network, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			if enabled, _ := network[flag].(bool); !enabled {
				continue
			}
			if address, _ := network["address"].(string); address != "" {
				return address
			}
		}
		return ""
	}
	if ip := byFlag("is_control"); ip != "" {
		return ip
	}
	if ip := byFlag("provisional"); ip != "" {
		return ip
	}
	for _, entry := range networks {
		if network, ok := entry.(map[string]any); ok {
			if address, _ := network["address"].(string); address != "" {
				return address
			}
		}
	}
	return ""
}
