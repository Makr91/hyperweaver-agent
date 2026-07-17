package machines

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
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

// Configuration keys the agent owns — discovery merges the live hypervisor
// view AROUND these; they are never clobbered (zoneweaver's zone sync merges
// the same way).
var preservedConfigKeys = []string{
	"settings", "zones", "networks", "disks", "metadata",
	"provisioner", "provisioner_state", "pending_changes", "guest_info",
	"snapshots", "host_hooks_confirmed",
}

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

// Folder is one folders[] entry (zone_sync metadata shape). Type carries the
// document's per-folder transport (rsync | scp; virtualbox entries are
// skipped — VBoxSF is never used); Syncback marks guest→host pulls.
type Folder struct {
	Map         string   `json:"map"`
	To          string   `json:"to"`
	Type        string   `json:"type,omitempty"`
	Description string   `json:"description,omitempty"`
	Args        []string `json:"args,omitempty"`
	Exclude     []string `json:"exclude,omitempty"`
	Delete      bool     `json:"delete,omitempty"`
	Owner       string   `json:"owner,omitempty"`
	Group       string   `json:"group,omitempty"`
	Disabled    bool     `json:"disabled,omitempty"`
	Automount   bool     `json:"automount,omitempty"`
	Syncback    bool     `json:"syncback,omitempty"`
}

// Playbook is one provisioning.ansible.playbooks entry (zone_provision
// metadata shape). Remote is WHICH MECHANISM executes it — in-guest ansible
// (local) or ansible-playbook on the agent host (remote) — set by the reader
// from the list the document declared it in; it is never an ordering.
type Playbook struct {
	Playbook          string   `json:"playbook"`
	Remote            bool     `json:"remote,omitempty"`
	Run               string   `json:"run,omitempty"`
	InstallMode       string   `json:"install_mode,omitempty"`
	ConfigFile        string   `json:"config_file,omitempty"`
	ProvisioningPath  string   `json:"provisioning_path,omitempty"`
	Verbose           any      `json:"verbose,omitempty"`
	CompatibilityMode string   `json:"compatibility_mode,omitempty"`
	Collections       []string `json:"collections,omitempty"`
	// RemoteCollections gates the ansible-galaxy install (in-guest for local
	// playbooks, on the agent host for remote ones) — Hosts.rb's contract
	// (Mark's ruling 2026-07-07): false (the packages' own setting) means the
	// collections ship INSIDE the provisioner; only true fetches the galaxy.
	RemoteCollections bool   `json:"remote_collections,omitempty"`
	Callbacks         any    `json:"callbacks,omitempty"`
	SSHPipelining     any    `json:"ssh_pipelining,omitempty"`
	PythonInterpreter string `json:"ansible_python_interpreter,omitempty"`
	Description       string `json:"description,omitempty"`
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

// ProvisionerFolders reads folders[] (falling back to sync_folders) from the
// provisioner document — TaskChainBuilder's provisioning.folders ||
// provisioning.sync_folders.
func ProvisionerFolders(provisioner map[string]any) []Folder {
	raw, ok := provisioner["folders"].([]any)
	if !ok {
		raw, _ = provisioner["sync_folders"].([]any)
	}
	folders := make([]Folder, 0, len(raw))
	for _, entry := range raw {
		folders = append(folders, decodeInto[Folder](entry))
	}
	return folders
}

// ProvisionerPlaybooks reads EVERY playbook in the order the DOCUMENT
// prescribes (Mark's ruling 2026-07-17): the `playbooks:` groups in LIST
// ORDER, each group's local entries then its remote entries — local/remote
// is each entry's execution MECHANISM, never a phase, and the list an entry
// sits in is what sets Remote (a stray `remote:` key on the entry itself
// never does). Both real-world shapes: the object form
// (`playbooks: {local: [...], remote: [...]}`) is one group; the flat
// provisioners[] fallback is all-local.
func ProvisionerPlaybooks(provisioner map[string]any) []Playbook {
	playbooks := []Playbook{}
	appendGroup := func(group map[string]any) {
		for _, entry := range listOr(group["local"]) {
			playbook := decodeInto[Playbook](entry)
			playbook.Remote = false
			playbooks = append(playbooks, playbook)
		}
		for _, entry := range listOr(group["remote"]) {
			playbook := decodeInto[Playbook](entry)
			playbook.Remote = true
			playbooks = append(playbooks, playbook)
		}
	}
	if provisioning, ok := provisioner["provisioning"].(map[string]any); ok {
		if ansible, aok := provisioning["ansible"].(map[string]any); aok {
			switch groups := ansible["playbooks"].(type) {
			case map[string]any:
				appendGroup(groups)
			case []any:
				for _, group := range groups {
					if entry, gok := group.(map[string]any); gok {
						appendGroup(entry)
					}
				}
			}
		}
	}
	if len(playbooks) == 0 {
		for _, entry := range listOr(provisioner["provisioners"]) {
			playbook := decodeInto[Playbook](entry)
			playbook.Remote = false
			playbooks = append(playbooks, playbook)
		}
	}
	return playbooks
}

// Hook is one provisioning.pre[]/post[] sequence-hook entry (design §5's
// ruled shape, 2026-07-16): a script wrapping the WHOLE provision run.
// Defaults: target guest, on_failure abort, run always.
type Hook struct {
	Script    string `json:"script"`
	Target    string `json:"target,omitempty"`     // host | guest
	OnFailure string `json:"on_failure,omitempty"` // abort | continue
	Run       string `json:"run,omitempty"`        // always | once
}

// HostTarget reports a host-side hook.
func (h *Hook) HostTarget() bool {
	return strings.EqualFold(h.Target, "host")
}

// ProvisionerHooks reads one hook phase ("pre" | "post") from the document,
// defaults applied. Script-less entries drop.
func ProvisionerHooks(provisioner map[string]any, phase string) []Hook {
	provisioning, _ := provisioner["provisioning"].(map[string]any)
	raw, _ := provisioning[phase].([]any)
	hooks := make([]Hook, 0, len(raw))
	for _, entry := range raw {
		hook := decodeInto[Hook](entry)
		if hook.Script == "" {
			continue
		}
		if hook.Target == "" {
			hook.Target = "guest"
		}
		if hook.OnFailure == "" {
			hook.OnFailure = "abort"
		}
		if hook.Run == "" {
			hook.Run = "always"
		}
		hooks = append(hooks, hook)
	}
	return hooks
}

// FilterHooksByRun applies the hook run vocabulary: once fires only while the
// machine has never provisioned; always (the default) fires every run.
func FilterHooksByRun(hooks []Hook, provisionedBefore bool) []Hook {
	out := make([]Hook, 0, len(hooks))
	for i := range hooks {
		if hooks[i].Run == "once" && provisionedBefore {
			continue
		}
		out = append(out, hooks[i])
	}
	return out
}

// HasHostHooks reports whether the document carries ANY host-target hook —
// the pre-flight confirmation's trigger.
func HasHostHooks(provisioner map[string]any) bool {
	for _, phase := range []string{"pre", "post"} {
		for _, hook := range ProvisionerHooks(provisioner, phase) {
			if hook.HostTarget() {
				return true
			}
		}
	}
	return false
}

// ProvisionerDocker reads provisioning.docker — Hosts.rb:591-598's docker
// provisioner block (design §5: docker/docker_compose EXECUTED now): enabled
// gates the family; compose files come from docker_compose[], with Hosts.rb's
// own hyphen/underscore key tolerance preserved (its gate checks
// 'docker-compose', its loop reads 'docker_compose').
func ProvisionerDocker(provisioner map[string]any) (enabled bool, composeFiles []string) {
	provisioning, _ := provisioner["provisioning"].(map[string]any)
	docker, _ := provisioning["docker"].(map[string]any)
	if onOff(docker["enabled"]) != "on" {
		return false, nil
	}
	raw, ok := docker["docker_compose"].([]any)
	if !ok {
		raw, _ = docker["docker-compose"].([]any)
	}
	for _, entry := range raw {
		if file := stringOr(entry, ""); file != "" {
			composeFiles = append(composeFiles, file)
		}
	}
	return true, composeFiles
}

// ProvisionerShellScripts reads provisioning.shell.scripts[] — Hosts.yml's
// shell-provisioner section (core/Hosts.rb:493-497 runs them as vagrant shell
// provisioners; Mark's go 2026-07-13): the package-relative script paths, in
// list order, gated on provisioning.shell.enabled (the on/true/1/yes
// vocabulary). Disabled, absent, or empty answers nil.
func ProvisionerShellScripts(provisioner map[string]any) []string {
	provisioning, _ := provisioner["provisioning"].(map[string]any)
	shell, _ := provisioning["shell"].(map[string]any)
	if onOff(shell["enabled"]) != "on" {
		return nil
	}
	raw, _ := shell["scripts"].([]any)
	scripts := make([]string, 0, len(raw))
	for _, entry := range raw {
		if script := stringOr(entry, ""); script != "" {
			scripts = append(scripts, script)
		}
	}
	return scripts
}

// decodeInto round-trips a generic YAML/JSON value into a typed struct.
func decodeInto[T any](value any) T {
	var out T
	raw, err := json.Marshal(value)
	if err != nil {
		return out
	}
	_ = json.Unmarshal(raw, &out)
	return out
}

// HasProvisionedBefore reports a prior successful provision —
// configuration.provisioner_state.last_provisioned_at set
// (hasZoneProvisionedBefore verbatim).
func HasProvisionedBefore(config MachineConfig) bool {
	state := config.Section("provisioner_state")
	stamp, _ := state["last_provisioned_at"].(string)
	return stamp != ""
}

// SkippedPlaybook is one run-directive skip record ({playbook, run}).
type SkippedPlaybook struct {
	Playbook string `json:"playbook"`
	Run      string `json:"run"`
}

// FilterPlaybooksByRun applies Hosts.rb's run-directive semantics
// (filterPlaybooksByRun verbatim): always = every provision; not_first = only
// after a prior success; once and anything unrecognized = only when never
// provisioned.
func FilterPlaybooksByRun(playbooks []Playbook, provisionedBefore bool) (included []Playbook, skipped []SkippedPlaybook) {
	included = []Playbook{}
	skipped = []SkippedPlaybook{}
	for i := range playbooks {
		run := playbooks[i].Run
		if run == "" {
			run = "once"
		}
		var shouldRun bool
		switch run {
		case "always":
			shouldRun = true
		case "not_first":
			shouldRun = provisionedBefore
		default:
			shouldRun = !provisionedBefore
		}
		if shouldRun {
			included = append(included, playbooks[i])
		} else {
			skipped = append(skipped, SkippedPlaybook{Playbook: playbooks[i].Playbook, Run: run})
		}
	}
	return included, skipped
}

// loadSecretsFromFiles merges the provisioning base path's secrets.yml then
// .secrets.yml (loadSecretsFromFiles verbatim — later file overrides, parse
// failures warn and continue).
func loadSecretsFromFiles(basePath string) map[string]any {
	secrets := map[string]any{}
	if basePath == "" {
		return secrets
	}
	for _, name := range []string{"secrets.yml", ".secrets.yml"} {
		raw, err := os.ReadFile(filepath.Clean(filepath.Join(basePath, name)))
		if err != nil {
			continue
		}
		parsed := map[string]any{}
		if uerr := yaml.Unmarshal(raw, &parsed); uerr != nil {
			mlog().Warn("failed to load secrets file", "path", name, "error", uerr)
			continue
		}
		for key, value := range parsed {
			secrets[key] = value
		}
	}
	return secrets
}

// BuildExtraVars assembles the complete Ansible extra_vars document —
// buildExtraVarsFromZone verbatim: settings + networks + disks + secrets
// (base-path files then API overrides) + role_vars + provision_roles +
// pre/post tasks + the three version fields. The ruled-verbatim payloads
// (vars/roles/pre_tasks/post_tasks) ride as the stored document's RAW BYTES
// — json.Marshal emits RawMessage byte-verbatim, so their key order survives
// into the ansible --extra-vars JSON (a map value would alphabetize).
func BuildExtraVars(machine *Machine, config MachineConfig, basePath string) map[string]any {
	provisionerMap := config.Provisioner()
	provisionerRaw := RawObject(RawProvisioner(machine))
	secrets := loadSecretsFromFiles(basePath)
	if apiSecrets, ok := provisionerMap["secrets"].(map[string]any); ok {
		for key, value := range apiSecrets {
			secrets[key] = value
		}
	}

	// The ruled-verbatim payloads, absent sections defaulting to their empty
	// JSON shape.
	rawOr := func(key, empty string) json.RawMessage {
		if raw, ok := provisionerRaw[key]; ok {
			return raw
		}
		return json.RawMessage(empty)
	}

	// Everything below the raw four stays the map view DELIBERATELY:
	// settings/disks are agent-composed infrastructure sections, not the
	// ruled-verbatim payloads; networks NEEDS the map — fillLiveMACs resolves
	// live MACs into the RUN's variable document only (the ruled live-MAC
	// mechanism mutates this map; the stored document is never modified);
	// secrets is the merge product (base-path files + the document's secrets
	// section); the version fields keep their orDefault reads.
	return map[string]any{
		"settings":                 config.Section("settings"),
		"networks":                 config.List("networks"),
		"disks":                    config.Section("disks"),
		"secrets":                  secrets,
		"role_vars":                rawOr("vars", "{}"),
		"provision_roles":          rawOr("roles", "[]"),
		"provision_pre_tasks":      rawOr("pre_tasks", "[]"),
		"provision_post_tasks":     rawOr("post_tasks", "[]"),
		"core_provisioner_version": orDefault(provisionerMap["core_provisioner_version"], "0.0.1"),
		"provisioner_name":         orDefault(provisionerMap["provisioner_name"], "hyperweaver"),
		"provisioner_version":      orDefault(provisionerMap["provisioner_version"], "0.0.1"),
	}
}

// BuildPlaybookExtraVars merges per-playbook additions onto the base document
// (buildPlaybookExtraVars verbatim).
func BuildPlaybookExtraVars(base map[string]any, playbook *Playbook) map[string]any {
	vars := make(map[string]any, len(base)+4)
	for key, value := range base {
		vars[key] = value
	}
	if len(playbook.Collections) > 0 {
		vars["playbook_collections"] = playbook.Collections
	}
	if playbook.Callbacks != nil {
		vars["ansible_callbacks_enabled"] = playbook.Callbacks
	}
	if playbook.SSHPipelining != nil {
		vars["ansible_ssh_pipelining"] = playbook.SSHPipelining
	}
	if playbook.PythonInterpreter != "" {
		vars["ansible_python_interpreter"] = playbook.PythonInterpreter
	}
	return vars
}

func orDefault(value any, fallback string) string {
	if s, ok := value.(string); ok && s != "" {
		return s
	}
	return fallback
}

// StampProvisionerState records a successful provision on the machine row —
// the base's fresh-read + merge rule: parse failure never clobbers the
// configuration document. Only the provisioner_state section re-encodes;
// every other section's bytes ride verbatim.
func (s *Store) StampProvisionerState(ctx context.Context, name string) error {
	machine, err := s.Get(ctx, name)
	if err != nil {
		return err
	}
	sections := ParseRawConfiguration(machine)
	state := rawSectionMap(sections, "provisioner_state")
	state["last_provisioned_at"] = time.Now().UTC().Format(time.RFC3339)
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	sections["provisioner_state"] = raw
	merged, err := marshalRawConfig(sections)
	if err != nil {
		return err
	}
	return s.SetConfiguration(ctx, name, merged)
}

// SetGuestInfo records the discovery sweep's guest-agent observation on the
// machine row — configuration.guest_info ({ips[], agent_responding,
// checked_at}): the machine LIST carries it, so the UI gates direct RDP/SSH
// buttons off data it already polls instead of querying per machine. nil
// clears the section (stopped machines, honest absence). Same fresh-read +
// merge rule as every configuration write.
func (s *Store) SetGuestInfo(ctx context.Context, name string, info map[string]any) error {
	machine, err := s.Get(ctx, name)
	if err != nil {
		return err
	}
	sections := ParseRawConfiguration(machine)
	if info == nil {
		if _, ok := sections["guest_info"]; !ok {
			return nil
		}
		delete(sections, "guest_info")
	} else {
		raw, merr := json.Marshal(info)
		if merr != nil {
			return merr
		}
		sections["guest_info"] = raw
	}
	merged, err := marshalRawConfig(sections)
	if err != nil {
		return err
	}
	return s.SetConfiguration(ctx, name, merged)
}

// SetSnapshotPolicy stores (or clears, on nil) the machine's per-machine
// snapshot retention policy — configuration.snapshots, the PUT `snapshots`
// field (zoneweaver's setSnapshotPolicy: an object with a type stores
// verbatim, null clears back to the agent default). Same fresh-read + merge
// rule as every configuration write.
func (s *Store) SetSnapshotPolicy(ctx context.Context, name string, policy map[string]any) error {
	machine, err := s.Get(ctx, name)
	if err != nil {
		return err
	}
	sections := ParseRawConfiguration(machine)
	if policy == nil {
		if _, ok := sections["snapshots"]; !ok {
			return nil
		}
		delete(sections, "snapshots")
	} else {
		raw, merr := json.Marshal(policy)
		if merr != nil {
			return merr
		}
		sections["snapshots"] = raw
	}
	merged, err := marshalRawConfig(sections)
	if err != nil {
		return err
	}
	return s.SetConfiguration(ctx, name, merged)
}

// MergeConfigurationSections merges document sections into a machine's
// configuration (create-finalize's storeInfrastructureConfig and PUT's
// provisioner store share it): existing keys survive unless the update
// carries them. Each incoming value marshals INDIVIDUALLY — a
// json.RawMessage value passes through byte-verbatim, which is how the PUT
// provisioner path stores the request's own key order.
func (s *Store) MergeConfigurationSections(ctx context.Context, name string, updates map[string]any) error {
	machine, err := s.Get(ctx, name)
	if err != nil {
		return err
	}
	sections := ParseRawConfiguration(machine)
	for key, value := range updates {
		raw, merr := json.Marshal(value)
		if merr != nil {
			return merr
		}
		sections[key] = raw
	}
	merged, err := marshalRawConfig(sections)
	if err != nil {
		return err
	}
	return s.SetConfiguration(ctx, name, merged)
}

// MergeSettingsKeys merges individual keys INTO configuration.settings (PUT's
// DB-immediate credentials family — the base's provisioner-store rule applied
// one level deeper: the rest of the settings section survives untouched).
// A nil or empty-string value deletes the key.
func (s *Store) MergeSettingsKeys(ctx context.Context, name string, keys map[string]any) error {
	machine, err := s.Get(ctx, name)
	if err != nil {
		return err
	}
	sections := ParseRawConfiguration(machine)
	settings := rawSectionMap(sections, "settings")
	for key, value := range keys {
		if value == nil {
			delete(settings, key)
			continue
		}
		if text, ok := value.(string); ok && text == "" {
			delete(settings, key)
			continue
		}
		settings[key] = value
	}
	raw, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	sections["settings"] = raw
	merged, err := marshalRawConfig(sections)
	if err != nil {
		return err
	}
	return s.SetConfiguration(ctx, name, merged)
}

// MergePendingChanges merges an accrued modify body into
// configuration.pending_changes (the accrue-changes contract: per top-level
// key the last edit wins; hardware merges per section.key so successive
// edits of different knobs coexist) and returns the merged set.
func (s *Store) MergePendingChanges(ctx context.Context, name string, updates map[string]any) (map[string]any, error) {
	machine, err := s.Get(ctx, name)
	if err != nil {
		return nil, err
	}
	sections := ParseRawConfiguration(machine)
	pending := rawSectionMap(sections, "pending_changes")
	for key, value := range updates {
		if key != "hardware" {
			pending[key] = value
			continue
		}
		hardware, _ := pending["hardware"].(map[string]any)
		if hardware == nil {
			hardware = map[string]any{}
		}
		for sectionName, raw := range mapOr(value) {
			// serial[]/parallel[] are arrays — they replace whole.
			section, ok := raw.(map[string]any)
			if !ok {
				hardware[sectionName] = raw
				continue
			}
			merged, _ := hardware[sectionName].(map[string]any)
			if merged == nil {
				merged = map[string]any{}
			}
			for k, v := range section {
				merged[k] = v
			}
			hardware[sectionName] = merged
		}
		pending["hardware"] = hardware
	}
	raw, err := json.Marshal(pending)
	if err != nil {
		return nil, err
	}
	sections["pending_changes"] = raw
	merged, err := marshalRawConfig(sections)
	if err != nil {
		return nil, err
	}
	return pending, s.SetConfiguration(ctx, name, merged)
}

// ClearPendingChanges drops the accrued set (the cancel path, and the
// executor's apply-success cleanup).
func (s *Store) ClearPendingChanges(ctx context.Context, name string) error {
	machine, err := s.Get(ctx, name)
	if err != nil {
		return err
	}
	sections := ParseRawConfiguration(machine)
	if _, ok := sections["pending_changes"]; !ok {
		return nil
	}
	delete(sections, "pending_changes")
	merged, err := marshalRawConfig(sections)
	if err != nil {
		return err
	}
	return s.SetConfiguration(ctx, name, merged)
}

// MergeLiveConfiguration overlays the hypervisor's live view onto a stored
// configuration document, preserving the agent-owned section keys — the zone
// sync's merge rule: discovery refreshes reality, never the stored document.
// Preserved keys copy as RAW bytes from the existing document, so the stored
// provisioner sections never re-encode (and never alphabetize) on a sweep.
func MergeLiveConfiguration(existing, live json.RawMessage) json.RawMessage {
	merged := map[string]json.RawMessage{}
	if len(live) > 0 {
		if err := json.Unmarshal(live, &merged); err != nil {
			merged = map[string]json.RawMessage{}
		}
	}
	if len(existing) > 0 {
		previous := map[string]json.RawMessage{}
		if err := json.Unmarshal(existing, &previous); err == nil {
			for _, key := range preservedConfigKeys {
				if value, ok := previous[key]; ok {
					if _, overwritten := merged[key]; !overwritten {
						merged[key] = value
					}
				}
			}
		}
	}
	raw, err := marshalRawConfig(merged)
	if err != nil {
		return existing
	}
	return raw
}
