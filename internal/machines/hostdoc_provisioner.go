package machines

import (
	"encoding/json"
	"strings"
)

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
