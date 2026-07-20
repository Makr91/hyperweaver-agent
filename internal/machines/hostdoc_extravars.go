package machines

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"
)

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
