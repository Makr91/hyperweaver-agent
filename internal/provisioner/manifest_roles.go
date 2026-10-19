package provisioner

import (
	"fmt"
	"sort"
)

// ManifestRoleFile is one kind's entry under a manifest role's files: answers maps each value a picked file fills (name, hash, version, major, minor, patch, install) onto the form field that receives it.
type ManifestRoleFile struct {
	Answers map[string]string `json:"answers"`
}

// ManifestRole is one metadata.roles entry as the manifest declares it.
type ManifestRole struct {
	Name           string                      `json:"name"`
	Label          string                      `json:"label,omitempty"`
	Description    string                      `json:"description,omitempty"`
	DefaultEnabled bool                        `json:"default_enabled"`
	Required       bool                        `json:"required,omitempty"`
	Collection     string                      `json:"collection,omitempty"`
	Tags           []string                    `json:"tags,omitempty"`
	InstallerDir   string                      `json:"installer_dir,omitempty"`
	Files          map[string]ManifestRoleFile `json:"files,omitempty"`
}

var roleFileKinds = map[string]bool{"installer": true, "fixpack": true, "hotfix": true}

// ManifestRoles answers metadata.roles in manifest order; entries without a name are left out.
func ManifestRoles(metadata map[string]any) []ManifestRole {
	meta, _ := metadata["metadata"].(map[string]any)
	roles := []ManifestRole{}
	for _, entry := range anyList(meta["roles"]) {
		raw, _ := entry.(map[string]any)
		name := anyString(raw["name"])
		if name == "" {
			continue
		}
		role := ManifestRole{
			Name:           name,
			Label:          anyString(raw["label"]),
			Description:    anyString(raw["description"]),
			DefaultEnabled: anyBool(raw["default_enabled"]),
			Required:       anyBool(raw["required"]),
			Collection:     anyString(raw["collection"]),
			Tags:           anyStringList(raw["tags"]),
			InstallerDir:   anyString(raw["installer_dir"]),
		}
		if files, ok := raw["files"].(map[string]any); ok {
			role.Files = map[string]ManifestRoleFile{}
			for kind, fileRaw := range files {
				file := ManifestRoleFile{Answers: map[string]string{}}
				if fileMap, fok := fileRaw.(map[string]any); fok {
					if answers, aok := fileMap["answers"].(map[string]any); aok {
						for key, value := range answers {
							file.Answers[key] = anyString(value)
						}
					}
				}
				role.Files[kind] = file
			}
		}
		roles = append(roles, role)
	}
	return roles
}

// ManifestRole answers the manifest's entry for one role name, false when the manifest declares none.
func (v *Version) ManifestRole(name string) (ManifestRole, bool) {
	for _, role := range ManifestRoles(v.Metadata) {
		if role.Name == name {
			return role, true
		}
	}
	return ManifestRole{}, false
}

func anyStringList(value any) []string {
	switch v := value.(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, entry := range v {
			if s := anyString(entry); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func manifestRoleNames(metadata map[string]any) []string {
	roles := ManifestRoles(metadata)
	names := make([]string, 0, len(roles))
	for i := range roles {
		names = append(names, roles[i].Name)
	}
	return names
}

// lintDefaults lints metadata.defaults, the package's machine defaults the create wizard prefills from: a map whose keys are settings and disks, each a map, and networks, a list; absent is legal.
func lintDefaults(metadata map[string]any) []string {
	meta, _ := metadata["metadata"].(map[string]any)
	raw, present := meta["defaults"]
	if !present || raw == nil {
		return nil
	}
	defaults, ok := raw.(map[string]any)
	if !ok {
		return []string{"metadata.defaults: must be a map with settings, disks and networks"}
	}
	problems := []string{}
	keys := make([]string, 0, len(defaults))
	for key := range defaults {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		switch key {
		case "settings", "disks":
			if _, isMap := defaults[key].(map[string]any); !isMap {
				problems = append(problems, "metadata.defaults."+key+": must be a map")
			}
		case "networks":
			if _, isList := defaults[key].([]any); !isList {
				problems = append(problems, "metadata.defaults.networks: must be a list")
			}
		default:
			problems = append(problems, fmt.Sprintf("metadata.defaults.%s: unknown key — the closed set is: disks, networks, settings", key))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return problems
}

// lintRoles lints metadata.roles: a role declaring files needs installer_dir, every files key is installer, fixpack or hotfix, and every answers value names a declared field; declared is nil while the form itself failed its lint, which skips the answers check.
func lintRoles(metadata map[string]any, declared map[string]bool) []string {
	problems := []string{}
	for i, role := range ManifestRoles(metadata) {
		where := fmt.Sprintf("metadata.roles[%d] %q", i, role.Name)
		if role.InstallerDir != "" && !ValidName(role.InstallerDir) {
			problems = append(problems, where+fmt.Sprintf(": installer_dir %q is not usable as a directory", role.InstallerDir))
		}
		if len(role.Files) == 0 {
			continue
		}
		if role.InstallerDir == "" {
			problems = append(problems, where+": files needs installer_dir, the folder under installers/ the role reads")
		}
		kinds := make([]string, 0, len(role.Files))
		for kind := range role.Files {
			kinds = append(kinds, kind)
		}
		sort.Strings(kinds)
		for _, kind := range kinds {
			if !roleFileKinds[kind] {
				problems = append(problems, where+fmt.Sprintf(".files.%s: unknown kind — the closed set is: fixpack, hotfix, installer", kind))
				continue
			}
			if declared == nil {
				continue
			}
			keys := make([]string, 0, len(role.Files[kind].Answers))
			for key := range role.Files[kind].Answers {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				field := role.Files[kind].Answers[key]
				if !declared[field] {
					problems = append(problems, where+fmt.Sprintf(".files.%s.answers.%s: %q is not a field of metadata.configuration", kind, key, field))
				}
			}
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return problems
}
