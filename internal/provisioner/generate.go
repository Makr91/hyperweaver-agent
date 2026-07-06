package provisioner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/flosch/pongo2/v6"
)

// Hosts.yml generation (architecture D9/D-B): the package's
// templates/Hosts.template.yml is a Jinja2 template — pongo2 renders it with
// a context assembled in SHI's CustomProvisioner precedence order,
// generalized to every package (design §5). SHI's ::TOKEN:: haxe.Template
// markers are gone: bundled templates were converted to Jinja2 at
// template-authoring time, and custom packages declare Jinja2 in our format
// docs (no compatibility shim — SHI-format packages need a one-time template
// conversion to import).

// hostsTemplateName is the template file every package version carries.
const hostsTemplateName = "Hosts.template.yml"

// RoleFiles carries one role's installer assignments (SHI's ServerRoleFiles,
// wire-shaped): filenames and hashes the file cache resolved.
type RoleFiles struct {
	Installer        string `json:"installer,omitempty"`
	InstallerHash    string `json:"installer_hash,omitempty"`
	InstallerVersion string `json:"installer_version,omitempty"`
	Fixpack          string `json:"fixpack,omitempty"`
	FixpackHash      string `json:"fixpack_hash,omitempty"`
	FixpackVersion   string `json:"fixpack_version,omitempty"`
	Hotfix           string `json:"hotfix,omitempty"`
	HotfixHash       string `json:"hotfix_hash,omitempty"`
	HotfixVersion    string `json:"hotfix_version,omitempty"`
}

// RoleInput is one role selection from the machine-create request. Enabled
// feeds the boolean role-gating flags (Mark's D-D ruling: the current
// 0.1.23+ convention — role-enable booleans gating when:, never
// vars:{run_tasks:}).
type RoleInput struct {
	Name    string    `json:"name"`
	Enabled bool      `json:"enabled"`
	Files   RoleFiles `json:"files"`
}

// GenerateInput is everything one Hosts.yml render consumes.
type GenerateInput struct {
	// Version is the provisioner package version whose template renders.
	Version *Version
	// Settings is the machine's settings document (hostname, domain,
	// server_id, vcpus, memory, box, network fields, …) — the Hosts.yml
	// settings vocabulary.
	Settings map[string]any
	// Networks is the machine's networks array, passed through structured.
	Networks []any
	// Roles are the machine's role selections.
	Roles []RoleInput
	// UserProperties/AdvancedProperties are the user's per-field entries
	// from the package's configuration.basicFields/advancedFields forms,
	// keyed by each field's EXACT unprefixed name (SHI rule).
	UserProperties     map[string]any
	AdvancedProperties map[string]any
	// SecretsVars are the global SECRETS_* template variables
	// (secrets.Store.TemplateVars — D-C: injected plain, by design).
	SecretsVars map[string]string
}

// BuildContext assembles the template context in CustomProvisioner
// precedence order, generalized (design §5): settings fields → per-role
// installer/hash/version vars + role-enable flags → package field defaults →
// user-entered dynamic properties → global secrets. Later writers win.
// Structured views (settings, networks, roles) ride alongside the flattened
// UPPERCASE vars so converted SHI templates and richer Jinja2 both work.
func BuildContext(in *GenerateInput) map[string]any {
	ctx := map[string]any{
		"settings": in.Settings,
		"networks": in.Networks,
		"roles":    rolesContext(in.Roles),
	}

	// 1. Server/settings fields, flattened UPPERCASE (SHI's SERVER_* style
	// comes from the converted templates' own naming; the raw field names
	// are uppercased here).
	for key, value := range in.Settings {
		ctx[sanitizeVar(key)] = value
	}

	// 2. Per-role installer vars + boolean enable flags, both casings
	// (SHI emits ::rolename::/::ROLENAME::).
	for i := range in.Roles {
		role := &in.Roles[i]
		upper := sanitizeVar(role.Name)
		lower := strings.ToLower(upper)
		ctx[lower] = role.Enabled
		ctx[upper] = role.Enabled
		roleFileVars(ctx, upper, &role.Files)
	}

	// 3. Package field defaults (metadata.configuration.basicFields/
	// advancedFields) fill only what nothing set yet.
	if in.Version != nil {
		for _, field := range configurationFields(in.Version.Metadata) {
			name, _ := field["name"].(string)
			if name == "" {
				continue
			}
			if _, present := ctx[name]; !present {
				ctx[name] = field["defaultValue"]
			}
		}
	}

	// 4. User-entered dynamic properties, exact unprefixed names (SHI rule:
	// stored and applied by the field's own name).
	for key, value := range in.UserProperties {
		ctx[key] = value
	}
	for key, value := range in.AdvancedProperties {
		ctx[key] = value
	}

	// 5. Global secrets as SECRETS_* vars.
	for key, value := range in.SecretsVars {
		ctx[key] = value
	}
	return ctx
}

// RenderHostsFile renders the package's Hosts.template.yml with the
// assembled context and returns the Hosts.yml bytes. The template set is
// rooted at the package's templates directory, so includes stay inside the
// package.
func RenderHostsFile(in *GenerateInput) ([]byte, error) {
	if in.Version == nil {
		return nil, errors.New("no provisioner version to render from")
	}
	templatesDir := filepath.Join(in.Version.Root, "templates")
	templatePath := filepath.Join(templatesDir, hostsTemplateName)
	if _, err := os.Stat(templatePath); err != nil {
		return nil, fmt.Errorf("package %s/%s has no templates/%s: %w",
			in.Version.Name, in.Version.Version, hostsTemplateName, err)
	}

	loader, err := pongo2.NewLocalFileSystemLoader(templatesDir)
	if err != nil {
		return nil, fmt.Errorf("open template dir: %w", err)
	}
	set := pongo2.NewSet("provisioner", loader)
	template, err := set.FromFile(hostsTemplateName)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", hostsTemplateName, err)
	}

	rendered, err := template.ExecuteBytes(pongo2.Context(BuildContext(in)))
	if err != nil {
		return nil, fmt.Errorf("render %s: %w", hostsTemplateName, err)
	}
	return rendered, nil
}

// rolesContext exposes the role selections structured (name/enabled/files)
// for templates that iterate instead of testing flattened flags.
func rolesContext(roles []RoleInput) []map[string]any {
	out := make([]map[string]any, 0, len(roles))
	for i := range roles {
		out = append(out, map[string]any{
			"name":    roles[i].Name,
			"enabled": roles[i].Enabled,
			"files":   roles[i].Files,
		})
	}
	return out
}

// roleFileVars flattens one role's file assignments into <ROLE>_* vars.
func roleFileVars(ctx map[string]any, upper string, files *RoleFiles) {
	assign := func(suffix, value string) {
		if value != "" {
			ctx[upper+suffix] = value
		}
	}
	assign("_INSTALLER", files.Installer)
	assign("_INSTALLER_HASH", files.InstallerHash)
	assign("_INSTALLER_VERSION", files.InstallerVersion)
	assign("_FIXPACK", files.Fixpack)
	assign("_FIXPACK_HASH", files.FixpackHash)
	assign("_FIXPACK_VERSION", files.FixpackVersion)
	assign("_HOTFIX", files.Hotfix)
	assign("_HOTFIX_HASH", files.HotfixHash)
	assign("_HOTFIX_VERSION", files.HotfixVersion)
}

// configurationFields flattens metadata.configuration.basicFields +
// advancedFields into one field list.
func configurationFields(metadata map[string]any) []map[string]any {
	fields := []map[string]any{}
	configuration, _ := metadata["configuration"].(map[string]any)
	if configuration == nil {
		return fields
	}
	for _, group := range []string{"basicFields", "advancedFields"} {
		list, _ := configuration[group].([]any)
		for _, entry := range list {
			if field, ok := entry.(map[string]any); ok {
				fields = append(fields, field)
			}
		}
	}
	return fields
}

// legacyMarkerPattern spots SHI's ::TOKEN:: haxe.Template markers — dead
// syntax (Mark's D-B ruling: Jinja2 everywhere, no compatibility shim), so
// their presence in RENDERED output means the package's template was never
// converted. pongo2 passes them through as literal text, which would land as
// garbage in Hosts.yml.
var legacyMarkerPattern = regexp.MustCompile(`::[A-Za-z_][A-Za-z0-9_]*::`)

// LegacyMarkers returns the ::TOKEN:: markers surviving in rendered output
// (nil when clean) so callers can warn that the template needs its one-time
// Jinja2 conversion.
func LegacyMarkers(rendered []byte) []string {
	found := legacyMarkerPattern.FindAll(rendered, 5)
	markers := make([]string, 0, len(found))
	for _, marker := range found {
		markers = append(markers, string(marker))
	}
	return markers
}

// sanitizeVar uppercases a name into template-variable form: hyphens and
// every other non-alphanumeric become underscores.
func sanitizeVar(name string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(name) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}
