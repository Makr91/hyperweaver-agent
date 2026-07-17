package provisioner

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nikolalohinski/gonja/v2"
	"github.com/nikolalohinski/gonja/v2/exec"
	"github.com/nikolalohinski/gonja/v2/loaders"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// Hosts.yml generation (architecture D9/D-B): the package's
// templates/Hosts.template.yml is a TRUE Jinja2 template — gonja (the
// Jinja2-faithful Go engine; Mark's dialect ruling 2026-07-06: real Jinja2
// on both agents, no Django-dialect wart) renders it with a context
// assembled in SHI's CustomProvisioner precedence order, generalized to
// every package (design §5). Undefined variables render as EMPTY STRING
// (gonja's default, StrictUndefined false — the published contract). SHI's
// ::TOKEN:: haxe.Template markers are gone: bundled templates were converted
// to Jinja2 at template-authoring time, and custom packages declare Jinja2
// in our format docs (no compatibility shim — SHI-format packages need a
// one-time template conversion to import).

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
	// Disks is the machine's disks section, passed through structured and
	// VERBATIM — exactly the networks model (converged, sync 2026-07-17):
	// inert until a template echoes it, the agent guarantees no keys.
	Disks map[string]any
	// Roles are the machine's role selections.
	Roles []RoleInput
	// UserProperties are the user's form answers, keyed by each field's
	// EXACT name (one flat map — the Field DSL's contract; the old
	// basic/advanced split died in the one cut).
	UserProperties map[string]any
	// SecretsVars are the global SECRETS_* template variables
	// (secrets.Store.TemplateVars — D-C: injected plain, by design).
	SecretsVars map[string]string
}

// BuildContext assembles the template context in the ruled precedence order
// (design §4): settings fields → per-role installer/hash/version vars +
// role-enable flags → the Field DSL's contribution (defaults merged BEFORE
// conditional evaluation, answers by exact name, hidden fields ABSENT) →
// global secrets. Later writers win. Structured views (settings, networks,
// roles) ride alongside the flattened UPPERCASE vars. resolvedAnswers is
// ResolveAnswers' output — computed by RenderHostsFile so the DSL parses
// once and an invalid one refuses the render instead of half-applying.
func BuildContext(in *GenerateInput, resolvedAnswers map[string]any) map[string]any {
	ctx := map[string]any{
		"settings": in.Settings,
		"networks": in.Networks,
		// disks ride structured only, the networks precedent exactly
		// (converged, sync 2026-07-17): no flattened twins — only settings
		// flatten to UPPERCASE vars.
		"disks": in.Disks,
		"roles": rolesContext(in.Roles),
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

	// 3. The Field DSL's contribution: defaults + answers, visibility
	// applied (a DSL-less package passed the answers through verbatim).
	for key, value := range resolvedAnswers {
		ctx[key] = value
	}

	// 4. Global secrets as SECRETS_* vars.
	for key, value := range in.SecretsVars {
		ctx[key] = value
	}
	return ctx
}

// RenderHostsFile renders the package's Hosts.template.yml with the
// assembled context and returns the Hosts.yml bytes. Template resolution is
// rooted at the package's templates directory (packageLoader), so includes
// can never escape the package.
func RenderHostsFile(in *GenerateInput) ([]byte, error) {
	if in.Version == nil {
		return nil, errors.New("no provisioner version to render from")
	}
	resolvedAnswers, err := ResolveAnswers(in.Version, in.Roles, in.UserProperties)
	if err != nil {
		return nil, err
	}
	templatesDir := filepath.Join(in.Version.Root, "templates")
	templatePath := filepath.Join(templatesDir, hostsTemplateName)
	if _, serr := os.Stat(templatePath); serr != nil {
		return nil, fmt.Errorf("package %s/%s has no templates/%s: %w",
			in.Version.Name, in.Version.Version, hostsTemplateName, serr)
	}

	template, err := exec.NewTemplate(hostsTemplateName,
		gonja.DefaultConfig, &packageLoader{root: templatesDir}, gonja.DefaultEnvironment)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", hostsTemplateName, err)
	}
	rendered, err := template.ExecuteToBytes(exec.NewContext(BuildContext(in, resolvedAnswers)))
	if err != nil {
		return nil, fmt.Errorf("render %s: %w", hostsTemplateName, err)
	}
	return rendered, nil
}

// packageLoader is the gonja template loader rooted at one package's
// templates/ directory: every resolution — the root template and every
// {% include %}/{% import %} it reaches — goes through safepath containment,
// so a template can never read outside its package (gonja's own filesystem
// loader is unrestricted; this one is THE loader the renderer uses).
type packageLoader struct {
	root string
}

// Resolve maps a template reference to its contained on-disk path. Absolute
// inputs (gonja hands back previously-resolved paths) are re-checked against
// the root; anything escaping it is refused.
func (l *packageLoader) Resolve(path string) (string, error) {
	if filepath.IsAbs(path) {
		rel, err := filepath.Rel(l.root, path)
		if err != nil {
			return "", fmt.Errorf("template path %q is outside the package: %w", path, err)
		}
		path = rel
	}
	return safepath.Under(l.root, path)
}

// Read opens a resolved template's content.
func (l *packageLoader) Read(path string) (io.Reader, error) {
	resolved, err := l.Resolve(path)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Clean(resolved))
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(raw), nil
}

// Inherit keeps children on the SAME root — nested includes stay inside the
// package's templates/ directory no matter how deep the chain goes.
func (l *packageLoader) Inherit(_ string) (loaders.Loader, error) {
	return l, nil
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

// legacyMarkerPattern spots SHI's ::TOKEN:: haxe.Template markers — dead
// syntax (Mark's D-B ruling: Jinja2 everywhere, no compatibility shim), so
// their presence in RENDERED output means the package's template was never
// converted. The engine passes them through as literal text, which would
// land as garbage in Hosts.yml.
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
