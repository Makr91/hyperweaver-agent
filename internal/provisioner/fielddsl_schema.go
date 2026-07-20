package provisioner

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// ResolveAnswers is the render path's entry: parse the version's DSL, refuse
// an invalid one (hand-dropped packages bypass import's lint), and answer the
// context contribution. A DSL-less package passes the answers through
// verbatim — no form means free text stays legal.
func ResolveAnswers(version *Version, roles []RoleInput, answers map[string]any) (map[string]any, error) {
	dsl, problems := ParseFieldDSL(version.Metadata, manifestRoleNames(version.Metadata))
	if len(problems) > 0 {
		return nil, errors.New("package field DSL is invalid — re-import to see the lint: " +
			strings.Join(problems, "; "))
	}
	if dsl == nil {
		out := make(map[string]any, len(answers))
		for key, value := range answers {
			out[key] = value
		}
		return out, nil
	}
	return dsl.RenderAnswers(answers, roles), nil
}

// ValidateVersionAnswers runs the authoritative validation for one version:
// the {FIELD: message} map (nil-safe empty when valid), or an error when the
// package's own DSL is invalid. A DSL-less package validates nothing.
func ValidateVersionAnswers(version *Version, roles []RoleInput, answers map[string]any,
	prior map[string]any, provisionedBefore bool,
) (map[string]string, error) {
	dsl, problems := ParseFieldDSL(version.Metadata, manifestRoleNames(version.Metadata))
	if len(problems) > 0 {
		return nil, errors.New("package field DSL is invalid — re-import to see the lint: " +
			strings.Join(problems, "; "))
	}
	if dsl == nil {
		return map[string]string{}, nil
	}
	return dsl.ValidateAnswers(answers, roles, prior, provisionedBefore), nil
}

// LintVersionManifest lints one version directory's manifest DSL — the
// import-time fail-closed gate. Errors echo the author's own values inline.
func LintVersionManifest(versionRoot string) []string {
	manifest, err := readManifest(filepath.Join(versionRoot, versionManifest))
	if err != nil {
		return []string{versionManifest + ": " + err.Error()}
	}
	_, problems := ParseFieldDSL(manifest, manifestRoleNames(manifest))
	return problems
}

// BuildFieldSchema derives a version's schema.json (JSON Schema 2020-12)
// from its DSL — beside role-specs.yml, at import and refresh. A DSL-less
// version loses any stale schema. Answers (derived count, wrote).
func BuildFieldSchema(versionRoot string) (int, error) {
	manifest, err := readManifest(filepath.Join(versionRoot, versionManifest))
	if err != nil {
		return 0, err
	}
	dsl, problems := ParseFieldDSL(manifest, manifestRoleNames(manifest))
	if len(problems) > 0 {
		return 0, errors.New(strings.Join(problems, "; "))
	}
	file := filepath.Join(versionRoot, fieldSchemaFile)
	if dsl == nil {
		if rerr := os.Remove(file); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			return 0, rerr
		}
		return 0, nil
	}
	raw, err := marshalFieldSchema(manifest, dsl)
	if err != nil {
		return 0, err
	}
	if werr := safepath.WriteFile(file, raw, 0o644); werr != nil {
		return 0, werr
	}
	return len(dsl.Fields), nil
}

// marshalFieldSchema renders the derived JSON Schema document. Conditionals,
// groups, immutability, and live pickers ride x-hyperweaver-* extensions —
// the schema validates shapes; the DSL stays the authority.
func marshalFieldSchema(manifest map[string]any, dsl *FieldDSL) ([]byte, error) {
	properties := map[string]any{}
	required := []string{}
	groupsExt := []map[string]any{}
	for i := range dsl.Groups {
		group := map[string]any{"name": dsl.Groups[i].Name}
		if dsl.Groups[i].Label != "" {
			group["label"] = dsl.Groups[i].Label
		}
		if dsl.Groups[i].Advanced {
			group["advanced"] = true
		}
		if dsl.Groups[i].ShowIf != nil {
			group["show_if"] = dsl.Groups[i].ShowIf
		}
		groupsExt = append(groupsExt, group)
	}

	for i := range dsl.Fields {
		field := &dsl.Fields[i]
		property := map[string]any{}
		if field.Label != "" {
			property["title"] = field.Label
		}
		if field.Help != "" {
			property["description"] = field.Help
		}
		if field.Default != nil {
			property["default"] = field.Default
		}
		switch field.Type {
		case "number":
			property["type"] = "number"
			if field.Validate != nil {
				if field.Validate.Min != nil {
					property["minimum"] = *field.Validate.Min
				}
				if field.Validate.Max != nil {
					property["maximum"] = *field.Validate.Max
				}
			}
		case "checkbox":
			property["type"] = "boolean"
		case "select":
			if len(field.Options) > 0 {
				property["enum"] = optionValues(field.Options)
			} else {
				property["type"] = "string"
				property["x-hyperweaver-options-source"] = field.OptionsSource
			}
		case "multiselect":
			property["type"] = "array"
			property["uniqueItems"] = true
			property["items"] = map[string]any{"enum": optionValues(field.Options)}
		default:
			property["type"] = "string"
			switch field.Type {
			case "fqdn":
				property["format"] = "hostname"
			case "ipaddr":
				switch field.IPVersion {
				case 4:
					property["format"] = "ipv4"
				case 6:
					property["format"] = "ipv6"
				}
			case "password":
				property["writeOnly"] = true
			}
			if field.Validate != nil {
				if field.Validate.MinLength != nil {
					property["minLength"] = *field.Validate.MinLength
				}
				if field.Validate.MaxLength != nil {
					property["maxLength"] = *field.Validate.MaxLength
				}
				if field.Validate.Pattern != "" {
					property["pattern"] = field.Validate.Pattern
				}
			}
		}
		property["x-hyperweaver-type"] = field.Type
		if field.Group != "" {
			property["x-hyperweaver-group"] = field.Group
		}
		if field.ShowIf != nil {
			property["x-hyperweaver-show-if"] = field.ShowIf
		}
		if field.Immutable {
			property["x-hyperweaver-immutable"] = true
		}
		properties[field.Name] = property

		unconditional := field.ShowIf == nil &&
			(field.Group == "" || dsl.byGroup[field.Group] == nil || dsl.byGroup[field.Group].ShowIf == nil)
		if field.Required && unconditional {
			required = append(required, field.Name)
		}
	}
	sort.Strings(required)

	document := map[string]any{
		"$schema":              "https://json-schema.org/draft/2020-12/schema",
		"title":                metaString(manifest, "name") + " " + metaString(manifest, "version"),
		"type":                 "object",
		"properties":           properties,
		"additionalProperties": false,
		"x-hyperweaver-groups": groupsExt,
	}
	if len(required) > 0 {
		document["required"] = required
	}
	return json.MarshalIndent(document, "", "  ")
}

func optionValues(options []FieldOption) []any {
	values := make([]any, 0, len(options))
	for i := range options {
		values = append(values, options[i].Value)
	}
	return values
}
