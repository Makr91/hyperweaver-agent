package provisioner

// The Field DSL (provisioning design §3.1, ruled 2026-07-16):
// metadata.configuration = {groups, fields} — the ONE form definition,
// replacing basicFields/advancedFields in one cut. This file is the agent's
// authoritative half of the shared contract: import-time schema lint
// (fail-closed — unknown type is an ERROR, refusals echo the author's own
// values), the closed show_if grammar evaluator, authoritative answer
// validation (the 422 {FIELD: message} map), the render-context contribution
// (defaults merge BEFORE conditional evaluation; hidden fields ABSENT), and
// the derived schema.json (JSON Schema 2020-12) beside role-specs.yml.
// metadata.presentation and metadata.forked_from pass through verbatim —
// the lint never touches them.

import "regexp"

// fieldSchemaFile is the derived JSON Schema's name inside a version
// directory (beside role-specs.yml).
const fieldSchemaFile = "schema.json"

// fieldTypes is the CLOSED type set — growth only by deliberate additions.
var fieldTypes = map[string]bool{
	"text": true, "textarea": true, "number": true, "checkbox": true,
	"select": true, "multiselect": true, "password": true,
	"fqdn": true, "ipaddr": true, "cidr": true, "path": true,
}

// optionsSources is the closed live-picker vocabulary for select fields.
var optionsSources = map[string]bool{
	"networks": true, "datastores": true, "hosts": true, "images": true,
}

// fieldNamePattern: a field's name is the EXACT Jinja2 context key, so it
// must be a legal Jinja2 identifier.
var fieldNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// stringFields are the types whose validate vocabulary is
// min_length/max_length/pattern.
var stringFields = map[string]bool{
	"text": true, "textarea": true, "password": true,
	"fqdn": true, "ipaddr": true, "cidr": true, "path": true,
}

// FieldOption is one select/multiselect choice.
type FieldOption struct {
	Value any
	Label string
}

// FieldValidate is a field's validate block. The regex subset is enforced by
// compilation with Go's RE2 (the JS/Go-common subset — RE2 rejects the
// JS-only constructs).
type FieldValidate struct {
	Min          *float64
	Max          *float64
	MinLength    *int
	MaxLength    *int
	Pattern      string
	PatternError string
	re           *regexp.Regexp
}

// FieldGroup is one ordered form group.
type FieldGroup struct {
	Name     string
	Label    string
	Help     string
	Advanced bool
	ShowIf   any
}

// Field is one form field.
type Field struct {
	Name           string
	Label          string
	Type           string
	Group          string
	Help           string
	Default        any
	Required       bool
	Immutable      bool
	Rows           int
	IPVersion      int // ipaddr: 4 | 6 | 0 (either)
	Options        []FieldOption
	OptionsSource  string
	GenerateLength int // password generate:{length}
	Validate       *FieldValidate
	ShowIf         any
}

// FieldDSL is one package version's parsed form definition.
type FieldDSL struct {
	Groups []FieldGroup
	Fields []Field

	byName  map[string]*Field
	byGroup map[string]*FieldGroup
}
