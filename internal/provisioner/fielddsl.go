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

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

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

// manifestRoleNames reads metadata.roles[].name — the source of the
// role-enable flags show_if may reference: <name>_enabled, the manifest role
// name VERBATIM (the ruled spelling; the Jinja render context's sanitized
// flags are generate.go's separate layer).
func manifestRoleNames(metadata map[string]any) []string {
	meta, _ := metadata["metadata"].(map[string]any)
	roles, _ := meta["roles"].([]any)
	names := []string{}
	for _, entry := range roles {
		role, _ := entry.(map[string]any)
		if name, _ := role["name"].(string); name != "" {
			names = append(names, name)
		}
	}
	return names
}

// ParseFieldDSL parses and LINTS metadata.configuration. A nil DSL with no
// problems means the package ships no form (legal — the simplest valid
// package is manifest + template). ANY returned problem is fail-closed at
// import. roleNames feeds the show_if operand check.
func ParseFieldDSL(metadata map[string]any, roleNames []string) (dsl *FieldDSL, problems []string) {
	meta, _ := metadata["metadata"].(map[string]any)
	rawConfiguration, present := meta["configuration"]
	if !present || rawConfiguration == nil {
		return nil, nil
	}
	configuration, ok := rawConfiguration.(map[string]any)
	if !ok {
		return nil, []string{"metadata.configuration: must be a map with groups and fields"}
	}
	if len(configuration) == 0 {
		return nil, nil
	}

	for _, legacy := range []string{"basicFields", "advancedFields"} {
		if _, has := configuration[legacy]; has {
			problems = append(problems, "metadata.configuration."+legacy+
				": legacy field format — the DSL replaced it in ONE CUT; convert to {groups, fields}")
		}
	}

	dsl = &FieldDSL{
		byName:  map[string]*Field{},
		byGroup: map[string]*FieldGroup{},
	}

	// Legal show_if operands: role flags always — <metadata.roles[].name>_enabled,
	// the manifest name verbatim; field names as declared.
	operands := map[string]bool{}
	for _, role := range roleNames {
		operands[role+"_enabled"] = true
	}

	for i, entry := range anyList(configuration["groups"]) {
		where := fmt.Sprintf("metadata.configuration.groups[%d]", i)
		group, gok := entry.(map[string]any)
		if !gok {
			problems = append(problems, where+": must be a map")
			continue
		}
		g := FieldGroup{
			Name:     anyString(group["name"]),
			Label:    anyString(group["label"]),
			Help:     anyString(group["help"]),
			Advanced: anyBool(group["advanced"]),
			ShowIf:   group["show_if"],
		}
		if g.Name == "" {
			problems = append(problems, where+": name is required")
			continue
		}
		if _, dup := dsl.byGroup[g.Name]; dup {
			problems = append(problems, where+fmt.Sprintf(" %q: duplicate group name", g.Name))
			continue
		}
		dsl.Groups = append(dsl.Groups, g)
		dsl.byGroup[g.Name] = &dsl.Groups[len(dsl.Groups)-1]
	}

	fieldEntries := anyList(configuration["fields"])
	for i, entry := range fieldEntries {
		where := fmt.Sprintf("metadata.configuration.fields[%d]", i)
		raw, fok := entry.(map[string]any)
		if !fok {
			problems = append(problems, where+": must be a map")
			continue
		}
		field, fieldProblems := parseField(where, raw, dsl)
		problems = append(problems, fieldProblems...)
		if field == nil {
			continue
		}
		if _, dup := dsl.byName[field.Name]; dup {
			problems = append(problems, where+fmt.Sprintf(" %q: duplicate field name", field.Name))
			continue
		}
		// show_if operands = EARLIER-declared fields + role flags (the closed
		// rule) — checked before this field joins the operand set.
		if field.ShowIf != nil {
			problems = append(problems, lintCondition(where+".show_if", field.ShowIf, operands)...)
		}
		dsl.Fields = append(dsl.Fields, *field)
		dsl.byName[field.Name] = &dsl.Fields[len(dsl.Fields)-1]
		operands[field.Name] = true
	}

	// Group show_if lints after every field is known — groups wrap fields, so
	// any declared field (plus role flags) is a legal operand.
	for i := range dsl.Groups {
		if dsl.Groups[i].ShowIf != nil {
			where := fmt.Sprintf("metadata.configuration.groups[%d] %q.show_if", i, dsl.Groups[i].Name)
			problems = append(problems, lintCondition(where, dsl.Groups[i].ShowIf, operands)...)
		}
	}

	if len(problems) > 0 {
		return nil, problems
	}
	if len(dsl.Fields) == 0 && len(dsl.Groups) == 0 {
		return nil, nil
	}
	return dsl, nil
}

// parseField parses + lints one fields[] entry. nil when unusable (problems
// carry why).
func parseField(where string, raw map[string]any, dsl *FieldDSL) (field *Field, problems []string) {
	field = &Field{
		Name:          anyString(raw["name"]),
		Label:         anyString(raw["label"]),
		Type:          anyString(raw["type"]),
		Group:         anyString(raw["group"]),
		Help:          anyString(raw["help"]),
		Default:       raw["default"],
		Required:      anyBool(raw["required"]),
		Immutable:     anyBool(raw["immutable"]),
		Rows:          int(anyInt(raw["rows"], 0)),
		IPVersion:     int(anyInt(raw["version"], 0)),
		OptionsSource: anyString(raw["options_source"]),
		ShowIf:        raw["show_if"],
	}
	if field.Name == "" {
		return nil, append(problems, where+": name is required")
	}
	where += fmt.Sprintf(" %q", field.Name)
	if !fieldNamePattern.MatchString(field.Name) {
		problems = append(problems, where+": name must be a legal Jinja2 identifier ([A-Za-z_][A-Za-z0-9_]*) — it IS the template context key")
	}
	if !fieldTypes[field.Type] {
		legal := make([]string, 0, len(fieldTypes))
		for t := range fieldTypes {
			legal = append(legal, t)
		}
		sort.Strings(legal)
		problems = append(problems, where+fmt.Sprintf(": unknown type %q — the closed set is: %s",
			field.Type, strings.Join(legal, ", ")))
		return nil, problems
	}
	if field.Group != "" {
		if _, known := dsl.byGroup[field.Group]; !known {
			problems = append(problems, where+fmt.Sprintf(": group %q is not declared in groups[]", field.Group))
		}
	}
	if field.Rows != 0 && field.Type != "textarea" {
		problems = append(problems, where+": rows applies to textarea only")
	}
	if field.IPVersion != 0 {
		if field.Type != "ipaddr" {
			problems = append(problems, where+": version applies to ipaddr only")
		} else if field.IPVersion != 4 && field.IPVersion != 6 {
			problems = append(problems, where+fmt.Sprintf(": ipaddr version must be 4 or 6 (got %d)", field.IPVersion))
		}
	}

	for _, entry := range anyList(raw["options"]) {
		switch option := entry.(type) {
		case map[string]any:
			value, has := option["value"]
			if !has {
				problems = append(problems, where+": options entries in map form require a value")
				continue
			}
			field.Options = append(field.Options, FieldOption{Value: value, Label: anyString(option["label"])})
		default:
			field.Options = append(field.Options, FieldOption{Value: option, Label: anyString(option)})
		}
	}
	switch field.Type {
	case "select":
		switch {
		case field.OptionsSource != "" && len(field.Options) > 0:
			problems = append(problems, where+": options and options_source are mutually exclusive")
		case field.OptionsSource != "":
			if !optionsSources[field.OptionsSource] {
				problems = append(problems, where+fmt.Sprintf(": unknown options_source %q — the closed set is: networks, datastores, hosts, images", field.OptionsSource))
			}
		case len(field.Options) == 0:
			problems = append(problems, where+": select needs options or options_source")
		}
	case "multiselect":
		if field.OptionsSource != "" {
			problems = append(problems, where+": options_source applies to select only")
		}
		if len(field.Options) == 0 {
			problems = append(problems, where+": multiselect needs options")
		}
	default:
		if field.OptionsSource != "" || len(field.Options) > 0 {
			problems = append(problems, where+": options/options_source apply to select and multiselect only")
		}
	}

	if generate, has := raw["generate"]; has {
		if field.Type != "password" {
			problems = append(problems, where+": generate applies to password only")
		} else {
			block, gok := generate.(map[string]any)
			length := anyInt(block["length"], 0)
			if !gok || length <= 0 {
				problems = append(problems, where+": generate must be {length: <positive int>}")
			} else {
				field.GenerateLength = int(length)
			}
		}
	}
	if field.Type == "password" && field.Default != nil {
		problems = append(problems, where+": password fields cannot carry a default (masked, log/export-redacted)")
	}

	if validateRaw, has := raw["validate"]; has {
		validate, vok := validateRaw.(map[string]any)
		if !vok {
			problems = append(problems, where+".validate: must be a map")
		} else {
			field.Validate, problems = parseValidate(where+".validate", validate, field.Type, problems)
		}
	}
	return field, problems
}

// parseValidate lints one validate block against its field's type, appending
// onto the caller's problem list.
func parseValidate(where string, raw map[string]any, fieldType string, in []string) (v *FieldValidate, problems []string) {
	problems = in
	v = &FieldValidate{}
	if value, has := raw["min"]; has {
		if fieldType != "number" {
			problems = append(problems, where+".min: applies to number fields only")
		} else if f, ok := anyFloat(value); ok {
			v.Min = &f
		} else {
			problems = append(problems, where+fmt.Sprintf(".min: not a number (%v)", value))
		}
	}
	if value, has := raw["max"]; has {
		if fieldType != "number" {
			problems = append(problems, where+".max: applies to number fields only")
		} else if f, ok := anyFloat(value); ok {
			v.Max = &f
		} else {
			problems = append(problems, where+fmt.Sprintf(".max: not a number (%v)", value))
		}
	}
	for key, target := range map[string]**int{"min_length": &v.MinLength, "max_length": &v.MaxLength} {
		if value, has := raw[key]; has {
			if !stringFields[fieldType] {
				problems = append(problems, where+"."+key+": applies to string fields only")
			} else if n := anyInt(value, -1); n >= 0 {
				length := int(n)
				*target = &length
			} else {
				problems = append(problems, where+fmt.Sprintf(".%s: not a non-negative integer (%v)", key, value))
			}
		}
	}
	v.Pattern = anyString(raw["pattern"])
	v.PatternError = anyString(raw["pattern_error"])
	if v.Pattern != "" {
		if !stringFields[fieldType] {
			problems = append(problems, where+".pattern: applies to string fields only")
		}
		if v.PatternError == "" {
			problems = append(problems, where+".pattern: pattern_error is REQUIRED alongside pattern")
		}
		re, err := regexp.Compile(v.Pattern)
		if err != nil {
			problems = append(problems, where+fmt.Sprintf(".pattern: %v (the JS/Go-common regex subset)", err))
		} else {
			v.re = re
		}
	} else if v.PatternError != "" {
		problems = append(problems, where+".pattern_error: has no pattern to describe")
	}
	return v, problems
}

// lintCondition checks one show_if value against the CLOSED grammar:
// map = AND; per operand a scalar (equals), a list (IN), or a one-key map of
// not|gt|gte|lt|lte; the reserved key `any` takes a list of maps (OR).
func lintCondition(where string, condition any, operands map[string]bool) []string {
	problems := []string{}
	block, ok := condition.(map[string]any)
	if !ok {
		return []string{where + ": must be a map (the closed grammar has no expression strings)"}
	}
	for key, value := range block {
		if key == "any" {
			branches := anyList(value)
			if len(branches) == 0 {
				problems = append(problems, where+".any: must be a list of condition maps")
				continue
			}
			for i, branch := range branches {
				problems = append(problems, lintCondition(fmt.Sprintf("%s.any[%d]", where, i), branch, operands)...)
			}
			continue
		}
		if !operands[key] {
			problems = append(problems, where+fmt.Sprintf(": operand %q is not an earlier-declared field or a role-enable flag (<metadata.roles[].name>_enabled)", key))
		}
		switch spec := value.(type) {
		case map[string]any:
			if len(spec) != 1 {
				problems = append(problems, where+"."+key+": operator maps take exactly one of not, gt, gte, lt, lte")
				continue
			}
			for op, operand := range spec {
				switch op {
				case "not":
				case "gt", "gte", "lt", "lte":
					if _, numeric := anyFloat(operand); !numeric {
						problems = append(problems, where+"."+key+"."+op+fmt.Sprintf(": needs a numeric operand (%v)", operand))
					}
				default:
					problems = append(problems, where+"."+key+fmt.Sprintf(": unknown operator %q — the closed set is not, gt, gte, lt, lte", op))
				}
			}
		default:
			// Scalar (equals) or list (IN) — both closed-legal as-is.
		}
	}
	return problems
}

// evalCondition evaluates a linted show_if against the value set (map = AND;
// any = OR). Unknown structure evaluates false — lint prevents it existing.
func evalCondition(condition any, values map[string]any) bool {
	block, ok := condition.(map[string]any)
	if !ok {
		return false
	}
	for key, spec := range block {
		if key == "any" {
			matched := false
			for _, branch := range anyList(spec) {
				if evalCondition(branch, values) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
			continue
		}
		if !matchOperand(values[key], spec) {
			return false
		}
	}
	return true
}

// matchOperand applies one operand's condition: scalar equals, list IN,
// operator map.
func matchOperand(value, spec any) bool {
	switch condition := spec.(type) {
	case []any:
		for _, candidate := range condition {
			if looseEqual(value, candidate) {
				return true
			}
		}
		return false
	case map[string]any:
		for op, operand := range condition {
			switch op {
			case "not":
				if list, isList := operand.([]any); isList {
					for _, candidate := range list {
						if looseEqual(value, candidate) {
							return false
						}
					}
					return true
				}
				return !looseEqual(value, operand)
			case "gt", "gte", "lt", "lte":
				left, lok := anyFloat(value)
				right, rok := anyFloat(operand)
				if !lok || !rok {
					return false
				}
				switch op {
				case "gt":
					return left > right
				case "gte":
					return left >= right
				case "lt":
					return left < right
				default:
					return left <= right
				}
			}
		}
		return false
	default:
		return looseEqual(value, spec)
	}
}

// looseEqual compares the way both evaluators must (the shared-vector
// contract): numbers numerically across int/float/json shapes, booleans as
// booleans, everything else by canonical string form (so "5" equals 5 and
// true equals "true" — the JS-side coercion zoneweaver's evaluator shows).
func looseEqual(a, b any) bool {
	if af, aok := anyFloat(a); aok {
		if bf, bok := anyFloat(b); bok {
			return af == bf
		}
	}
	return fmt.Sprint(a) == fmt.Sprint(b)
}

// visibilityValues builds the value set conditionals evaluate against:
// defaults merged FIRST (the ruled order), answers over them, one
// <role name>_enabled flag per role selection alongside (RoleInput.Name IS
// the manifest role name — the create wire seeds roles[] from metadata.roles).
func (d *FieldDSL) visibilityValues(answers map[string]any, roles []RoleInput) map[string]any {
	values := map[string]any{}
	for i := range d.Fields {
		if d.Fields[i].Default != nil {
			values[d.Fields[i].Name] = d.Fields[i].Default
		}
	}
	for key, value := range answers {
		values[key] = value
	}
	for i := range roles {
		values[roles[i].Name+"_enabled"] = roles[i].Enabled
	}
	return values
}

// VisibleFields answers which fields are visible for a value set: a field
// hides when its own show_if is false OR its group's is.
func (d *FieldDSL) VisibleFields(values map[string]any) map[string]bool {
	groupVisible := map[string]bool{}
	for i := range d.Groups {
		visible := true
		if d.Groups[i].ShowIf != nil {
			visible = evalCondition(d.Groups[i].ShowIf, values)
		}
		groupVisible[d.Groups[i].Name] = visible
	}
	visible := map[string]bool{}
	for i := range d.Fields {
		field := &d.Fields[i]
		show := true
		if field.Group != "" {
			if groupShow, known := groupVisible[field.Group]; known {
				show = groupShow
			}
		}
		if show && field.ShowIf != nil {
			show = evalCondition(field.ShowIf, values)
		}
		visible[field.Name] = show
	}
	return visible
}

// ValidateAnswers is the authoritative pre-render validation: the returned
// map is EXACTLY the ruled 422 body — {FIELD: message}; empty means valid.
// required enforces only while visible; hidden fields skip every check (their
// answers are simply not collected); immutable compares against prior once a
// machine has provisioned.
func (d *FieldDSL) ValidateAnswers(answers map[string]any, roles []RoleInput,
	prior map[string]any, provisionedBefore bool,
) map[string]string {
	problems := map[string]string{}
	values := d.visibilityValues(answers, roles)
	visible := d.VisibleFields(values)

	for key := range answers {
		if _, declared := d.byName[key]; !declared {
			problems[key] = "not a field of this provisioner's form"
		}
	}

	for i := range d.Fields {
		field := &d.Fields[i]
		answer, answered := answers[field.Name]
		if !visible[field.Name] {
			continue
		}
		if !answered || isEmptyAnswer(answer) {
			if field.Required && field.Default == nil && field.GenerateLength == 0 {
				problems[field.Name] = "required"
			}
			continue
		}
		if message := field.validateValue(answer); message != "" {
			problems[field.Name] = message
			continue
		}
		if field.Immutable && provisionedBefore {
			if priorValue, had := prior[field.Name]; had && !looseEqual(priorValue, answer) {
				problems[field.Name] = "immutable after first provision"
			}
		}
	}
	return problems
}

// validateValue applies one field's type + validate rules to a present
// answer ("" = valid).
func (f *Field) validateValue(answer any) string {
	switch f.Type {
	case "number":
		value, ok := anyFloat(answer)
		if !ok {
			return "must be a number"
		}
		if f.Validate != nil {
			if f.Validate.Min != nil && value < *f.Validate.Min {
				return fmt.Sprintf("must be at least %v", *f.Validate.Min)
			}
			if f.Validate.Max != nil && value > *f.Validate.Max {
				return fmt.Sprintf("must be at most %v", *f.Validate.Max)
			}
		}
		return ""
	case "checkbox":
		switch answer.(type) {
		case bool:
			return ""
		default:
			return "must be true or false"
		}
	case "select":
		if f.OptionsSource != "" {
			// Live platform pickers: membership is the platform's, not the
			// manifest's — presence + scalar shape is all the agent can hold.
			if _, isList := answer.([]any); isList {
				return "must be a single value"
			}
			return ""
		}
		if !f.optionLegal(answer) {
			return "must be one of the declared options"
		}
		return ""
	case "multiselect":
		entries, ok := answer.([]any)
		if !ok {
			return "must be a list of options"
		}
		for _, entry := range entries {
			if !f.optionLegal(entry) {
				return fmt.Sprintf("%v is not one of the declared options", entry)
			}
		}
		return ""
	}

	// The string family.
	text, ok := answer.(string)
	if !ok {
		return "must be a string"
	}
	switch f.Type {
	case "fqdn":
		if !fqdnPattern.MatchString(text) {
			return "must be a fully qualified domain name"
		}
	case "ipaddr":
		ip := net.ParseIP(text)
		if ip == nil {
			return "must be an IP address"
		}
		if f.IPVersion == 4 && ip.To4() == nil {
			return "must be an IPv4 address"
		}
		if f.IPVersion == 6 && ip.To4() != nil {
			return "must be an IPv6 address"
		}
	case "cidr":
		if _, _, err := net.ParseCIDR(text); err != nil {
			return "must be CIDR notation (address/prefix)"
		}
	}
	if f.Validate != nil {
		if f.Validate.MinLength != nil && len(text) < *f.Validate.MinLength {
			return fmt.Sprintf("must be at least %d characters", *f.Validate.MinLength)
		}
		if f.Validate.MaxLength != nil && len(text) > *f.Validate.MaxLength {
			return fmt.Sprintf("must be at most %d characters", *f.Validate.MaxLength)
		}
		if f.Validate.re != nil && !f.Validate.re.MatchString(text) {
			return f.Validate.PatternError
		}
	}
	return ""
}

// optionLegal reports whether a value matches one of the field's declared
// options.
func (f *Field) optionLegal(value any) bool {
	for i := range f.Options {
		if looseEqual(f.Options[i].Value, value) {
			return true
		}
	}
	return false
}

// isEmptyAnswer treats null and "" as unanswered (a cleared form field).
func isEmptyAnswer(value any) bool {
	if value == nil {
		return true
	}
	if text, ok := value.(string); ok {
		return text == ""
	}
	return false
}

// RenderAnswers is the DSL's render-context contribution: defaults merged
// BEFORE conditional evaluation, answers by exact field name over them,
// hidden fields REMOVED — their names are ABSENT from the context, so
// templates see undefined (renders empty), never a stale default.
func (d *FieldDSL) RenderAnswers(answers map[string]any, roles []RoleInput) map[string]any {
	values := d.visibilityValues(answers, roles)
	visible := d.VisibleFields(values)
	out := map[string]any{}
	for i := range d.Fields {
		field := &d.Fields[i]
		if !visible[field.Name] {
			continue
		}
		if value, has := values[field.Name]; has {
			out[field.Name] = value
		}
	}
	return out
}

// fqdnPattern: dot-separated labels, letters/digits/hyphens, no leading or
// trailing hyphen, at least two labels.
var fqdnPattern = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

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

// Loose manifest-value coercions (YAML/JSON-typed input).
func anyString(value any) string {
	s, _ := value.(string)
	return s
}

func anyBool(value any) bool {
	b, _ := value.(bool)
	return b
}

func anyList(value any) []any {
	l, _ := value.([]any)
	return l
}

func anyInt(value any, fallback int64) int64 {
	switch v := value.(type) {
	case int:
		return int64(v)
	case int64:
		return v
	case uint64:
		if v > math.MaxInt64 {
			return fallback
		}
		return int64(v)
	case float64:
		return int64(v)
	case string:
		if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			return n
		}
	}
	return fallback
}

func anyFloat(value any) (float64, bool) {
	switch v := value.(type) {
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint64:
		return float64(v), true
	case float64:
		return v, true
	case string:
		if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			return f, true
		}
	}
	return 0, false
}
