package provisioner

import (
	"fmt"
	"net"
	"regexp"
)

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
