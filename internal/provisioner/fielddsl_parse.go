package provisioner

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

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
