// Package validation evaluates values and objects against the JSON Schema documents the configuration files and the request bodies are described by, answering the first failing rule per value as a problem error.
package validation

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/problem"
)

func refTarget(ref string, document Schema) (target Schema, name string) {
	if !strings.HasPrefix(ref, "#/") {
		return nil, ""
	}
	segments := strings.Split(ref[2:], "/")
	var node any = document
	for _, segment := range segments {
		object, ok := node.(map[string]any)
		if !ok {
			return nil, ""
		}
		node = object[segment]
	}
	target, ok := node.(map[string]any)
	if !ok {
		return nil, ""
	}
	if segments[0] == "$defs" && len(segments) > 1 {
		name = segments[1]
	}
	return target, name
}

func resolve(schema, document Schema) (merged Schema, name string) {
	ref, ok := str(schema, "$ref")
	if !ok {
		return schema, ""
	}
	target, name := refTarget(ref, document)
	merged = Schema{}
	for key, value := range target {
		merged[key] = value
	}
	for key, value := range schema {
		if key != "$ref" {
			merged[key] = value
		}
	}
	return merged, name
}

func subschemaFailure(schema Schema, value any, patternName string, document Schema) *problem.Error {
	inner, innerName := resolve(schema, document)
	if innerName == "" {
		innerName = patternName
	}
	return firstFailure(inner, value, innerName, document)
}

func allOfCheck(rule Schema, value any, patternName string, document Schema) *problem.Error {
	branches, _ := rule["allOf"].([]any)
	for _, branch := range branches {
		schema, ok := branch.(map[string]any)
		if !ok {
			continue
		}
		if f := subschemaFailure(schema, value, patternName, document); f != nil {
			return f
		}
	}
	return nil
}

func notCheck(rule Schema, value any, patternName string, document Schema) *problem.Error {
	schema, ok := rule["not"].(map[string]any)
	if !ok {
		return nil
	}
	if subschemaFailure(schema, value, patternName, document) != nil {
		return nil
	}
	if patternName != "" {
		return failure("pattern", map[string]any{"pattern": patternName})
	}
	return failure("not", map[string]any{})
}

func firstFailure(rule Schema, value any, patternName string, document Schema) *problem.Error {
	checks := allChecks
	if s, ok := value.(string); ok && s == "" {
		checks = blankChecks
	}
	for _, c := range checks {
		if f := c(rule, value, patternName); f != nil {
			return f
		}
	}
	if f := allOfCheck(rule, value, patternName, document); f != nil {
		return f
	}
	return notCheck(rule, value, patternName, document)
}

func isBlank(value any) bool {
	return value == nil
}

// Value evaluates one value against one schema and answers the first failing rule, or nothing.
func Value(schema Schema, value any, document Schema) []problem.Error {
	rule, patternName := resolve(schema, document)
	if isBlank(value) {
		if required, _ := rule["required"].(bool); required {
			return []problem.Error{{Pointer: "", Rule: "required", Params: map[string]any{}}}
		}
		return nil
	}
	f := firstFailure(rule, value, patternName, document)
	if f == nil {
		return nil
	}
	f.Pointer = ""
	return []problem.Error{*f}
}

func jsonEqual(a, b any) bool {
	left, err := json.Marshal(a)
	if err != nil {
		return false
	}
	right, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return bytes.Equal(left, right)
}

// Visible reports whether a property is evaluated under its dependsOn and showWhen words.
func Visible(rule Schema, scopes []map[string]any) bool {
	dependsOn, ok := str(rule, "dependsOn")
	if !ok {
		return true
	}
	var current any
	for i := len(scopes) - 1; i >= 0; i-- {
		if scopes[i] == nil {
			continue
		}
		if value, has := scopes[i][dependsOn]; has {
			current = value
			break
		}
	}
	options, _ := rule["showWhen"].([]any)
	for _, option := range options {
		if jsonEqual(option, current) {
			return true
		}
	}
	return false
}

func passesIf(condition Schema, values map[string]any) bool {
	if condition == nil {
		return false
	}
	required, _ := condition["required"].([]any)
	for _, name := range required {
		key, _ := name.(string)
		if isBlank(values[key]) {
			return false
		}
	}
	properties, _ := condition["properties"].(map[string]any)
	for name, raw := range properties {
		rule, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		expected, has := rule["const"]
		if has && !jsonEqual(values[name], expected) {
			return false
		}
	}
	return true
}

func requiredOf(schema Schema, values map[string]any) map[string]bool {
	required := map[string]bool{}
	list, _ := schema["required"].([]any)
	for _, name := range list {
		if key, ok := name.(string); ok {
			required[key] = true
		}
	}
	dependent, _ := schema["dependentRequired"].(map[string]any)
	for key, needs := range dependent {
		value := values[key]
		if isBlank(value) {
			continue
		}
		if b, ok := value.(bool); ok && !b {
			continue
		}
		names, _ := needs.([]any)
		for _, name := range names {
			if n, ok := name.(string); ok {
				required[n] = true
			}
		}
	}
	condition, _ := schema["if"].(map[string]any)
	if passesIf(condition, values) {
		then, _ := schema["then"].(map[string]any)
		names, _ := then["required"].([]any)
		for _, name := range names {
			if n, ok := name.(string); ok {
				required[n] = true
			}
		}
	}
	return required
}

func escape(segment string) string {
	return strings.ReplaceAll(strings.ReplaceAll(segment, "~", "~0"), "/", "~1")
}

func walkMap(item Schema, values any, scopes []map[string]any, base string, document Schema, errors *[]problem.Error) {
	entries, _ := values.(map[string]any)
	for key, entry := range entries {
		pointer := base + "/" + escape(key)
		if _, hasProperties := item["properties"]; hasProperties {
			child, _ := entry.(map[string]any)
			if child == nil {
				child = map[string]any{}
			}
			walkObject(item, child, append(scopes, child), pointer, document, errors)
			continue
		}
		for _, e := range Value(item, entry, document) {
			e.Pointer = pointer
			*errors = append(*errors, e)
		}
	}
}

func walkObject(schema Schema, values map[string]any, scopes []map[string]any, base string, document Schema, errors *[]problem.Error) {
	required := requiredOf(schema, values)
	properties, _ := schema["properties"].(map[string]any)
	for name, raw := range properties {
		property, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		rule, _ := resolve(property, document)
		if !Visible(rule, scopes) {
			continue
		}
		value := values[name]
		pointer := base + "/" + escape(name)
		if _, hasProperties := rule["properties"]; hasProperties {
			child, _ := value.(map[string]any)
			if child == nil {
				child = map[string]any{}
			}
			walkObject(rule, child, append(scopes, child), pointer, document, errors)
			continue
		}
		if additional, isMap := rule["additionalProperties"].(map[string]any); isMap {
			item, _ := resolve(additional, document)
			childScope, _ := value.(map[string]any)
			walkMap(item, value, append(scopes, childScope), pointer, document, errors)
			continue
		}
		own := Schema{}
		for key, v := range property {
			own[key] = v
		}
		own["required"] = required[name]
		result := Value(own, value, document)
		if len(result) > 0 {
			result[0].Pointer = pointer
			*errors = append(*errors, result[0])
		}
	}
}

// Object evaluates an object against an object schema and answers one entry per failing property.
func Object(schema Schema, values map[string]any, document Schema) []problem.Error {
	errors := []problem.Error{}
	if values == nil {
		values = map[string]any{}
	}
	if document == nil {
		document = schema
	}
	walkObject(schema, values, []map[string]any{values}, "", document, &errors)
	return errors
}
