package configengine

import (
	"bytes"
	"encoding/json"
	"math"
	"sort"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/validation"
)

func escape(segment string) string {
	return strings.ReplaceAll(strings.ReplaceAll(segment, "~", "~0"), "/", "~1")
}

func segmentsOf(pointer string) []string {
	if pointer == "" {
		return nil
	}
	parts := strings.Split(pointer, "/")[1:]
	for i, part := range parts {
		parts[i] = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
	}
	return parts
}

func clone(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, entry := range v {
			out[key] = clone(entry)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, entry := range v {
			out[i] = clone(entry)
		}
		return out
	default:
		return v
	}
}

func normalize(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, entry := range v {
			out[key] = normalize(entry)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(v))
		for key, entry := range v {
			text, ok := key.(string)
			if !ok {
				raw, _ := json.Marshal(key)
				text = string(raw)
			}
			out[text] = normalize(entry)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, entry := range v {
			out[i] = normalize(entry)
		}
		return out
	case uint64:
		if v > math.MaxInt64 {
			return float64(v)
		}
		return int64(v)
	case int:
		return int64(v)
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return i
		}
		f, _ := v.Float64()
		return f
	default:
		return v
	}
}

func propertiesOf(schema validation.Schema) map[string]any {
	properties, _ := schema["properties"].(map[string]any)
	return properties
}

func isMapSchema(property validation.Schema) bool {
	_, ok := property["additionalProperties"].(map[string]any)
	return ok
}

func isFreeSubtree(property validation.Schema) bool {
	t, _ := property["type"].(string)
	_, hasProperties := property["properties"]
	return t == "object" && !hasProperties && !isMapSchema(property)
}

func hasDefaults(property validation.Schema) bool {
	for _, raw := range propertiesOf(property) {
		child, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if _, has := child["default"]; has {
			return true
		}
		if _, nested := child["properties"]; nested && hasDefaults(child) {
			return true
		}
	}
	return false
}

func fillDefaults(schema validation.Schema, config map[string]any) map[string]any {
	filled := map[string]any{}
	for key, value := range config {
		filled[key] = clone(value)
	}
	for key, raw := range propertiesOf(schema) {
		property, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		_, present := filled[key]
		if _, nested := property["properties"]; nested {
			if present || hasDefaults(property) {
				child, _ := filled[key].(map[string]any)
				filled[key] = fillDefaults(property, child)
			}
			continue
		}
		if d, has := property["default"]; !present && has {
			filled[key] = clone(d)
		}
	}
	return filled
}

func unknownKeys(schema validation.Schema, config map[string]any, base string) []string {
	properties := propertiesOf(schema)
	out := []string{}
	for key, value := range config {
		pointer := base + "/" + escape(key)
		raw, known := properties[key]
		property, _ := raw.(map[string]any)
		if !known || property == nil {
			out = append(out, pointer)
			continue
		}
		if _, nested := property["properties"]; nested && !isFreeSubtree(property) {
			child, _ := value.(map[string]any)
			out = append(out, unknownKeys(property, child, pointer)...)
			continue
		}
		if isMapSchema(property) {
			item := property["additionalProperties"].(map[string]any)
			if _, itemProps := item["properties"]; itemProps {
				entries, _ := value.(map[string]any)
				for entryKey, entry := range entries {
					child, _ := entry.(map[string]any)
					out = append(out, unknownKeys(item, child, pointer+"/"+escape(entryKey))...)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

func flaggedWithoutReason(schema validation.Schema, base string) []string {
	out := []string{}
	for key, raw := range propertiesOf(schema) {
		property, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		pointer := base + "/" + escape(key)
		if _, nested := property["properties"]; nested {
			out = append(out, flaggedWithoutReason(property, pointer)...)
			continue
		}
		if isMapSchema(property) {
			item := property["additionalProperties"].(map[string]any)
			if _, itemProps := item["properties"]; itemProps {
				out = append(out, flaggedWithoutReason(item, pointer+"/*")...)
			} else if flagged(item) && reasonOf(item) == "" {
				out = append(out, pointer+"/*")
			}
			continue
		}
		if flagged(property) && reasonOf(property) == "" {
			out = append(out, pointer)
		}
	}
	sort.Strings(out)
	return out
}

func flagged(property validation.Schema) bool {
	v, _ := property["requiresRestart"].(bool)
	return v
}

func reasonOf(property validation.Schema) string {
	v, _ := property["restartReason"].(string)
	return v
}

func titleOf(property validation.Schema, fallback string) string {
	if v, ok := property["title"].(string); ok && v != "" {
		return v
	}
	return fallback
}

func readOnlyPointers(schema validation.Schema, body map[string]any, base string) []string {
	properties := propertiesOf(schema)
	out := []string{}
	for key, value := range body {
		raw, known := properties[key]
		property, _ := raw.(map[string]any)
		if !known || property == nil {
			continue
		}
		pointer := base + "/" + escape(key)
		if ro, _ := property["readOnly"].(bool); ro {
			out = append(out, pointer)
			continue
		}
		if _, nested := property["properties"]; nested {
			child, _ := value.(map[string]any)
			out = append(out, readOnlyPointers(property, child, pointer)...)
			continue
		}
		if isMapSchema(property) {
			item := property["additionalProperties"].(map[string]any)
			entries, _ := value.(map[string]any)
			for entryKey, entry := range entries {
				child, _ := entry.(map[string]any)
				out = append(out, readOnlyPointers(item, child, pointer+"/"+escape(entryKey))...)
			}
		}
	}
	sort.Strings(out)
	return out
}

func mergePatch(target, patch any) any {
	patchObject, ok := patch.(map[string]any)
	if !ok {
		return clone(patch)
	}
	merged := map[string]any{}
	if targetObject, isObject := target.(map[string]any); isObject {
		for key, value := range targetObject {
			merged[key] = value
		}
	}
	for key, value := range patchObject {
		if value == nil {
			delete(merged, key)
			continue
		}
		if _, isObject := value.(map[string]any); isObject {
			merged[key] = mergePatch(merged[key], value)
			continue
		}
		merged[key] = clone(value)
	}
	return merged
}

func valueAt(document any, pointer string) any {
	node := document
	for _, segment := range segmentsOf(pointer) {
		object, ok := node.(map[string]any)
		if !ok {
			return nil
		}
		node = object[segment]
	}
	return node
}

func propertyAt(schema validation.Schema, pointer string) validation.Schema {
	property := schema
	for _, segment := range segmentsOf(pointer) {
		if property == nil {
			return nil
		}
		if child, ok := propertiesOf(property)[segment].(map[string]any); ok {
			property = child
			continue
		}
		if isMapSchema(property) {
			property = property["additionalProperties"].(map[string]any)
			continue
		}
		return nil
	}
	return property
}

type leaf struct {
	pointer string
	value   any
}

func leaves(node any, base string) []leaf {
	object, ok := node.(map[string]any)
	if !ok {
		return []leaf{{pointer: base, value: node}}
	}
	out := []leaf{}
	for key, value := range object {
		out = append(out, leaves(value, base+"/"+escape(key))...)
	}
	return out
}

func changed(before, after any) bool {
	left, _ := json.Marshal(before)
	right, _ := json.Marshal(after)
	return !bytes.Equal(left, right)
}

func restartDiff(schema validation.Schema, before, after map[string]any, base string) []RestartEntry {
	out := []RestartEntry{}
	for key, raw := range propertiesOf(schema) {
		property, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		pointer := base + "/" + escape(key)
		previous := before[key]
		next := after[key]
		if _, nested := property["properties"]; nested {
			p, _ := previous.(map[string]any)
			n, _ := next.(map[string]any)
			out = append(out, restartDiff(property, p, n, pointer)...)
			continue
		}
		if isMapSchema(property) {
			item := property["additionalProperties"].(map[string]any)
			p, _ := previous.(map[string]any)
			n, _ := next.(map[string]any)
			keys := map[string]bool{}
			for k := range p {
				keys[k] = true
			}
			for k := range n {
				keys[k] = true
			}
			for entryKey := range keys {
				entryPointer := pointer + "/" + escape(entryKey)
				if _, itemProps := item["properties"]; itemProps {
					pe, _ := p[entryKey].(map[string]any)
					ne, _ := n[entryKey].(map[string]any)
					out = append(out, restartDiff(item, pe, ne, entryPointer)...)
				} else if flagged(item) && changed(p[entryKey], n[entryKey]) {
					out = append(out, RestartEntry{Pointer: entryPointer, Title: titleOf(item, entryKey), Reason: reasonOf(item)})
				}
			}
			continue
		}
		if flagged(property) && changed(previous, next) {
			out = append(out, RestartEntry{Pointer: pointer, Title: titleOf(property, key), Reason: reasonOf(property)})
		}
	}
	sortEntries(out)
	return out
}

func sortEntries(list []RestartEntry) {
	sort.Slice(list, func(i, j int) bool { return list[i].Pointer < list[j].Pointer })
}
