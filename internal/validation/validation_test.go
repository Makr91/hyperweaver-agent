package validation

import (
	"testing"
)

func schema(properties map[string]any, required ...string) Schema {
	s := Schema{"properties": properties}
	if len(required) > 0 {
		list := make([]any, 0, len(required))
		for _, name := range required {
			list = append(list, name)
		}
		s["required"] = list
	}
	return s
}

func TestRequiredIsPresenceAlone(t *testing.T) {
	s := schema(map[string]any{"name": map[string]any{"type": "string"}}, "name")
	errors := Object(s, map[string]any{}, nil)
	if len(errors) != 1 || errors[0].Rule != "required" || errors[0].Pointer != "/name" {
		t.Fatalf("expected one required failure at /name, got %+v", errors)
	}
	if errors := Object(s, map[string]any{"name": ""}, nil); len(errors) != 0 {
		t.Fatalf("a blank string is present, got %+v", errors)
	}
}

func TestBlankSkipsFormatEnumAndBounds(t *testing.T) {
	s := schema(map[string]any{
		"url":  map[string]any{"type": "string", "format": "uri"},
		"mode": map[string]any{"type": "string", "enum": []any{"a", "b"}},
	})
	if errors := Object(s, map[string]any{"url": "", "mode": ""}, nil); len(errors) != 0 {
		t.Fatalf("blank skips format and enum, got %+v", errors)
	}
	errors := Object(s, map[string]any{"url": "nope", "mode": "c"}, nil)
	if len(errors) != 2 {
		t.Fatalf("expected two failures, got %+v", errors)
	}
}

func TestBoundsReportTheCrossedSide(t *testing.T) {
	s := schema(map[string]any{"port": map[string]any{"type": "integer", "minimum": 1, "maximum": 65535}})
	low := Object(s, map[string]any{"port": 0}, nil)
	high := Object(s, map[string]any{"port": 70000}, nil)
	if len(low) != 1 || low[0].Rule != "minimum" {
		t.Fatalf("expected minimum, got %+v", low)
	}
	if len(high) != 1 || high[0].Rule != "maximum" {
		t.Fatalf("expected maximum, got %+v", high)
	}
	if errors := Object(s, map[string]any{"port": 2.5}, nil); len(errors) != 1 || errors[0].Rule != "type" {
		t.Fatalf("2.5 is not an integer, got %+v", errors)
	}
}

func TestNestedObjectsAndMaps(t *testing.T) {
	s := schema(map[string]any{
		"logging": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"categories": map[string]any{
					"type":                 "object",
					"additionalProperties": map[string]any{"type": "string", "enum": []any{"info", "debug"}},
				},
			},
		},
	})
	errors := Object(s, map[string]any{"logging": map[string]any{"categories": map[string]any{"tasks": "loud"}}}, nil)
	if len(errors) != 1 || errors[0].Pointer != "/logging/categories/tasks" || errors[0].Rule != "enum" {
		t.Fatalf("expected enum at the map entry, got %+v", errors)
	}
}

func TestDependsOnHidesAField(t *testing.T) {
	s := schema(map[string]any{
		"enabled": map[string]any{"type": "boolean"},
		"issuer":  map[string]any{"type": "string", "format": "uri", "dependsOn": "enabled", "showWhen": []any{true}},
	})
	if errors := Object(s, map[string]any{"enabled": false, "issuer": "bad"}, nil); len(errors) != 0 {
		t.Fatalf("hidden field is not evaluated, got %+v", errors)
	}
	if errors := Object(s, map[string]any{"enabled": true, "issuer": "bad"}, nil); len(errors) != 1 {
		t.Fatalf("shown field is evaluated, got %+v", errors)
	}
}

func TestRefWithinDefsNamesThePattern(t *testing.T) {
	document := Schema{
		"$defs": map[string]any{
			"slug": map[string]any{"type": "string", "pattern": "^[a-z0-9_]+$"},
		},
		"properties": map[string]any{
			"id": map[string]any{"$ref": "#/$defs/slug"},
		},
	}
	errors := Object(document, map[string]any{"id": "Bad Id"}, document)
	if len(errors) != 1 || errors[0].Rule != "pattern" || errors[0].Params["pattern"] != "slug" {
		t.Fatalf("expected pattern slug, got %+v", errors)
	}
}

func TestArrayItemsCount(t *testing.T) {
	s := schema(map[string]any{"list": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "maxItems": 1}})
	errors := Object(s, map[string]any{"list": []any{"a", "b"}}, nil)
	if len(errors) != 1 || errors[0].Rule != "maxItems" {
		t.Fatalf("expected maxItems, got %+v", errors)
	}
}
