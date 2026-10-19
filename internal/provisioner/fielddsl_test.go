package provisioner

import (
	"strings"
	"testing"
)

func manifestWith(fields []any, defaults any) map[string]any {
	meta := map[string]any{
		"configuration": map[string]any{
			"groups": []any{},
			"fields": fields,
		},
	}
	if defaults != nil {
		meta["defaults"] = defaults
	}
	return map[string]any{"metadata": meta}
}

func TestListAndFileFieldsParseAndValidate(t *testing.T) {
	manifest := manifestWith([]any{
		map[string]any{"name": "NAMES", "type": "list", "items": "fqdn", "validate": map[string]any{"min_items": 1, "max_items": 2}},
		map[string]any{"name": "SAFE", "type": "file", "kind": "id_file", "role": "safe_id", "default": "SAFE.ids"},
		map[string]any{"name": "PROVIDER", "type": "select", "options_source": "hypervisor"},
	}, nil)
	dsl, problems := ParseFieldDSL(manifest, nil)
	if len(problems) > 0 {
		t.Fatalf("lint refused a legal manifest: %v", problems)
	}

	cases := []struct {
		answers map[string]any
		field   string
		want    string
	}{
		{map[string]any{"NAMES": []any{"a.example.com"}, "SAFE": "SAFE.ids", "PROVIDER": "utm"}, "", ""},
		{map[string]any{"NAMES": []any{}}, "NAMES", ""},
		{map[string]any{"NAMES": []any{"a.example.com", "b.example.com", "c.example.com"}}, "NAMES", "at most 2"},
		{map[string]any{"NAMES": []any{"not a host"}}, "NAMES", "entry 1 must be a fully qualified domain name"},
		{map[string]any{"NAMES": "a.example.com"}, "NAMES", "must be a list"},
		{map[string]any{"SAFE": "ids/SAFE.ids"}, "SAFE", "not a path"},
	}
	for _, tc := range cases {
		got := dsl.ValidateAnswers(tc.answers, nil, nil, false)
		if tc.field == "" {
			if len(got) != 0 {
				t.Errorf("answers %v: unexpected problems %v", tc.answers, got)
			}
			continue
		}
		if tc.want == "" {
			if _, has := got[tc.field]; has {
				t.Errorf("answers %v: %s refused: %v", tc.answers, tc.field, got)
			}
			continue
		}
		if !strings.Contains(got[tc.field], tc.want) {
			t.Errorf("answers %v: want %s problem containing %q, got %v", tc.answers, tc.field, tc.want, got)
		}
	}
}

func TestListAndFileLint(t *testing.T) {
	cases := []struct {
		field map[string]any
		want  string
	}{
		{map[string]any{"name": "A", "type": "list"}, "list needs items"},
		{map[string]any{"name": "A", "type": "list", "items": "number"}, "list needs items"},
		{map[string]any{"name": "A", "type": "list", "items": "fqdn", "default": "x"}, "list default must be a list"},
		{map[string]any{"name": "A", "type": "text", "items": "fqdn"}, "items applies to list only"},
		{map[string]any{"name": "A", "type": "file", "role": "safe_id"}, "file needs kind"},
		{map[string]any{"name": "A", "type": "file", "kind": "id_file"}, "file needs role"},
		{map[string]any{"name": "A", "type": "text", "kind": "id_file"}, "kind and role apply to file only"},
		{map[string]any{"name": "A", "type": "text", "validate": map[string]any{"min_items": 1}}, "applies to list fields only"},
		{map[string]any{"name": "A", "type": "select", "options_source": "clouds"}, "hypervisor"},
	}
	for _, tc := range cases {
		_, problems := ParseFieldDSL(manifestWith([]any{tc.field}, nil), nil)
		if !strings.Contains(strings.Join(problems, "; "), tc.want) {
			t.Errorf("field %v: want a problem containing %q, got %v", tc.field, tc.want, problems)
		}
	}
}

func TestLintDefaults(t *testing.T) {
	legal := map[string]any{
		"settings": map[string]any{"box": "STARTcloud/debian13-server"},
		"disks":    map[string]any{"boot": map[string]any{"type": "template"}},
		"networks": []any{map[string]any{"type": "external", "dhcp4": true}},
	}
	if problems := lintDefaults(manifestWith(nil, legal)); len(problems) != 0 {
		t.Fatalf("legal defaults refused: %v", problems)
	}
	if problems := lintDefaults(manifestWith(nil, nil)); len(problems) != 0 {
		t.Fatalf("absent defaults refused: %v", problems)
	}
	cases := []struct {
		defaults any
		want     string
	}{
		{"x", "must be a map"},
		{map[string]any{"vbox": map[string]any{}}, "unknown key"},
		{map[string]any{"settings": "x"}, "settings: must be a map"},
		{map[string]any{"networks": map[string]any{}}, "networks: must be a list"},
	}
	for _, tc := range cases {
		problems := lintDefaults(manifestWith(nil, tc.defaults))
		if !strings.Contains(strings.Join(problems, "; "), tc.want) {
			t.Errorf("defaults %v: want a problem containing %q, got %v", tc.defaults, tc.want, problems)
		}
	}
}
