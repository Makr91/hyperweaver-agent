package provisioner

import (
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

func fieldYAML(t *testing.T, text string) map[string]any {
	t.Helper()
	field := map[string]any{}
	if err := yaml.Unmarshal([]byte(text), &field); err != nil {
		t.Fatal(err)
	}
	return field
}

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

func TestListFileAndSecretFieldsParseAndValidate(t *testing.T) {
	SetSecretLookup(func(id string) (string, bool) {
		switch id {
		case "key-row":
			return "api_key", true
		case "cert-row":
			return "authority", true
		}
		return "", false
	})
	t.Cleanup(func() { SetSecretLookup(nil) })
	manifest := manifestWith([]any{
		map[string]any{"name": "NAMES", "type": "list", "items": "fqdn", "validate": map[string]any{"min_items": 1, "max_items": 2}},
		map[string]any{"name": "INSTALLER", "type": "file", "kind": "installer", "role": "domino", "default": "Domino.tar"},
		map[string]any{"name": "PROVIDER", "type": "select", "options_source": "hypervisor"},
		fieldYAML(t, "name: IQ_KEY\ntype: secret\nkind: api_key\nsecret_key: domino_iq_api_key\nprofile: openai\n"),
		fieldYAML(t, "name: CERT\ntype: secret\nkind: certificate\nsecret_key: default-signed\n"),
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
		{map[string]any{"NAMES": []any{"a.example.com"}, "INSTALLER": "Domino.tar", "PROVIDER": "utm", "IQ_KEY": "key-row", "CERT": "cert-row"}, "", ""},
		{map[string]any{"NAMES": []any{}}, "NAMES", ""},
		{map[string]any{"NAMES": []any{"a.example.com", "b.example.com", "c.example.com"}}, "NAMES", "at most 2"},
		{map[string]any{"NAMES": []any{"not a host"}}, "NAMES", "entry 1 must be a fully qualified domain name"},
		{map[string]any{"NAMES": "a.example.com"}, "NAMES", "must be a list"},
		{map[string]any{"INSTALLER": "tars/Domino.tar"}, "INSTALLER", "not a path"},
		{map[string]any{"IQ_KEY": "missing-row"}, "IQ_KEY", "must name a secret of this host"},
		{map[string]any{"IQ_KEY": "cert-row"}, "IQ_KEY", "must name a api_key secret"},
		{map[string]any{"CERT": "key-row"}, "CERT", "must name a certificate secret"},
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
		{map[string]any{"name": "A", "type": "file", "role": "domino"}, "file needs kind"},
		{map[string]any{"name": "A", "type": "file", "kind": "installer"}, "file needs role"},
		{map[string]any{"name": "A", "type": "file", "kind": "id_file", "role": "safe_id"}, "file needs kind"},
		{map[string]any{"name": "A", "type": "text", "kind": "installer"}, "kind, role and secret_key apply to file and secret only"},
		{map[string]any{"name": "A", "type": "text", "validate": map[string]any{"min_items": 1}}, "applies to list fields only"},
		{map[string]any{"name": "A", "type": "select", "options_source": "clouds"}, "hypervisor"},
		{fieldYAML(t, "name: A\ntype: secret\nsecret_key: k\n"), "secret needs kind"},
		{fieldYAML(t, "name: A\ntype: secret\nkind: api_key\n"), "secret needs secret_key"},
		{fieldYAML(t, "name: A\ntype: secret\nkind: api_key\nsecret_key: k\nrole: x\n"), "role applies to file only"},
		{map[string]any{"name": "A", "type": "text", "profile": "openai"}, "profile applies to secret only"},
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
		"settings":    map[string]any{"box": "STARTcloud/debian13-server"},
		"disks":       map[string]any{"boot": map[string]any{"type": "template"}},
		"networks":    []any{map[string]any{"type": "external", "dhcp4": true}},
		"tags":        []any{"domino", "standalone"},
		"guest_agent": true,
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
		{map[string]any{"vbox": map[string]any{"guest_agent": true}}, "unknown key"},
		{map[string]any{"settings": "x"}, "settings: must be a map"},
		{map[string]any{"networks": map[string]any{}}, "networks: must be a list"},
		{map[string]any{"tags": "domino"}, "tags: must be a list of strings"},
		{map[string]any{"tags": []any{"domino", 1}}, "tags: must be a list of strings"},
		{map[string]any{"guest_agent": "yes"}, "guest_agent: must be a boolean"},
	}
	for _, tc := range cases {
		problems := lintDefaults(manifestWith(nil, tc.defaults))
		if !strings.Contains(strings.Join(problems, "; "), tc.want) {
			t.Errorf("defaults %v: want a problem containing %q, got %v", tc.defaults, tc.want, problems)
		}
	}
}
