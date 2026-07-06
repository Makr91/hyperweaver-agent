package provisioner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The two contract proofs of Mark's Jinja2 dialect ruling (2026-07-06,
// hyperweaver-ai-sync.md): undefined variables render as EMPTY STRING, and
// template includes can never escape the package's templates/ directory.
// Named proofs, not assumptions — the standing order.

// writeTestPackage builds a minimal package version on disk:
// <root>/templates/Hosts.template.yml plus any extra template files.
func writeTestPackage(t *testing.T, template string, extras map[string]string) *Version {
	t.Helper()
	root := t.TempDir()
	templates := filepath.Join(root, "templates")
	if err := os.MkdirAll(templates, 0o750); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{hostsTemplateName: template}
	for name, content := range extras {
		files[name] = content
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(templates, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return &Version{Name: "test", Version: "1.0.0", Root: root}
}

// Proof 1 + dialect: an undefined variable renders empty (never an error),
// true-Jinja2 parenthesized filter arguments apply, and undefined values are
// falsy in conditions.
func TestRenderUndefinedEmptyAndJinja2Dialect(t *testing.T) {
	version := writeTestPackage(t, strings.Join([]string{
		`a: '{{ never_defined }}'`,
		`b: '{{ also_missing|default("fallback") }}'`,
		`c: {% if never_defined %}broken{% else %}falsy{% endif %}`,
		`d: '{{ HOSTNAME }}'`,
		``,
	}, "\n"), nil)

	rendered, err := RenderHostsFile(&GenerateInput{
		Version:  version,
		Settings: map[string]any{"hostname": "box-one"},
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	out := string(rendered)
	if !strings.Contains(out, "a: ''") {
		t.Errorf("undefined variable must render as empty string, got: %q", out)
	}
	if !strings.Contains(out, "b: 'fallback'") {
		t.Errorf(`parenthesized |default("fallback") must apply, got: %q`, out)
	}
	if !strings.Contains(out, "c: falsy") {
		t.Errorf("undefined variable must be falsy in conditions, got: %q", out)
	}
	if !strings.Contains(out, "d: 'box-one'") {
		t.Errorf("flattened UPPERCASE settings var missing, got: %q", out)
	}
}

// Proof 2: an include inside templates/ resolves; an include reaching
// outside it is refused even when the target file exists.
func TestRenderIncludeContainment(t *testing.T) {
	version := writeTestPackage(t,
		"{% include \"partial.yml\" %}\n",
		map[string]string{"partial.yml": "included: true\n"})
	rendered, err := RenderHostsFile(&GenerateInput{Version: version, Settings: map[string]any{}})
	if err != nil {
		t.Fatalf("in-package include: %v", err)
	}
	if !strings.Contains(string(rendered), "included: true") {
		t.Errorf("in-package include content missing, got: %q", rendered)
	}

	escape := writeTestPackage(t, "{% include \"../outside.yml\" %}\n", nil)
	if err := os.WriteFile(filepath.Join(escape.Root, "outside.yml"), []byte("leaked: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RenderHostsFile(&GenerateInput{Version: escape, Settings: map[string]any{}}); err == nil {
		t.Fatal("an include escaping templates/ must fail, not render")
	}
}
