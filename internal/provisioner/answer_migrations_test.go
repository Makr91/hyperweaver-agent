package provisioner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplyAnswerMigrations(t *testing.T) {
	root := t.TempDir()
	doc := `from:
  "0.1.0":
    renames:
      old_name: new_name
      shadowed_old: taken
`
	if err := os.WriteFile(filepath.Join(root, answerMigrationsFile), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}

	answers := map[string]any{
		"old_name":     "v",
		"shadowed_old": "loser",
		"taken":        "winner",
		"other":        7,
	}
	out, err := ApplyAnswerMigrations(root, "0.1.0", answers)
	if err != nil {
		t.Fatal(err)
	}
	if out["new_name"] != "v" {
		t.Fatalf("rename did not move the value: %v", out)
	}
	if _, present := out["old_name"]; present {
		t.Fatalf("old key survived: %v", out)
	}
	if out["taken"] != "winner" {
		t.Fatalf("already-present new key lost: %v", out)
	}
	if _, present := out["shadowed_old"]; present {
		t.Fatalf("shadowed old key survived: %v", out)
	}
	if out["other"] != 7 {
		t.Fatalf("verbatim key lost: %v", out)
	}
	if answers["old_name"] != "v" {
		t.Fatalf("input map mutated: %v", answers)
	}

	untouched, err := ApplyAnswerMigrations(root, "0.0.9", answers)
	if err != nil {
		t.Fatal(err)
	}
	if len(untouched) != len(answers) {
		t.Fatalf("unlisted source version transformed: %v", untouched)
	}

	absent, err := ApplyAnswerMigrations(t.TempDir(), "0.1.0", answers)
	if err != nil {
		t.Fatal(err)
	}
	if len(absent) != len(answers) {
		t.Fatalf("absent file transformed: %v", absent)
	}
}
