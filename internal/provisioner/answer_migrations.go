package provisioner

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"
)

// answerMigrationsFile is the OPTIONAL renames-only transform shipped beside
// provisioner.yml (the frozen cross-agent format, sync 2026-07-19 — Mark's
// complexity ceiling: renames ONLY; if it ever needs more than renames, the
// feature dies instead of growing).
const answerMigrationsFile = "answer-migrations.yml"

type answerMigrations struct {
	From map[string]struct {
		Renames map[string]string `yaml:"renames"`
	} `yaml:"from"`
}

// ApplyAnswerMigrations transforms an answers map recorded under fromVersion
// for rendering against the version rooted at versionRoot — zoneweaver's
// applyAnswerMigrations twin, exact semantics: the target version's OPTIONAL
// answer-migrations.yml names direct per-source-version renames (no
// chaining); each rename moves the old key's value to the new key (an
// already-present new key wins); everything else passes verbatim. An absent
// file or an unlisted source version answers the map untouched. Every
// cross-version flow (fork, upgrade) calls this before validate/render. The
// input map is never mutated.
func ApplyAnswerMigrations(versionRoot, fromVersion string, answers map[string]any) (map[string]any, error) {
	raw, err := os.ReadFile(filepath.Clean(filepath.Join(versionRoot, answerMigrationsFile)))
	if errors.Is(err, fs.ErrNotExist) {
		return answers, nil
	}
	if err != nil {
		return nil, err
	}
	var doc answerMigrations
	if uerr := yaml.Unmarshal(raw, &doc); uerr != nil {
		return nil, fmt.Errorf("parse %s: %w", answerMigrationsFile, uerr)
	}
	renames := doc.From[fromVersion].Renames
	if len(renames) == 0 || len(answers) == 0 {
		return answers, nil
	}

	out := make(map[string]any, len(answers))
	for key, value := range answers {
		if newKey, renamed := renames[key]; renamed {
			if _, present := answers[newKey]; !present {
				out[newKey] = value
			}
			continue
		}
		out[key] = value
	}
	return out, nil
}
