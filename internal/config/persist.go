package config

import (
	"fmt"
	"os"

	"github.com/goccy/go-yaml"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// Settings persistence (Node-agent semantics): PUT /settings shallow-merges
// the submitted top-level sections onto the on-disk YAML and writes it back
// atomically (safepath.WriteFile — the agent's one write path), after
// validating the result parses as a working configuration. The running
// process keeps its loaded values — changes apply on restart (the settings
// UI offers a Restart button for exactly that).

// validateConfigBytes strict-parses candidate YAML as a full configuration.
func validateConfigBytes(raw []byte) error {
	candidate := Default()
	if err := yaml.UnmarshalWithOptions(raw, candidate, yaml.Strict()); err != nil {
		return err
	}
	return candidate.validate()
}

// MergeAndSave merges the submitted top-level sections onto the on-disk
// configuration and persists the result. A backup of the current file is
// created first. Comments in the file are lost on save (same trade-off as the
// Node agent's yaml.dump).
func (c *Config) MergeAndSave(updates map[string]any) error {
	raw, err := os.ReadFile(c.path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	current := map[string]any{}
	if uerr := yaml.Unmarshal(raw, &current); uerr != nil {
		return fmt.Errorf("parse current config: %w", uerr)
	}

	for key, value := range updates {
		current[key] = value
	}

	merged, err := yaml.Marshal(current)
	if err != nil {
		return fmt.Errorf("serialize merged config: %w", err)
	}
	if verr := validateConfigBytes(merged); verr != nil {
		return fmt.Errorf("merged configuration is invalid: %w", verr)
	}

	if _, err := c.CreateBackup(); err != nil {
		return err
	}
	return safepath.WriteFile(c.path, merged, 0o600)
}
