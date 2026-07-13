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

// normalizeNumbers rewrites whole-valued floats as ints, recursively through
// maps and slices. JSON decoding types every number float64, so without this
// a settings save writes port: 9420.0 into the YAML (Mark's fix order
// 2026-07-08 — the config had float-ified integers everywhere). Fractional
// values pass through untouched.
func normalizeNumbers(value any) any {
	switch typed := value.(type) {
	case float64:
		if typed == float64(int64(typed)) {
			return int64(typed)
		}
		return typed
	case map[string]any:
		for key, entry := range typed {
			typed[key] = normalizeNumbers(entry)
		}
		return typed
	case []any:
		for i, entry := range typed {
			typed[i] = normalizeNumbers(entry)
		}
		return typed
	default:
		return value
	}
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
		current[key] = normalizeNumbers(value)
	}
	// The current file may already carry float-ified integers from earlier
	// saves — normalize the whole document on the way out, healing it.
	for key, value := range current {
		current[key] = normalizeNumbers(value)
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
