package config

import (
	"encoding/json"
	"fmt"
)

func sectionPatch(value any) (map[string]any, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	patch := map[string]any{}
	if uerr := json.Unmarshal(raw, &patch); uerr != nil {
		return nil, uerr
	}
	return patch, nil
}

// MergeAndSave writes whole top-level sections through the engine and refills the typed view.
func (c *Config) MergeAndSave(updates map[string]any) error {
	patches := map[string]map[string]any{}
	for key, value := range updates {
		name, known := fileOfSection[key]
		if !known {
			return fmt.Errorf("unknown configuration section %q", key)
		}
		patch, err := sectionPatch(value)
		if err != nil {
			return err
		}
		if patches[name] == nil {
			patches[name] = map[string]any{}
		}
		patches[name][key] = patch
	}
	for name, body := range patches {
		body = c.engine.WithDeletions(name, body)
		if _, err := c.engine.Save(name, body, "agent"); err != nil {
			return err
		}
	}
	return c.fill()
}
