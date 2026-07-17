package machines

import (
	"bytes"
	"encoding/json"
)

// Ordered/raw JSON utilities for the stored configuration document. Go's
// map[string]any round-trip alphabetizes object keys on re-marshal, which
// destroys the stored document's provisioning:/vars: key order — and the
// ruling is that the document is the program: agents execute it AS WRITTEN,
// methods in the order their keys appear, unknown keys surviving round-trips
// untouched. These helpers keep section bytes verbatim so a configuration
// write re-encodes ONLY the section it touches.

// ParseRawConfiguration reads a machine row's configuration JSON as raw
// top-level sections — each section's bytes verbatim, never decoded. Empty
// map when absent; a parse failure warns and answers empty (the same
// tolerance as ParseConfiguration — a bad document never fails a write path).
func ParseRawConfiguration(machine *Machine) map[string]json.RawMessage {
	sections := map[string]json.RawMessage{}
	if len(machine.Configuration) == 0 {
		return sections
	}
	if err := json.Unmarshal(machine.Configuration, &sections); err != nil {
		mlog().Warn("failed to parse machine configuration", "machine", machine.Name, "error", err)
		return map[string]json.RawMessage{}
	}
	return sections
}

// marshalRawConfig re-assembles the configuration document from raw sections.
// json.Marshal emits RawMessage values byte-verbatim, so every untouched
// section's internal key order survives; only the TOP-LEVEL section keys
// alphabetize, which the ruling permits — order INSIDE each section is what
// it protects.
func marshalRawConfig(sections map[string]json.RawMessage) (json.RawMessage, error) {
	return json.Marshal(sections)
}

// OrderedKeys answers a JSON object's keys IN DOCUMENT ORDER — the one thing
// map[string]json.RawMessage cannot carry. nil for non-objects or invalid
// JSON. The token walk skips each value with a depth counter so nested
// objects/arrays never desynchronize the key alternation.
func OrderedKeys(raw json.RawMessage) []string {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil {
		return nil
	}
	if delim, ok := opening.(json.Delim); !ok || delim != '{' {
		return nil
	}
	keys := []string{}
	for decoder.More() {
		token, terr := decoder.Token()
		if terr != nil {
			return nil
		}
		key, ok := token.(string)
		if !ok {
			return nil
		}
		keys = append(keys, key)
		if serr := skipJSONValue(decoder); serr != nil {
			return nil
		}
	}
	return keys
}

// skipJSONValue consumes one complete JSON value from the token stream —
// scalars are one token; objects/arrays are walked to their closing delim.
func skipJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok || (delim != '{' && delim != '[') {
		return nil
	}
	depth := 1
	for depth > 0 {
		next, nerr := decoder.Token()
		if nerr != nil {
			return nerr
		}
		if d, dok := next.(json.Delim); dok {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
	}
	return nil
}

// RawObject decodes ONE object level, values staying raw — the section-level
// view of a document whose inner bytes must not re-encode. nil on failure.
func RawObject(raw json.RawMessage) map[string]json.RawMessage {
	object := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil
	}
	return object
}

// RawProvisioner answers the stored provisioner document's verbatim bytes
// (nil when absent) — what an ordered walk reads instead of the alphabetized
// map view.
func RawProvisioner(machine *Machine) json.RawMessage {
	return ParseRawConfiguration(machine)["provisioner"]
}

// rawSectionMap decodes one section for mutation ({} when absent or
// unparsable) — the write pattern's "decode ONLY the touched section" half.
func rawSectionMap(sections map[string]json.RawMessage, key string) map[string]any {
	section := map[string]any{}
	raw, ok := sections[key]
	if !ok {
		return section
	}
	if err := json.Unmarshal(raw, &section); err != nil {
		return map[string]any{}
	}
	return section
}
