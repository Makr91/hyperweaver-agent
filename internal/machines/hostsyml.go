package machines

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"github.com/goccy/go-yaml"
)

var documentSections = []string{"settings", "zones", "networks", "disks", "provisioner", "metadata"}

var bookkeepingSections = []string{
	"provisioner_state", "pending_changes", "guest_info", "snapshots", "host_hooks_confirmed",
}

// DocumentYAML serializes a machine's stored document sections as YAML (the
// hosts-yml GET — frozen contract, sync 2026-07-19), key order preserved.
func DocumentYAML(machine *Machine) (string, error) {
	sections := ParseRawConfiguration(machine)
	doc := yaml.MapSlice{}
	for _, key := range documentSections {
		raw, ok := sections[key]
		if !ok {
			continue
		}
		value, err := orderedJSONValue(raw)
		if err != nil {
			return "", fmt.Errorf("section %s: %w", key, err)
		}
		doc = append(doc, yaml.MapItem{Key: key, Value: value})
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// HostsYAMLResult is StoreDocumentYAML's outcome: a non-empty Problem is the
// 400 (Line/Column set when the parser reported a position); otherwise the
// document stored and Warnings carry the non-blocking advisories.
type HostsYAMLResult struct {
	Problem  string
	Line     int
	Column   int
	Warnings []string
}

var yamlPositionPattern = regexp.MustCompile(`\[(\d+):(\d+)\]`)

// StoreDocumentYAML replaces a machine's document sections from raw YAML (the
// hosts-yml PUT — frozen contract, sync 2026-07-19): parse errors and
// impossible shapes refuse with nothing stored, the converged document
// pre-flights still answer 400, bookkeeping/unknown top-level keys refuse,
// and a parseable document stores VERBATIM with key order preserved — a
// section absent from the YAML is REMOVED.
func (s *Store) StoreDocumentYAML(ctx context.Context, machine *Machine, text string) (*HostsYAMLResult, error) {
	result := &HostsYAMLResult{Warnings: []string{}}
	problem := func(message string) (*HostsYAMLResult, error) {
		result.Problem = message
		return result, nil
	}

	var parsed any
	if err := yaml.UnmarshalWithOptions([]byte(text), &parsed, yaml.UseOrderedMap()); err != nil {
		message := err.Error()
		if match := yamlPositionPattern.FindStringSubmatch(message); match != nil {
			result.Line, _ = strconv.Atoi(match[1])
			result.Column, _ = strconv.Atoi(match[2])
		}
		return problem(message)
	}
	root, ok := parsed.(yaml.MapSlice)
	if !ok {
		return problem("the document root must be a mapping")
	}

	allowed := map[string]bool{}
	for _, key := range documentSections {
		allowed[key] = true
	}
	bookkeeping := map[string]bool{}
	for _, key := range bookkeepingSections {
		bookkeeping[key] = true
	}
	incoming := map[string]any{}
	for _, item := range root {
		key, kok := item.Key.(string)
		if !kok {
			return problem(fmt.Sprintf("top-level key %v is not a string", item.Key))
		}
		if bookkeeping[key] {
			return problem(key + " is agent bookkeeping — never part of the document")
		}
		if !allowed[key] {
			return problem(key + " is not a document section (settings|zones|networks|disks|provisioner|metadata)")
		}
		incoming[key] = item.Value
	}

	for _, key := range []string{"settings", "zones", "disks", "provisioner", "metadata"} {
		value, present := incoming[key]
		if !present || value == nil {
			continue
		}
		if _, mok := value.(yaml.MapSlice); !mok {
			return problem(key + " must be a mapping")
		}
	}
	if value, present := incoming["networks"]; present && value != nil {
		if _, lok := value.([]any); !lok {
			return problem("networks must be a list")
		}
	}

	settings := mapOr(orderedToPlain(incoming["settings"]))
	disks := mapOr(orderedToPlain(incoming["disks"]))
	networks := listOr(orderedToPlain(incoming["networks"]))
	if value, present := settings["consoleport"]; present {
		if p := ConsolePortProblem(value); p != "" {
			return problem(p)
		}
	}
	if value, present := settings["vcpus"]; present {
		if p := VCPUProblem(value); p != "" {
			return problem(p)
		}
	}
	diskProblems, diskWarnings := ValidateDisks(disks, settings)
	if len(diskProblems) > 0 {
		return problem(diskProblems[0])
	}
	result.Warnings = append(result.Warnings, diskWarnings...)
	if len(networks) > 0 && ExtractControlIP(networks) == "" {
		result.Warnings = append(result.Warnings, "networks[] carries no control IP (set is_control: true or an address on one entry)")
	}

	sections := ParseRawConfiguration(machine)
	for _, key := range documentSections {
		value, present := incoming[key]
		if !present {
			delete(sections, key)
			continue
		}
		raw, err := orderedYAMLToJSON(value)
		if err != nil {
			return nil, fmt.Errorf("section %s: %w", key, err)
		}
		sections[key] = raw
	}
	merged, err := marshalRawConfig(sections)
	if err != nil {
		return nil, err
	}
	if err := s.SetConfiguration(ctx, machine.Name, merged); err != nil {
		return nil, err
	}
	return result, nil
}

func orderedJSONValue(raw json.RawMessage) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	return decodeOrderedJSON(decoder)
}

func decodeOrderedJSON(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	return decodeOrderedJSONToken(decoder, token)
}

func decodeOrderedJSONToken(decoder *json.Decoder, token json.Token) (any, error) {
	switch t := token.(type) {
	case json.Delim:
		switch t {
		case '{':
			object := yaml.MapSlice{}
			for decoder.More() {
				keyToken, kerr := decoder.Token()
				if kerr != nil {
					return nil, kerr
				}
				key, _ := keyToken.(string)
				value, verr := decodeOrderedJSON(decoder)
				if verr != nil {
					return nil, verr
				}
				object = append(object, yaml.MapItem{Key: key, Value: value})
			}
			if _, cerr := decoder.Token(); cerr != nil {
				return nil, cerr
			}
			return object, nil
		case '[':
			list := []any{}
			for decoder.More() {
				value, verr := decodeOrderedJSON(decoder)
				if verr != nil {
					return nil, verr
				}
				list = append(list, value)
			}
			if _, cerr := decoder.Token(); cerr != nil {
				return nil, cerr
			}
			return list, nil
		}
		return nil, errors.New("unexpected JSON delimiter")
	case json.Number:
		if n, nerr := strconv.ParseInt(t.String(), 10, 64); nerr == nil {
			return n, nil
		}
		f, ferr := t.Float64()
		if ferr != nil {
			return nil, ferr
		}
		return f, nil
	default:
		return t, nil
	}
}

func orderedToPlain(value any) any {
	switch v := value.(type) {
	case yaml.MapSlice:
		plain := map[string]any{}
		for _, item := range v {
			key, ok := item.Key.(string)
			if !ok {
				key = fmt.Sprint(item.Key)
			}
			plain[key] = orderedToPlain(item.Value)
		}
		return plain
	case []any:
		list := make([]any, 0, len(v))
		for _, item := range v {
			list = append(list, orderedToPlain(item))
		}
		return list
	default:
		return value
	}
}
