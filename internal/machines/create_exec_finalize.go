package machines

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// createFinalize executes machine_create_finalize: the registry row lands
// (the base's syncZoneToDatabase moment), the document sections and the
// render-produced provisioner document store into configuration, and the
// VirtualBox UUID is recorded.
func (e *executors) createFinalize(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	meta, err := readCreateMetadata(task)
	if err != nil {
		return err
	}
	output, err := e.dependencyOutput(ctx, task)
	if err != nil {
		return err
	}
	documentRaw := output.Document
	document := parseConfigBytes(documentRaw)

	e.taskProgress(task, 20, "creating_database_record")
	hostname, herr := os.Hostname()
	if herr != nil {
		hostname = "unknown"
	}
	rawSpec, err := json.Marshal(meta.Spec)
	if err != nil {
		return err
	}
	serverID := stringOr(document.Section("settings")["server_id"], "")
	if _, cerr := e.store.Create(ctx, &NewMachine{
		Name:       task.MachineName,
		Host:       hostname,
		Home:       e.machineWorkdir(task.MachineName),
		ServerID:   serverID,
		Hypervisor: meta.Spec.Hypervisor,
		Spec:       rawSpec,
	}); cerr != nil {
		return fmt.Errorf("create machine row: %w", cerr)
	}

	e.taskProgress(task, 60, "storing_configuration")
	// Sections store as the RAW document's own bytes — MergeConfigurationSections
	// passes json.RawMessage values through verbatim, so key order survives.
	rawSections := RawObject(documentRaw)
	sections := map[string]any{}
	for _, key := range []string{"settings", "zones", "networks", "disks", "metadata"} {
		if value, ok := rawSections[key]; ok {
			sections[key] = value
		}
	}
	// The rendered document's non-infrastructure half IS the provisioner
	// document — stored exactly where PUT stores it; a later PUT overrides it
	// verbatim. Package-based creates ONLY: the base's finalize persists no
	// provisioner (storeInfrastructureConfig stores settings/zones/networks/
	// disks/metadata and nothing else) — provisioner-less machines gain a
	// document via PUT when the user wants one, never here. EVERY top-level
	// key that is not one of the five infra keys rides in, in DOCUMENT ORDER
	// — unknown keys survive (the ruling; the old six-key whitelist dropped
	// them).
	if meta.Spec.HasProvisioner() {
		provisionerDoc, perr := buildProvisionerDocRaw(meta.Spec, documentRaw, rawSections)
		if perr != nil {
			return perr
		}
		sections["provisioner"] = provisionerDoc
	}
	if merr := e.store.MergeConfigurationSections(ctx, task.MachineName, sections); merr != nil {
		return merr
	}

	if output.UUID != "" {
		if uerr := e.store.SetUUID(ctx, task.MachineName, output.UUID); uerr != nil {
			return uerr
		}
	}

	// The transport-removal signal (the converged cross-agent flag, sync
	// 2026-07-18): the create body's remove_transport_on_completion persists
	// into configuration.settings — the ONE effective-flag home knob_current,
	// the PUT flip, and the provision chain's removal cycle all read. Absent
	// stores nothing: this agent's ruled default (false — keep) applies by
	// omission.
	if meta.Spec.RemoveTransportOnCompletion != nil {
		if serr := e.store.MergeSettingsKeys(ctx, task.MachineName, map[string]any{
			"remove_transport_on_completion": *meta.Spec.RemoveTransportOnCompletion,
		}); serr != nil {
			return serr
		}
	}

	// Notes/tags at create — the base's finalize persists both
	// (SubTaskExecutors.js: updateFields.notes/tags). Failures narrate; user
	// metadata never fails a build.
	if meta.Spec.Notes != "" {
		notes := meta.Spec.Notes
		if nerr := e.store.SetNotes(ctx, task.MachineName, &notes); nerr != nil {
			out.Write("stderr", "Storing notes failed: "+nerr.Error()+"\n")
		}
	}
	if len(meta.Spec.Tags) > 0 {
		if raw, jerr := json.Marshal(meta.Spec.Tags); jerr == nil {
			if terr := e.store.SetTags(ctx, task.MachineName, raw); terr != nil {
				out.Write("stderr", "Storing tags failed: "+terr.Error()+"\n")
			}
		}
	}
	e.taskProgress(task, 100, "completed")
	out.Write("stdout", "Machine "+task.MachineName+" finalized\n")
	return nil
}

// createInfraKeys are the document's infrastructure sections — stored as
// their own configuration sections, never inside the provisioner document.
var createInfraKeys = map[string]bool{
	"settings": true, "zones": true, "networks": true, "disks": true, "metadata": true,
}

// buildProvisionerDocRaw assembles the stored provisioner document's JSON
// MANUALLY, in DOCUMENT ORDER: the spec's package identity first, then every
// non-infrastructure top-level key of hosts[0] with its bytes verbatim — a
// map here would alphabetize, and duplicate identity keys from the document
// itself are skipped (the spec's values win, the previous behavior).
func buildProvisionerDocRaw(spec *Spec, documentRaw json.RawMessage,
	rawSections map[string]json.RawMessage,
) (json.RawMessage, error) {
	nameJSON, err := json.Marshal(spec.Provisioner.Name)
	if err != nil {
		return nil, err
	}
	versionJSON, err := json.Marshal(spec.Provisioner.Version)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString(`{"provisioner_name":`)
	buf.Write(nameJSON)
	buf.WriteString(`,"provisioner_version":`)
	buf.Write(versionJSON)
	for _, key := range OrderedKeys(documentRaw) {
		if createInfraKeys[key] || key == "provisioner_name" || key == "provisioner_version" {
			continue
		}
		value, ok := rawSections[key]
		if !ok {
			continue
		}
		keyJSON, kerr := json.Marshal(key)
		if kerr != nil {
			return nil, kerr
		}
		buf.WriteByte(',')
		buf.Write(keyJSON)
		buf.WriteByte(':')
		buf.Write(value)
	}
	buf.WriteByte('}')
	return json.RawMessage(buf.Bytes()), nil
}
