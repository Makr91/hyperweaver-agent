package machines

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/Makr91/hyperweaver-agent/internal/provisioner"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// prepareDocument executes machine_prepare in the create chain (and the
// provision chain's extract slot): render the package's Hosts.template.yml
// with the spec, materialize the working directory (package tree, id-files,
// ssls, hash-verified installer mounts), parse the spec's own hosts[HostIndex]
// entry (multi-host converged wire, sync 2026-07-17: M-Q1), and pass the
// document forward.
func (e *executors) prepareDocument(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	meta, err := readCreateMetadata(task)
	if err != nil {
		return err
	}
	spec := meta.Spec
	if !spec.HasProvisioner() {
		// The chain builders never queue prepare without a package — reaching
		// here means a builder regressed; say so instead of a GetVersion error.
		return errors.New("machine_prepare queued for a provisioner-less spec — nothing to render")
	}
	e.taskProgress(task, 10, "rendering_document")

	version, err := e.env.Registry.GetVersion(spec.Provisioner.Name, spec.Provisioner.Version)
	if err != nil {
		return fmt.Errorf("provisioner %s/%s: %w", spec.Provisioner.Name, spec.Provisioner.Version, err)
	}

	// Authoritative answer validation before every render (the Field DSL's
	// agent half; the HTTP 422 already gated the create — this catches
	// hand-edited specs and re-provisions against a stricter package).
	if problems, verr := provisioner.ValidateVersionAnswers(version, spec.Roles,
		spec.Properties, nil, false); verr != nil {
		return verr
	} else if len(problems) > 0 {
		keys := make([]string, 0, len(problems))
		for key := range problems {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			out.Write("stderr", "answer "+key+": "+problems[key]+"\n")
		}
		return fmt.Errorf("%d form answer(s) fail the package's field validation (listed in the task output)", len(problems))
	}

	settings := effectiveSettings(ctx, e.env, spec)
	mounts, roles, err := e.resolveInstallerFiles(ctx, spec, out)
	if err != nil {
		return err
	}
	rendered, err := provisioner.RenderHostsFile(&provisioner.GenerateInput{
		Version:  version,
		Settings: settings,
		Networks: spec.Networks,
		// disks in the render context, structured and verbatim — the
		// networks model exactly (converged, sync 2026-07-17): inert until
		// a template echoes it.
		Disks:          spec.Disks,
		Roles:          roles,
		UserProperties: spec.Properties,
		SecretsVars:    e.env.SecretsVars(),
	})
	if err != nil {
		return err
	}
	if markers := provisioner.LegacyMarkers(rendered); len(markers) > 0 {
		out.Write("stderr", "WARNING: rendered document still contains ::TOKEN:: markers ("+
			strings.Join(markers, ", ")+") — the package template was never converted to Jinja2\n")
	}

	// Each machine reads ITS OWN hosts[] entry (multi-host converged wire,
	// sync 2026-07-17: M-Q1) — HostIndex is 0 for every single-host spec.
	document, err := parseHostsDocumentOrdered(rendered, spec.HostIndex)
	if err != nil {
		return err
	}
	workdir := e.machineWorkdir(task.MachineName)
	e.taskProgress(task, 50, "materializing_workdir")
	out.Write("stdout", "Materializing working directory "+workdir+"\n")
	if merr := provisioner.Materialize(&provisioner.MaterializeInput{
		MachineDir: workdir,
		Version:    version,
		HostsYML:   rendered,
		Roles:      roles,
		Installers: mounts,
		SafeIDPath: spec.SafeIDPath,
		CACertPath: e.env.CACertPath,
		CAKeyPath:  e.env.CAKeyPath,
	}); merr != nil {
		return merr
	}

	if rerr := e.recordOutput(ctx, task, spec, &createExecutionOutput{Document: document}); rerr != nil {
		return rerr
	}
	e.taskProgress(task, 100, "completed")
	return nil
}

// effectiveSettings copies the spec's settings and injects the effective
// sync method and default network interface (the render-time injections the
// package template consumes: folders[].type = settings.sync_method).
func effectiveSettings(ctx context.Context, env *ProvisionEnv, spec *Spec) map[string]any {
	return EffectiveSettings(ctx, spec, env.DefaultSyncMethod, env.DefaultNetworkInterface)
}

// specDocument builds the working document straight from the spec — the
// provisioner-less create path (the base's model: the request body IS the
// document; no render exists without a package). Every optional section the
// base's create accepts rides through: disks (boot/additional/cdroms), zones,
// cloud_init, and the vbox directives passthrough.
func specDocument(ctx context.Context, env *ProvisionEnv, spec *Spec) map[string]any {
	document := map[string]any{
		"settings": effectiveSettings(ctx, env, spec),
	}
	if len(spec.Networks) > 0 {
		document["networks"] = normalizeNetworkDNS(spec.Networks)
	}
	for key, section := range map[string]map[string]any{
		"disks":      spec.Disks,
		"zones":      spec.Zones,
		"cloud_init": spec.CloudInit,
		"vbox":       spec.Vbox,
	} {
		if len(section) > 0 {
			document[key] = section
		}
	}
	return document
}

// normalizeNetworkDNS declares wire-string dns entries into the document's
// map shape [{nameserver: ip}] (converged contract, sync 2026-07-18 — the
// networking role hard-consumes dns[0]['nameserver']). Empty strings drop;
// map entries ride untouched.
func normalizeNetworkDNS(networks []any) []any {
	for _, entry := range networks {
		network, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		list, lok := network["dns"].([]any)
		if !lok {
			continue
		}
		changed := false
		normalized := make([]any, 0, len(list))
		for _, item := range list {
			if s, sok := item.(string); sok {
				changed = true
				if s != "" {
					normalized = append(normalized, map[string]any{"nameserver": s})
				}
				continue
			}
			normalized = append(normalized, item)
		}
		if changed {
			network["dns"] = normalized
		}
	}
	return networks
}

// EffectiveSettings builds the render-time settings document from a spec —
// shared by the create handler's render-once box resolution and the prepare
// executor.
func EffectiveSettings(ctx context.Context, spec *Spec, defaultSync, defaultNIC string) map[string]any {
	requested := spec.SyncMethod
	if requested == "" {
		requested = defaultSync
	}
	method, _ := effectiveSyncMethod(ctx, requested)
	settings := make(map[string]any, len(spec.Settings)+2)
	for key, value := range spec.Settings {
		settings[key] = value
	}
	settings["sync_method"] = method
	if _, present := settings["default_network_interface"]; !present && defaultNIC != "" {
		settings["default_network_interface"] = defaultNIC
	}
	return settings
}

// ParseHostsDocument extracts hosts[0] from a rendered Hosts.yml — the
// single-host readers' view (index 0 keeps every existing path byte-identical).
func ParseHostsDocument(rendered []byte) (map[string]any, error) {
	hosts, err := ParseHostsDocuments(rendered)
	if err != nil {
		return nil, err
	}
	return hosts[0], nil
}

// ParseHostsDocuments extracts EVERY hosts[] entry from a rendered Hosts.yml
// (multi-host converged wire, sync 2026-07-17: M-Q1): the DOCUMENT is the
// program — one render may carry N coordinated machines, and the create
// handler counts and pre-checks them ALL before anything queues.
func ParseHostsDocuments(rendered []byte) ([]map[string]any, error) {
	var parsed struct {
		Hosts []map[string]any `yaml:"hosts"`
	}
	if err := yaml.Unmarshal(rendered, &parsed); err != nil {
		return nil, fmt.Errorf("parse rendered document: %w", err)
	}
	if len(parsed.Hosts) == 0 {
		return nil, errors.New("rendered document carries no hosts[] entry")
	}
	return parsed.Hosts, nil
}

// parseHostsDocumentOrdered extracts hosts[index] as ordered JSON bytes: the
// ordered-map decode keeps every object's keys in the rendered YAML's own
// order, and the JSON conversion writes them back in that order — the storage
// ingress the ruling demands (a plain map decode would alphabetize the
// provisioning:/vars: sections on re-marshal). index is the machine's own
// hosts[] slot (multi-host converged wire, sync 2026-07-17: M-Q1) — 0 for
// every single-host document; out of range names the count.
func parseHostsDocumentOrdered(rendered []byte, index int) (json.RawMessage, error) {
	var parsed struct {
		Hosts []any `yaml:"hosts"`
	}
	if err := yaml.UnmarshalWithOptions(rendered, &parsed, yaml.UseOrderedMap()); err != nil {
		return nil, fmt.Errorf("parse rendered document: %w", err)
	}
	if len(parsed.Hosts) == 0 {
		return nil, errors.New("rendered document carries no hosts[] entry")
	}
	if index < 0 || index >= len(parsed.Hosts) {
		return nil, fmt.Errorf("spec asks for hosts[%d] but the rendered document carries %d hosts[] entries",
			index, len(parsed.Hosts))
	}
	raw, err := orderedYAMLToJSON(parsed.Hosts[index])
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// orderedYAMLToJSON converts an ordered-map YAML value into JSON bytes,
// objects keeping their yaml.MapSlice key order. MapSlice keys may be any
// scalar type — non-strings render through fmt (JSON object keys must be
// strings). map[string]interface{} should never appear under an ordered
// decode; it marshals defensively (alphabetized, order already lost upstream).
func orderedYAMLToJSON(value any) ([]byte, error) {
	switch v := value.(type) {
	case yaml.MapSlice:
		var buf bytes.Buffer
		buf.WriteByte('{')
		for i := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			key, ok := v[i].Key.(string)
			if !ok {
				key = fmt.Sprint(v[i].Key)
			}
			keyJSON, kerr := json.Marshal(key)
			if kerr != nil {
				return nil, kerr
			}
			buf.Write(keyJSON)
			buf.WriteByte(':')
			encoded, verr := orderedYAMLToJSON(v[i].Value)
			if verr != nil {
				return nil, verr
			}
			buf.Write(encoded)
		}
		buf.WriteByte('}')
		return buf.Bytes(), nil
	case []any:
		var buf bytes.Buffer
		buf.WriteByte('[')
		for i := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			encoded, verr := orderedYAMLToJSON(v[i])
			if verr != nil {
				return nil, verr
			}
			buf.Write(encoded)
		}
		buf.WriteByte(']')
		return buf.Bytes(), nil
	default:
		return json.Marshal(value)
	}
}

// parseConfigBytes reads the ordered document bytes back into the map view
// the executors' reads use (empty on failure) — reads never need order, only
// storage does.
func parseConfigBytes(raw json.RawMessage) MachineConfig {
	config := MachineConfig{}
	if len(raw) == 0 {
		return config
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		return MachineConfig{}
	}
	return config
}
