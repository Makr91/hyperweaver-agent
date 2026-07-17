package machines

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/Makr91/hyperweaver-agent/internal/assets"
	"github.com/Makr91/hyperweaver-agent/internal/provisioner"
	"github.com/Makr91/hyperweaver-agent/internal/qga"
	"github.com/Makr91/hyperweaver-agent/internal/sslcert"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// The create orchestration children — zoneweaver's ZoneCreationManager
// (SubTaskExecutors/StorageManager/ConfigurationManager/ZoneLifecycle)
// spoken in VBoxManage, with Hosts.rb's exact VirtualBox directive set.
// Chain: machine_prepare (render the package template + materialize the
// working directory — the provisioning-content step our registry replaces
// zoneweaver's artifact with) → machine_create_storage (media) →
// machine_create_config (createvm/modifyvm/attach) → machine_create_finalize
// (row + document sections). Children hand results forward by updating their
// OWN task metadata (_execution_output) and reading it through depends_on —
// the base's exact handoff.

// Create-chain operations.
const (
	OpCreateOrchestration = "machine_create_orchestration"
	OpCreateStorage       = "machine_create_storage"
	OpCreateConfig        = "machine_create_config"
	OpCreateFinalize      = "machine_create_finalize"
)

// createExecutionOutput is the _execution_output document children pass
// forward.
type createExecutionOutput struct {
	// Document is the machine's own rendered hosts[HostIndex] entry
	// (multi-host converged wire, sync 2026-07-17: M-Q1) —
	// settings/networks/disks/zones plus
	// the provisioner sections (folders/provisioning/vars/roles) — as ordered
	// JSON bytes: the rendered YAML's own key order, which finalize stores
	// verbatim (a map here would alphabetize it).
	Document json.RawMessage `json:"document"`
	// BootdiskPath is the machine's cloned boot medium.
	BootdiskPath string `json:"bootdisk_path,omitempty"`
	// MediaCreated tracks created media for reverse-order rollback.
	MediaCreated []string `json:"media_created,omitempty"`
	// UUID is the VirtualBox identity createvm reported.
	UUID string `json:"uuid,omitempty"`
}

// createTaskMetadata is every create child's metadata: the creation spec
// verbatim (the base carries the request body verbatim) plus the running
// _execution_output.
type createTaskMetadata struct {
	Spec            *Spec                  `json:"spec"`
	ExecutionOutput *createExecutionOutput `json:"_execution_output,omitempty"`
}

// readCreateMetadata parses a create child's own metadata.
func readCreateMetadata(task *tasks.Task) (*createTaskMetadata, error) {
	if task.Metadata == nil {
		return nil, errors.New("create task has no metadata")
	}
	var meta createTaskMetadata
	if err := json.Unmarshal([]byte(*task.Metadata), &meta); err != nil {
		return nil, fmt.Errorf("parse create metadata: %w", err)
	}
	if meta.Spec == nil {
		return nil, errors.New("create task metadata has no spec")
	}
	return &meta, nil
}

// dependencyOutput loads the _execution_output the dependency child recorded
// (the base reads the storage task through depends_on).
func (e *executors) dependencyOutput(ctx context.Context, task *tasks.Task) (*createExecutionOutput, error) {
	if task.DependsOn == nil {
		return nil, errors.New("create child has no dependency to read")
	}
	previous, err := e.queue.Store().Get(ctx, *task.DependsOn)
	if err != nil {
		return nil, fmt.Errorf("dependency task: %w", err)
	}
	if previous.Metadata == nil {
		return nil, errors.New("dependency task carries no metadata")
	}
	var meta createTaskMetadata
	if err := json.Unmarshal([]byte(*previous.Metadata), &meta); err != nil {
		return nil, fmt.Errorf("parse dependency metadata: %w", err)
	}
	if meta.ExecutionOutput == nil {
		return nil, errors.New("dependency task recorded no execution output")
	}
	return meta.ExecutionOutput, nil
}

// recordOutput writes the child's _execution_output into its own metadata.
func (e *executors) recordOutput(ctx context.Context, task *tasks.Task, spec *Spec, out *createExecutionOutput) error {
	raw, err := json.Marshal(&createTaskMetadata{Spec: spec, ExecutionOutput: out})
	if err != nil {
		return err
	}
	return e.queue.Store().UpdateMetadata(ctx, task.ID, string(raw))
}

// machineWorkdir is the machine's working directory under the machines root
// — the provisioning dataset analog, and where the VM's media live.
func (e *executors) machineWorkdir(machineName string) string {
	return filepath.Join(e.env.MachinesDir, provisioner.MachineDirName(machineName))
}

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
		document["networks"] = spec.Networks
	}
	for key, section := range map[string]map[string]any{
		"disks":      spec.Disks,
		"zones":      spec.Zones,
		"cloud_init": spec.CloudInit,
		"vbox":       spec.Vbox,
		"hardware":   spec.Hardware,
	} {
		if len(section) > 0 {
			document[key] = section
		}
	}
	return document
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

// createStorage executes machine_create_storage: resolve the template
// (post-download re-resolution included), clone its disk image as the boot
// medium, grow it to disks.boot.size, create the additional media — every
// created medium tracked for reverse-order rollback (StorageManager 1:1; on
// this hypervisor the boot disk IS the box's disk image).
func (e *executors) createStorage(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	meta, err := readCreateMetadata(task)
	if err != nil {
		return err
	}
	var output *createExecutionOutput
	if meta.Spec.HasProvisioner() {
		output, err = e.dependencyOutput(ctx, task)
		if err != nil {
			return err
		}
	} else {
		// No prepare child ran — the base's shape (its chain has no render
		// step; the create body IS the document): build the document straight
		// from the spec. Provisioning attaches later via PUT, never here.
		// Marshal order is irrelevant on this path — no provisioner section
		// exists (only the provisioner document's key order is load-bearing).
		out.Write("stdout", "Provisioner-less create — building the document from the spec\n")
		raw, merr := json.Marshal(specDocument(ctx, e.env, meta.Spec))
		if merr != nil {
			return merr
		}
		output = &createExecutionOutput{Document: raw}
	}
	document := parseConfigBytes(output.Document)
	settings := document.Section("settings")
	disks := document.Section("disks")

	vboxExe := VBoxManagePath(ctx)
	if vboxExe == "" {
		return errors.New("VirtualBox is not installed")
	}

	workdir := e.machineWorkdir(task.MachineName)
	// prepare's materialize normally creates the working directory; a
	// provisioner-less create has no prepare, so ensure it (idempotent) —
	// media land in it either way.
	if merr := os.MkdirAll(workdir, 0o750); merr != nil {
		return merr
	}
	media := []string{}
	rollback := func() {
		for i := len(media) - 1; i >= 0; i-- {
			if cerr := vbox.CloseMedium(context.Background(), vboxExe, media[i], true); cerr != nil {
				out.Write("stderr", "Rollback of "+media[i]+" failed: "+cerr.Error()+"\n")
			}
			// The rollback deletes what this step created + stamped — the
			// sidecar stamp (when the property write fell back) goes with it.
			removeMediumSidecar(media[i])
		}
	}

	// Typed disk spec re-validation at the RENDERED document (Mark's word,
	// sync 2026-07-17 — the ZERO-inference model): the packaged-render path
	// can emit disks the HTTP pre-flight never saw, so the same frozen
	// strings gate here before any medium materializes. Warnings narrate —
	// they never fail a build.
	diskProblems, diskWarnings := ValidateDisks(disks, settings)
	for _, warning := range diskWarnings {
		out.Write("stderr", "WARNING: "+warning+"\n")
	}
	if len(diskProblems) > 0 {
		for _, problem := range diskProblems {
			out.Write("stderr", problem+"\n")
		}
		return errors.New(diskProblems[0])
	}

	// Boot medium — disks.boot.type is the ONLY dispatcher (the typed disk
	// spec; the old presence-dispatch ladder died with it):
	//   template → clone settings.box's image, grow to boot.size, stamp
	//   image    → attach an EXISTING file AS-IS (existence + in-use
	//              pre-checked; never created/deleted/resized, never stamped)
	//   blank    → create a fresh VDI (sparse by default), stamp
	//   none     → DISKLESS — no boot medium at all (PXE/manual)
	// An ABSENT disks.boot is the spelled default: template when settings.box
	// is present, none otherwise — exactly the old box/diskless behavior.
	e.taskProgress(task, 10, "preparing_storage")
	boot := mapOr(disks["boot"])
	bootPath := ""
	boxRef := stringOr(settings["box"], "")
	switch EffectiveBootType(disks, settings) {
	case DiskTypeImage:
		bootPath = stringOr(boot["path"], "")
		if _, serr := os.Stat(bootPath); serr != nil {
			return errors.New("disks.boot.path " + bootPath + " does not exist on this host")
		}
		// In-use pre-check: a medium another machine holds is refused unless
		// the entry carries force: true (the frozen string names the holder).
		if force, _ := boot["force"].(bool); force {
			out.Write("stdout", "force: true — skipping the in-use pre-check for "+bootPath+"\n")
		} else {
			holder, herr := mediumHolder(ctx, vboxExe, bootPath, task.MachineName)
			if herr != nil {
				return herr
			}
			if holder != "" {
				return errors.New("disks.boot.path " + bootPath + " is attached to " + holder +
					" (set force: true to attach anyway)")
			}
		}
		out.Write("stdout", "Attaching existing boot medium "+bootPath+" (image — attached as-is, never ours to delete)\n")

	case DiskTypeTemplate:
		org, box, ok := strings.Cut(boxRef, "/")
		if !ok || org == "" || box == "" {
			return errors.New(`settings.box must be "organization/box-name"`)
		}
		template, terr := e.store.FindTemplate(ctx, org, box,
			stringOr(settings["box_version"], "latest"), stringOr(settings["box_arch"], "amd64"))
		if terr != nil {
			return fmt.Errorf("template %s/%s: %w (download it first — POST /templates/pull or let create chain it)", org, box, terr)
		}
		e.taskProgress(task, 30, "importing_template")
		bootPath = filepath.Join(workdir, "boot"+filepath.Ext(template.DiskPath))
		clearStaleMedium(ctx, vboxExe, bootPath, out)
		out.Write("stdout", "Cloning template "+template.DiskPath+" → "+bootPath+"\n")
		if cerr := vbox.CloneMedium(ctx, vboxExe, template.DiskPath, bootPath, ""); cerr != nil {
			rollback()
			return cerr
		}
		media = append(media, bootPath)
		// Provenance stamp at materialization (property-first, sidecar
		// fallback): the delete flow destroys stamped media and preserves
		// everything else.
		if perr := stampMedium(ctx, vboxExe, bootPath, DiskTypeTemplate, out); perr != nil {
			rollback()
			return perr
		}
		if sizeMB := sizeToMB(boot["size"]); sizeMB > 0 {
			if rerr := vbox.ResizeMedium(ctx, vboxExe, bootPath, sizeMB); rerr != nil {
				out.Write("stderr", "Boot volume resize failed (continuing with template size): "+rerr.Error()+"\n")
			}
		}

	case DiskTypeBlank:
		e.taskProgress(task, 30, "creating_boot_volume")
		name := stringOr(boot["volume_name"], "boot")
		bootPath = filepath.Join(workdir, name+".vdi")
		sparse := true
		if v, bok := boot["sparse"].(bool); bok {
			sparse = v
		}
		clearStaleMedium(ctx, vboxExe, bootPath, out)
		out.Write("stdout", fmt.Sprintf("Creating blank boot volume %s (%d MB)\n",
			bootPath, sizeToMB(boot["size"])))
		if cerr := vbox.CreateMedium(ctx, vboxExe, bootPath, sizeToMB(boot["size"]), sparse); cerr != nil {
			rollback()
			return cerr
		}
		media = append(media, bootPath)
		if perr := stampMedium(ctx, vboxExe, bootPath, DiskTypeBlank, out); perr != nil {
			rollback()
			return perr
		}

	case DiskTypeNone:
		out.Write("stdout", "disks.boot.type none — DISKLESS machine (attach media later via modify)\n")

	default:
		// ValidateDisks refused every invalid/missing type above — defensive.
		return errors.New("disks.boot.type is required when disks.boot is present (template|image|blank|none)")
	}

	e.taskProgress(task, 60, "creating_additional_disks")
	disksDir := filepath.Join(workdir, "disks")
	for i, entry := range listOr(disks["additional_disks"]) {
		disk := mapOr(entry)
		// type is the dispatcher here too (image|blank — ValidateDisks
		// refused everything else above).
		switch stringOr(disk["type"], "") {
		case DiskTypeImage:
			// Attached by the config phase AS-IS — never created, stamped, or
			// rolled back here. Existence + in-use pre-checks mirror boot's
			// with the 1-based entry prefix.
			existing := stringOr(disk["path"], "")
			label := "disks.additional_disks[" + strconv.Itoa(i+1) + "].path " + existing
			if _, serr := os.Stat(existing); serr != nil {
				rollback()
				return errors.New(label + " does not exist on this host")
			}
			if force, _ := disk["force"].(bool); force {
				out.Write("stdout", "force: true — skipping the in-use pre-check for "+existing+"\n")
			} else {
				holder, herr := mediumHolder(ctx, vboxExe, existing, task.MachineName)
				if herr != nil {
					rollback()
					return herr
				}
				if holder != "" {
					rollback()
					return errors.New(label + " is attached to " + holder + " (set force: true to attach anyway)")
				}
			}
			out.Write("stdout", "Additional disk uses existing medium "+existing+"\n")

		case DiskTypeBlank:
			name := stringOr(disk["volume_name"], fmt.Sprintf("disk%d", i+1))
			sizeMB := sizeToMB(disk["size"])
			if merr := os.MkdirAll(disksDir, 0o750); merr != nil {
				rollback()
				return merr
			}
			diskPath := filepath.Join(disksDir, name+".vdi")
			sparse := true
			if v, bok := disk["sparse"].(bool); bok {
				sparse = v
			}
			clearStaleMedium(ctx, vboxExe, diskPath, out)
			out.Write("stdout", fmt.Sprintf("Creating %s (%d MB)\n", diskPath, sizeMB))
			if cerr := vbox.CreateMedium(ctx, vboxExe, diskPath, sizeMB, sparse); cerr != nil {
				rollback()
				return cerr
			}
			media = append(media, diskPath)
			if perr := stampMedium(ctx, vboxExe, diskPath, DiskTypeBlank, out); perr != nil {
				rollback()
				return perr
			}
		}
	}

	output.BootdiskPath = bootPath
	output.MediaCreated = media
	if rerr := e.recordOutput(ctx, task, meta.Spec, output); rerr != nil {
		rollback()
		return rerr
	}
	e.taskProgress(task, 100, "completed")
	return nil
}

// createConfig executes machine_create_config: createvm + the full Hosts.rb
// VirtualBox directive set + storage attach + NICs + cloud-init properties.
// Failure unregisters the half-made machine (the base's zonecfg delete -F).
func (e *executors) createConfig(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	meta, err := readCreateMetadata(task)
	if err != nil {
		return err
	}
	output, err := e.dependencyOutput(ctx, task)
	if err != nil {
		return err
	}
	document := parseConfigBytes(output.Document)
	settings := document.Section("settings")

	// consoleport guard at the RENDERED document (converged, sync 2026-07-17):
	// the 0.1.31 package defaults consoleport to server_id, which the HTTP
	// pre-flight never sees — packaged creates render in the task chain. An
	// out-of-range or non-numeric value fails HERE, before createvm/modifyvm,
	// instead of surfacing as VRDE's cryptic mid-chain E_INVALIDARG. An absent
	// consoleport stays exactly as before (no VRDE flags, no invented default).
	if value, ok := settings["consoleport"]; ok {
		if problem := ConsolePortProblem(value); problem != "" {
			out.Write("stderr", "Rendered document carries consoleport "+
				stringOr(value, fmt.Sprint(value))+": "+problem+"\n")
			return errors.New(problem)
		}
	}
	// vcpus guard at the RENDERED document (converged, sync 2026-07-17 —
	// zoneweaver's proposal, ACKED): a present vcpus must be a whole number
	// >= 1 (the 0.1.31 template renders integral floats like 2.0 — those
	// pass); anything else fails HERE, before createvm/modifyvm. An absent
	// vcpus keeps the existing default-2 behavior byte-identical.
	if value, ok := settings["vcpus"]; ok {
		if problem := VCPUProblem(value); problem != "" {
			out.Write("stderr", "Rendered document carries vcpus "+
				stringOr(value, fmt.Sprint(value))+": "+problem+"\n")
			return errors.New(problem)
		}
	}

	vboxExe := VBoxManagePath(ctx)
	if vboxExe == "" {
		return errors.New("VirtualBox is not installed")
	}

	e.taskProgress(task, 20, "creating_vm")
	e.clearStaleSettings(ctx, vboxExe, task.MachineName, out)
	arch := "x86"
	if strings.Contains(stringOr(settings["box_arch"], "amd64"), "arm") {
		arch = "arm"
	}
	uuid, err := vbox.CreateVM(ctx, vboxExe, task.MachineName, arch,
		stringOr(settings["os_type"], "Debian_64"), e.env.MachinesDir)
	if err != nil {
		return err
	}
	failed := func(step string, ferr error) error {
		out.Write("stderr", step+" failed — unregistering the half-made machine\n")
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if uerr := vbox.UnregisterVM(cleanupCtx, vboxExe, task.MachineName, false); uerr != nil {
			out.Write("stderr", "Unregister failed: "+uerr.Error()+"\n")
		}
		e.clearStaleSettings(cleanupCtx, vboxExe, task.MachineName, out)
		return ferr
	}

	// Host-type NICs ride the provisioning network's host-only interface —
	// resolved by host IP (VirtualBox names interfaces itself); absent setup
	// is a loud note, never an invented adapter.
	hostAdapter := ""
	if e.env.Network.Enabled && hasHostNetworks(document) {
		if iface, ferr := FindProvisioningIf(ctx, vboxExe, e.env.Network.HostIP); ferr == nil && iface != nil {
			hostAdapter = iface.Name
		} else {
			out.Write("stderr", "Provisioning network is not set up — host-type NICs attach without an adapter (run POST /provisioning/network/setup first)\n")
		}
	}

	// The provisioning NIC's transport (Mark's architecture, 2026-07-07):
	// adapter 1 is the provisioning NIC — on VirtualBox that is the NAT
	// adapter, and the host reaches the guest through an ssh port-forward
	// (vagrant's model). The pipeline dials 127.0.0.1:<port>, never a real
	// adapter, so the networking role can reconfigure every guest interface
	// without ever killing the session carrying it.
	sshPort, perr := allocateLocalPort(ctx)
	if perr != nil {
		return failed("ssh port-forward allocation", perr)
	}
	out.Write("stdout", fmt.Sprintf("Provisioning SSH port-forward: 127.0.0.1:%d → guest 22\n", sshPort))

	// winrm communicator (zoneweaver's shipped winrm shape, sync 2026-07-17:
	// W-Q1..W-Q5): a SECOND natpf1 forward beside the ssh one — the pipeline
	// dials 127.0.0.1:<forward> for winrm exactly like it does for ssh. The
	// document's winrm_port names the GUEST port (ruled, no veto).
	winrmForwardPort := 0
	if winrm, _ := ExtractWinRM(settings); winrm.Enabled {
		port, werr := allocateLocalPort(ctx)
		if werr != nil {
			return failed("winrm port-forward allocation", werr)
		}
		winrmForwardPort = port
		out.Write("stdout", fmt.Sprintf("Provisioning WinRM port-forward: 127.0.0.1:%d → guest %d\n",
			winrmForwardPort, winrm.Port))
	}

	e.taskProgress(task, 40, "configuring_vm")
	flags, ferr := modifyFlags(document, hostAdapter, sshPort, winrmForwardPort)
	if ferr != nil {
		return failed("modifyvm", ferr)
	}
	// The QEMU guest-agent UART: COM2 onto a host pipe — the credential-less
	// guest channel the box templates' qemu-ga answers on. A PER-MACHINE
	// create option (Mark's Proxmox-model ruling 2026-07-12, zoneweaver's
	// shipped decision ported: zones.guest_agent === true, default OFF, under
	// the guest_agent.enabled master gate — ConfigurationManager.js's
	// buildExtraAttrCommand). A document claiming serial port 2 itself wins;
	// QGA steps aside. Opt-in later via POST /machines/{name}/guest-agent/setup.
	guestAgent, _ := document.Section("zones")["guest_agent"].(bool)
	if e.env.GuestAgentEnabled && guestAgent {
		if serialPortClaimed(document.Section("hardware"), 2) {
			out.Write("stderr", "Document claims serial port 2 — guest-agent UART skipped\n")
		} else {
			pipe := qga.PipePath(e.machineWorkdir(task.MachineName), task.MachineName)
			flags = append(flags, "--uart2", "0x2F8", "3", "--uart-mode2", "server", pipe)
			out.Write("stdout", "Guest-agent channel: COM2 → "+pipe+"\n")
		}
	}
	// VRDE TLS from birth (Mark's zero-click ruling 2026-07-11): mint the
	// machine's certificate from the agent CA and set the Enhanced-security
	// properties with the other create flags — every new machine is
	// browser-RDP-ready without the vrde-tls setup. PREPENDED so document
	// knobs override (modifyvm's last occurrence wins). Failure only
	// narrates — the bridge self-heals live at first connect anyway.
	if e.env.VRDECertRoot != "" {
		certPath, keyPath, caPath, verr := sslcert.EnsureVRDECertificate(
			e.env.CACertPath, e.env.CAKeyPath,
			filepath.Join(e.env.VRDECertRoot, task.MachineName), task.MachineName)
		if verr != nil {
			out.Write("stderr", "VRDE TLS material generation failed (the browser-RDP bridge self-heals at first connect): "+verr.Error()+"\n")
		} else {
			flags = append([]string{
				"--vrde-property=Security/Method=Negotiate",
				"--vrde-property=Security/ServerCertificate=" + certPath,
				"--vrde-property=Security/ServerPrivateKey=" + keyPath,
				"--vrde-property=Security/CACertificate=" + caPath,
			}, flags...)
			out.Write("stdout", "VRDE TLS: certificate minted, Enhanced security set — browser-RDP ready from birth\n")
		}
	}
	if merr := vbox.ModifyVM(ctx, vboxExe, task.MachineName, flags); merr != nil {
		return failed("modifyvm", merr)
	}

	// Pin each host-network address as a DHCP fixed lease (the base's
	// dhcp_add_host block): the guest's ordinary DHCP request then receives
	// the document's own control IP — the deterministic addressing wait_ssh
	// dials.
	if hostAdapter != "" {
		leases := 0
		for i, entry := range document.List("networks") {
			network := mapOr(entry)
			if stringOr(network["type"], "") != "host" {
				continue
			}
			address := stringOr(network["address"], "")
			if address == "" {
				continue
			}
			// NIC numbering follows the adapter shift: NAT at 1, this
			// document network at adapter i+2.
			if lerr := vbox.SetDHCPFixedAddress(ctx, vboxExe, hostAdapter,
				task.MachineName, i+2, address); lerr != nil {
				return failed("dhcp fixed lease", lerr)
			}
			out.Write("stdout", fmt.Sprintf("Fixed DHCP lease: NIC %d → %s\n", i+2, address))
			leases++
		}
		// A running VBoxNetDHCP never re-reads its configuration
		// (runtime-proven 2026-07-07: hwtest-03's registered lease was
		// ignored — the guest drew the range start — until `dhcpserver
		// restart`). No process yet refuses the restart; that is fine, the
		// first boot starts it with fresh config.
		if leases > 0 {
			if rerr := vbox.RestartDHCPServer(ctx, vboxExe, hostAdapter); rerr != nil {
				out.Write("stdout", "DHCP server restart skipped (not running yet)\n")
			} else {
				out.Write("stdout", "DHCP server restarted — fixed leases active\n")
			}
		}
	}

	e.taskProgress(task, 60, "attaching_storage")
	if serr := e.attachStorage(ctx, vboxExe, task.MachineName, document, output, out); serr != nil {
		return failed("storage attach", serr)
	}

	e.taskProgress(task, 80, "configuring_cloud_init")
	for key, value := range mapOr(document["cloud_init"]) {
		if s := stringOr(value, ""); s != "" {
			if perr := vbox.SetGuestProperty(ctx, vboxExe, task.MachineName,
				"/Hyperweaver/CloudInit/"+key, s); perr != nil {
				out.Write("stderr", "cloud-init property "+key+": "+perr.Error()+"\n")
			}
		}
	}

	output.UUID = uuid
	if rerr := e.recordOutput(ctx, task, meta.Spec, output); rerr != nil {
		return failed("record output", rerr)
	}
	e.taskProgress(task, 100, "completed")
	out.Write("stdout", "Machine "+task.MachineName+" configured ("+uuid+")\n")
	return nil
}

// allocateLocalPort reserves a free localhost TCP port for the ssh
// port-forward (bind :0, read the assignment, release).
func allocateLocalPort(ctx context.Context) (int, error) {
	var config net.ListenConfig
	listener, err := config.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port, nil
}

// hasHostNetworks reports whether the document declares any host-type
// network (the provisioning-network riders).
func hasHostNetworks(document MachineConfig) bool {
	for _, entry := range document.List("networks") {
		if stringOr(mapOr(entry)["type"], "") == "host" {
			return true
		}
	}
	return false
}

// modifyFlags assembles the modifyvm set FROM THE DOCUMENT — zoneweaver's
// model: core config + the document-driven attribute map, nothing hardcoded.
// settings drive resources/console/firmware, networks[] drive the adapters,
// and vbox.directives is the generic passthrough (the zonecfg attr-map
// analog). Adapter 1 is vagrant's reserved NAT (Mark's ruling 2026-07-07):
// guest internet egress AND the layout every provisioner assumes — the role
// stacks were built for vagrant's NAT-first guests on BOTH hypervisors
// (vagrant-zones emulated it on bhyve; runtime-proven: the networking role
// refuses guests with fewer than two interfaces). Document networks occupy
// adapters 2+ (host-type entries ride hostOnlyAdapter, the provisioning
// network's interface).
func modifyFlags(document MachineConfig, hostOnlyAdapter string, sshForwardPort, winrmForwardPort int) ([]string, error) {
	settings := document.Section("settings")
	flags := []string{
		// Browser-RDP-era defaults (Mark's directive 2026-07-10, after live
		// multi-connection testing): absolute pointer + USB keyboard + xHCI
		// for usable consoles, bidirectional clipboard, and a VRDE server
		// that takes parallel clients and keeps the guest session across
		// reconnects. Emitted FIRST — any document knob later in the flag
		// list overrides (modifyvm's last occurrence wins).
		"--mouse=usbtablet",
		"--keyboard=usb",
		"--usb-xhci=on",
		"--clipboard-mode=bidirectional",
		"--clipboard-file-transfers=enabled",
		"--vrde-multi-con=on",
		"--vrde-reuse-con=on",
		// VCPUCount, not intOr (converged v2, sync 2026-07-17): a guard-passed
		// float-string like "4.0" must apply as 4, never the default.
		"--cpus=" + strconv.FormatInt(VCPUCount(settings["vcpus"], 2), 10),
		"--memory=" + strconv.FormatInt(memoryToMB(settings["memory"]), 10),
		"--nic1=nat",
		// The NAT adapter's fixed marker MAC — Hosts.rb:310 verbatim
		// (vb.customize --macaddress1 00FF00FF00FF): the role stacks know
		// vagrant's NAT adapter by it.
		"--mac-address1=00FF00FF00FF",
	}
	if sshForwardPort > 0 {
		flags = append(flags,
			fmt.Sprintf("--natpf1=ssh,tcp,127.0.0.1,%d,,22", sshForwardPort))
	}
	if winrmForwardPort > 0 {
		// The winrm communicator's transport forward (W-Q1..W-Q5): the guest
		// port is the RULED winrm_port — re-read here so the rule and its
		// allocation (createConfig) can never disagree on the document.
		winrm, _ := ExtractWinRM(settings)
		flags = append(flags,
			fmt.Sprintf("--natpf1=winrm,tcp,127.0.0.1,%d,,%d", winrmForwardPort, winrm.Port))
	}
	// roles[].port_forwards → --natpf1 rules on the reserved NAT adapter
	// (core/Hosts.rb:312-320's forwarded_port entries {guest, host, ip};
	// implemented per the 2026-07-16 parity ruling, superseding the earlier
	// TODO-only one). Rule names carry the ports, so two roles forwarding the
	// same pair collide loudly in VirtualBox instead of silently doubling.
	portForwards, pfErr := rolePortForwardFlags(document.List("roles"))
	if pfErr != nil {
		return nil, pfErr
	}
	flags = append(flags, portForwards...)
	if port := intOr(settings["consoleport"], 0); port > 0 {
		flags = append(flags, "--vrde=on",
			"--vrde-port="+strconv.FormatInt(port, 10))
		if host := stringOr(settings["consolehost"], ""); host != "" {
			flags = append(flags, "--vrde-address="+host)
		}
	}
	if strings.EqualFold(stringOr(settings["firmware_type"], ""), "UEFI") {
		flags = append(flags, "--firmware=efi")
	}
	// Boot order (--boot1..4): settings.boot_order is an ordered list of
	// floppy|dvd|disk|net|none — the ISO-first install story (attach the ISO,
	// boot dvd before disk). Unset slots after the list are cleared to none so
	// the order is exactly what the document says.
	flags = append(flags, bootOrderFlags(settings["boot_order"])...)

	// The base's zone attrs at CREATE (Mark's proper-tab ruling — the same
	// named vocabulary the modify executor translates, buildZoneAttributeMap's
	// set): bootrom→firmware, hostbridge→chipset (i440fx→piix3), vnc→VRDE,
	// acpi/xhci direct, netif→each DOCUMENT adapter's hardware type (the
	// reserved NAT adapter keeps VirtualBox's default — vagrant's exact
	// layout is the provisioning contract). diskif has no modifyvm analog —
	// it selects the storage CONTROLLER type, consumed by attachStorage.
	zones := document.Section("zones")
	if autostart, ok := zones["autostart"].(bool); ok && autostart {
		flags = append(flags, "--autostart-enabled=on")
	}
	if v, ok := zones["bootrom"]; ok {
		firmware := "bios"
		if strings.Contains(strings.ToLower(stringOr(v, "")), "efi") {
			firmware = "efi"
		}
		flags = append(flags, "--firmware="+firmware)
	}
	if v, ok := zones["hostbridge"]; ok {
		chipset := strings.ToLower(stringOr(v, ""))
		if chipset == "i440fx" {
			chipset = "piix3"
		}
		if chipset != "" {
			flags = append(flags, "--chipset="+chipset)
		}
	}
	if v, ok := zones["vnc"]; ok {
		flags = append(flags, "--vrde="+onOff(v))
	}
	if v, ok := zones["acpi"]; ok {
		flags = append(flags, "--acpi="+onOff(v))
	}
	if v, ok := zones["xhci"]; ok {
		flags = append(flags, "--usb-xhci="+onOff(v))
	}
	nicType := vboxNICType(stringOr(zones["netif"], ""))

	// Document networks from adapter 2 — adapter 1 is the reserved NAT.
	for i, entry := range document.List("networks") {
		network := mapOr(entry)
		n := strconv.Itoa(i + 2)
		switch stringOr(network["type"], "external") {
		case "host":
			flags = append(flags, "--nic"+n+"=hostonly")
			if hostOnlyAdapter != "" {
				flags = append(flags, "--host-only-adapter"+n+"="+hostOnlyAdapter)
			}
		default:
			flags = append(flags, "--nic"+n+"=bridged")
			if bridge := stringOr(network["bridge"], ""); bridge != "" {
				flags = append(flags, "--bridge-adapter"+n+"="+bridge)
			}
		}
		// zones.netif's coarse type, unless the entry carries its own raw
		// nic_type (nicExtraFlags emits it with the other per-NIC knobs).
		if nicType != "" && stringOr(network["nic_type"], "") == "" {
			flags = append(flags, "--nic-type"+n+"="+nicType)
		}
		if mac := stringOr(network["mac"], ""); mac != "" && !strings.EqualFold(mac, "auto") {
			flags = append(flags, "--mac-address"+n+"="+strings.ReplaceAll(mac, ":", ""))
		}
		flags = append(flags, nicExtraFlags(network, n)...)
	}

	// The first-class hardware vocabulary (Mark's ALL-knobs ruling
	// 2026-07-09): hardware.<section>.<key> — emitted after the legacy
	// zones/settings flags so a hardware twin of the same knob wins.
	if hardware := document.Section("hardware"); len(hardware) > 0 {
		hwFlags, herr := hardwareFlags(hardware)
		if herr != nil {
			return nil, herr
		}
		flags = append(flags, hwFlags...)
	}

	// The vbox.directives passthrough: the document's own modifyvm attributes
	// — the user's final word, after everything.
	for _, entry := range listOr(document.Section("vbox")["directives"]) {
		directive := mapOr(entry)
		if name := stringOr(directive["directive"], ""); name != "" {
			flags = append(flags, "--"+name+"="+stringOr(directive["value"], ""))
		}
	}
	return flags, nil
}

// rolePortForwardFlags reads the document's roles[].port_forwards[] entries
// ({guest, host, ip?} — Hosts.rb:312-320's vocabulary) into --natpf1 rules.
// Malformed ports are a hard error: a forward the author asked for must
// never silently vanish.
func rolePortForwardFlags(roles []any) ([]string, error) {
	flags := []string{}
	for _, entry := range roles {
		role := mapOr(entry)
		roleName := stringOr(role["name"], "role")
		for _, raw := range listOr(role["port_forwards"]) {
			forward := mapOr(raw)
			if len(forward) == 0 {
				continue
			}
			guest := intOr(forward["guest"], 0)
			host := intOr(forward["host"], 0)
			if guest < 1 || guest > 65535 || host < 1 || host > 65535 {
				return nil, fmt.Errorf("role %s port_forwards entries need guest and host ports 1-65535 (got guest=%v host=%v)",
					roleName, forward["guest"], forward["host"])
			}
			hostIP := stringOr(forward["ip"], "")
			flags = append(flags, fmt.Sprintf("--natpf1=pf-%d-%d,tcp,%s,%d,,%d",
				host, guest, hostIP, host, guest))
		}
	}
	return flags, nil
}

// bootOrderFlags maps a boot_order list onto --boot1..4 (VirtualBox's four
// boot slots; values floppy|dvd|disk|net|none). Slots past the list clear to
// none; unknown values are dropped (the flags would 400 the whole modifyvm).
func bootOrderFlags(value any) []string {
	entries := listOr(value)
	if len(entries) == 0 {
		return nil
	}
	flags := []string{}
	slot := 1
	for _, entry := range entries {
		if slot > 4 {
			break
		}
		device := strings.ToLower(stringOr(entry, ""))
		switch device {
		case "floppy", "dvd", "disk", "net", "none":
			flags = append(flags, fmt.Sprintf("--boot%d=%s", slot, device))
			slot++
		}
	}
	if len(flags) == 0 {
		return nil
	}
	for ; slot <= 4; slot++ {
		flags = append(flags, fmt.Sprintf("--boot%d=none", slot))
	}
	return flags
}

// storageControllerKind maps the document's controller-type vocabulary onto
// storagectl --add types (yardstick 2: the controller type is the user's
// choice at create; VirtualBox fixes a controller's type once media attach).
// Default sata. The full storagectl bus set is exposed — Mark's rule: every
// option VirtualBox has.
func storageControllerKind(diskif string) string {
	switch strings.ToLower(diskif) {
	case "ide":
		return "ide"
	case "scsi":
		return "scsi"
	case "sas":
		return "sas"
	case "nvme", "pcie":
		return "pcie"
	case "virtio", "virtio-scsi", "virtio-blk":
		return "virtio"
	case "usb":
		return "usb"
	case "floppy":
		return "floppy"
	default:
		return "sata"
	}
}

// controllerPlan is one storage controller the create builds, with its
// next-free-port counter for entries that declare no port.
type controllerPlan struct {
	name     string
	kind     string
	ports    int
	bootable bool
	nextPort int
}

// storageControllers derives the create's controller set — the device model
// (Mark's Proxmox/VirtualBox correction 2026-07-07 + the multiple-adapters
// ask 2026-07-08): disks.controllers[] entries ({name?, type, ports?,
// bootable?}) each become a storagectl controller; media then address them by
// name. Absent, ONE default controller exists exactly as before — type from
// zones.diskif, the stable "SATA Controller" label modify addresses ports
// through (the name deliberately survives a non-SATA diskif for port-address
// stability).
func storageControllers(document MachineConfig) ([]*controllerPlan, error) {
	plans := []*controllerPlan{}
	seen := map[string]bool{}
	for _, entry := range listOr(document.Section("disks")["controllers"]) {
		c := mapOr(entry)
		if len(c) == 0 {
			continue
		}
		kind := storageControllerKind(stringOr(c["type"], ""))
		name := stringOr(c["name"], defaultControllerName(kind))
		if seen[name] {
			return nil, fmt.Errorf("disks.controllers: duplicate controller name %q", name)
		}
		seen[name] = true
		bootable := true
		if v, ok := c["bootable"].(bool); ok {
			bootable = v
		}
		plans = append(plans, &controllerPlan{
			name:     name,
			kind:     kind,
			ports:    int(intOr(c["ports"], 0)),
			bootable: bootable,
		})
	}
	if len(plans) == 0 {
		plans = append(plans, &controllerPlan{
			name:     sataController,
			kind:     storageControllerKind(stringOr(document.Section("zones")["diskif"], "")),
			bootable: true,
		})
	}
	return plans, nil
}

// defaultControllerName names an unnamed controller after its bus.
func defaultControllerName(kind string) string {
	switch kind {
	case "ide":
		return "IDE Controller"
	case "scsi":
		return "SCSI Controller"
	case "sas":
		return "SAS Controller"
	case "pcie":
		return "NVMe Controller"
	case "virtio":
		return "VirtIO Controller"
	case "usb":
		return "USB Controller"
	case "floppy":
		return "Floppy Controller"
	default:
		return sataController
	}
}

// resolveController picks an entry's controller: its own controller name when
// declared (must exist), else the first (default) controller.
func resolveController(plans []*controllerPlan, entry map[string]any) (*controllerPlan, error) {
	name := stringOr(entry["controller"], "")
	if name == "" {
		return plans[0], nil
	}
	for _, plan := range plans {
		if plan.name == name {
			return plan, nil
		}
	}
	return nil, fmt.Errorf("controller %q is not declared in disks.controllers", name)
}

// attachStorage wires the media over the controller set: boot at the default
// controller's port 0 (or its own controller/port/device), additional disks
// and cdroms at their declared controller/port/device or the controller's
// next free port.
func (e *executors) attachStorage(ctx context.Context, vboxExe, name string,
	document MachineConfig, output *createExecutionOutput, out *tasks.OutputWriter,
) error {
	plans, err := storageControllers(document)
	if err != nil {
		return err
	}
	for _, plan := range plans {
		if plan.kind != "sata" || plan.name != sataController || plan.ports > 0 {
			out.Write("stdout", fmt.Sprintf("Storage controller %q (%s)\n", plan.name, plan.kind))
		}
		if cerr := vbox.AddStorageController(ctx, vboxExe, name, plan.name, plan.kind, plan.ports, plan.bootable); cerr != nil {
			return cerr
		}
	}

	disks := document.Section("disks")
	// Diskless machines (the base's prepareBootVolume null) have no boot
	// medium — the controllers still exist so modify can attach media later.
	if output.BootdiskPath != "" {
		boot := mapOr(disks["boot"])
		plan, berr := resolveController(plans, boot)
		if berr != nil {
			return berr
		}
		port := int(intOr(boot["port"], 0))
		device := int(intOr(boot["device"], 0))
		if aerr := vbox.StorageAttach(ctx, vboxExe, name, plan.name, port, device, "hdd", output.BootdiskPath); aerr != nil {
			return aerr
		}
		if port >= plan.nextPort {
			plan.nextPort = port + 1
		}
	}

	for i, entry := range listOr(disks["additional_disks"]) {
		disk := mapOr(entry)
		if len(disk) == 0 {
			continue
		}
		diskName := stringOr(disk["volume_name"], fmt.Sprintf("disk%d", i+1))
		path := stringOr(disk["path"], "")
		if path == "" {
			path = filepath.Join(e.machineWorkdir(name), "disks", diskName+".vdi")
		}
		plan, perr := resolveController(plans, disk)
		if perr != nil {
			return perr
		}
		port := int(intOr(disk["port"], int64(plan.nextPort)))
		device := int(intOr(disk["device"], 0))
		out.Write("stdout", fmt.Sprintf("Attaching %s at %s port %d device %d\n", path, plan.name, port, device))
		if aerr := vbox.StorageAttach(ctx, vboxExe, name, plan.name, port, device, "hdd", path); aerr != nil {
			return aerr
		}
		if port >= plan.nextPort {
			plan.nextPort = port + 1
		}
	}

	for _, entry := range listOr(disks["cdroms"]) {
		cdrom := mapOr(entry)
		iso, rerr := e.resolveCdromPath(ctx, cdrom)
		if rerr != nil {
			return rerr
		}
		if iso == "" {
			continue
		}
		plan, perr := resolveController(plans, cdrom)
		if perr != nil {
			return perr
		}
		port := int(intOr(cdrom["port"], int64(plan.nextPort)))
		device := int(intOr(cdrom["device"], 0))
		out.Write("stdout", fmt.Sprintf("Attaching %s at %s port %d device %d\n", iso, plan.name, port, device))
		if aerr := vbox.StorageAttach(ctx, vboxExe, name, plan.name, port, device, "dvddrive", iso); aerr != nil {
			return aerr
		}
		if port >= plan.nextPort {
			plan.nextPort = port + 1
		}
	}
	return nil
}

// resolveCdromPath answers a cdroms[] entry's medium: path verbatim (raw
// paths stay legal), or iso — a cached-ISO filename resolved through the
// artifact registry (Mark's ruling 2026-07-09).
func (e *executors) resolveCdromPath(ctx context.Context, cdrom map[string]any) (string, error) {
	if path := stringOr(cdrom["path"], ""); path != "" {
		return path, nil
	}
	name := stringOr(cdrom["iso"], "")
	if name == "" {
		return "", nil
	}
	if e.env.Assets == nil {
		return "", errors.New("cdroms[].iso references the artifact registry — artifact_storage.enabled is false")
	}
	artifact, err := e.env.Assets.FindByKindFilename(ctx, assets.KindISO, name)
	if errors.Is(err, assets.ErrNotFound) {
		return "", fmt.Errorf("ISO %q is not in any storage location — upload or download it first (GET /artifacts/iso lists what exists)", name)
	}
	if err != nil {
		return "", err
	}
	return artifact.Path, nil
}

// clearStaleSettings removes a leftover machine settings file from a
// previous failed attempt: unregistervm (deliberately WITHOUT --delete —
// that would take the whole working directory with it) keeps the .vbox
// file, and createvm then refuses with "settings file already exists"
// (runtime-proven 2026-07-06). Only acts when VirtualBox no longer knows
// the machine.
func (e *executors) clearStaleSettings(ctx context.Context, vboxExe, name string, out *tasks.OutputWriter) {
	if _, err := vbox.ShowVMInfo(ctx, vboxExe, name); !errors.Is(err, vbox.ErrNotFound) {
		return
	}
	workdir := e.machineWorkdir(name)
	for _, file := range []string{name + ".vbox", name + ".vbox-prev"} {
		path := filepath.Join(workdir, file)
		if _, serr := os.Stat(path); serr != nil {
			continue
		}
		out.Write("stderr", "Removing stale settings file from a previous attempt: "+path+"\n")
		if rerr := os.Remove(path); rerr != nil {
			out.Write("stderr", "Stale settings removal failed: "+rerr.Error()+"\n")
		}
	}
}

// clearStaleMedium makes a create retry idempotent: a previous failed run
// can leave the target medium on disk AND registered as an orphan in
// VirtualBox's media registry (runtime-proven 2026-07-06 — clonemedium onto
// it would fail). Close+delete via VirtualBox first; fall back to removing
// the bare file when it was never registered.
func clearStaleMedium(ctx context.Context, vboxExe, path string, out *tasks.OutputWriter) {
	if _, err := os.Stat(path); err != nil {
		return
	}
	out.Write("stderr", "Removing stale medium from a previous attempt: "+path+"\n")
	if cerr := vbox.CloseMedium(ctx, vboxExe, path, true); cerr != nil {
		if rerr := os.Remove(path); rerr != nil {
			out.Write("stderr", "Stale medium removal failed (the clone will error): "+rerr.Error()+"\n")
		}
	}
}

// cancelCreateStorage is machine_create_storage's post-kill cleanup (D-F): a
// kill mid-clone can leave half-written media the in-memory rollback list
// never saw — close and delete every medium the child places under the
// machine's working directory.
func (e *executors) cancelCreateStorage(task *tasks.Task, out *tasks.OutputWriter) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	vboxExe := VBoxManagePath(ctx)
	if vboxExe == "" {
		return
	}
	workdir := e.machineWorkdir(task.MachineName)
	candidates := []string{}
	for _, ext := range []string{".vmdk", ".vdi", ".vhd"} {
		candidates = append(candidates, filepath.Join(workdir, "boot"+ext))
	}
	if entries, err := os.ReadDir(filepath.Join(workdir, "disks")); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				candidates = append(candidates, filepath.Join(workdir, "disks", entry.Name()))
			}
		}
	}
	out.Write("stderr", "Storage step cancelled — removing half-made media\n")
	for _, path := range candidates {
		if _, serr := os.Stat(path); serr != nil {
			continue
		}
		if cerr := vbox.CloseMedium(ctx, vboxExe, path, true); cerr != nil {
			// Never registered with VirtualBox: delete the file directly.
			if rerr := os.Remove(path); rerr != nil {
				out.Write("stderr", "Cleanup of "+path+" failed: "+rerr.Error()+"\n")
			}
		}
		// A half-made medium's sidecar stamp goes with it.
		removeMediumSidecar(path)
	}
}

// cancelCreateConfig is machine_create_config's post-kill cleanup: the
// half-configured machine is unregistered (the error path's rule applied to
// cancellation).
func (e *executors) cancelCreateConfig(task *tasks.Task, out *tasks.OutputWriter) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	vboxExe := VBoxManagePath(ctx)
	if vboxExe == "" {
		return
	}
	out.Write("stderr", "Config step cancelled — unregistering the half-made machine\n")
	if err := vbox.UnregisterVM(ctx, vboxExe, task.MachineName, false); err != nil {
		// A machine that never reached createvm has nothing to unregister.
		out.Write("stderr", "Unregister after cancel: "+err.Error()+"\n")
	}
	e.clearStaleSettings(ctx, vboxExe, task.MachineName, out)
}

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
		Name:     task.MachineName,
		Host:     hostname,
		Home:     e.machineWorkdir(task.MachineName),
		ServerID: serverID,
		Spec:     rawSpec,
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

// DocString coerces a document value to string (the handlers read the
// rendered document's box tuple through it).
func DocString(value any, fallback string) string {
	return stringOr(value, fallback)
}

// DocInt coerces a document value to int64 (the server's resource validation
// reads vcpus through it).
func DocInt(value any, fallback int64) int64 {
	return intOr(value, fallback)
}

// ConsolePortProblem validates a PRESENT settings.consoleport value against
// the VRDE TCP port range (converged, sync 2026-07-17 — both agents ship the
// identical refusal): the 0.1.31 package defaults consoleport to server_id,
// and an id above 65535 otherwise surfaces as a cryptic mid-chain modifyvm
// E_INVALIDARG. Numbers and numeric strings must be an integer in 1025-65535;
// anything else answers the refusal with the value verbatim. "" = valid.
// Absence is the caller's business — an absent consoleport is always fine.
func ConsolePortProblem(value any) string {
	refusal := func(text string) string {
		return "consoleport " + text + " is outside the valid console port range (1025-65535)"
	}
	inRange := func(n int64) bool { return n >= 1025 && n <= 65535 }
	switch v := value.(type) {
	case int:
		if !inRange(int64(v)) {
			return refusal(strconv.Itoa(v))
		}
	case int64:
		if !inRange(v) {
			return refusal(strconv.FormatInt(v, 10))
		}
	case uint64:
		if v > math.MaxInt64 || !inRange(int64(v)) {
			return refusal(strconv.FormatUint(v, 10))
		}
	case float64:
		if v != math.Trunc(v) || !inRange(int64(v)) {
			return refusal(strconv.FormatFloat(v, 'f', -1, 64))
		}
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil || !inRange(n) {
			return refusal(v)
		}
	default:
		return refusal(fmt.Sprint(value))
	}
	return ""
}

// VCPUProblem validates a PRESENT settings.vcpus value (converged, sync
// 2026-07-17 — zoneweaver's proposal, ACKED; both agents ship the identical
// refusal): a whole number >= 1. Integers pass; an INTEGRAL float like 2.0
// PASSES — it is whole, and the 0.1.31 template renders 2.0 from the
// wizard's integer 2 — while 2.5, zero, negatives, and non-numerics answer
// the refusal with the value verbatim. Numeric strings parse as floats
// (ParseInt alone would reject "2.0") and take the same whole-number test.
// "" = valid. Absence is the caller's business — an absent vcpus keeps the
// existing default-2 behavior byte-identical.
func VCPUProblem(value any) string {
	refusal := func(text string) string {
		return "vcpus " + text + " is not a valid vCPU count (whole number >= 1)"
	}
	wholeAtLeastOne := func(v float64) bool {
		return !math.IsNaN(v) && !math.IsInf(v, 0) && v == math.Trunc(v) && v >= 1
	}
	switch v := value.(type) {
	case int:
		if v < 1 {
			return refusal(strconv.Itoa(v))
		}
	case int64:
		if v < 1 {
			return refusal(strconv.FormatInt(v, 10))
		}
	case uint64:
		if v < 1 {
			return refusal(strconv.FormatUint(v, 10))
		}
	case float64:
		if !wholeAtLeastOne(v) {
			return refusal(strconv.FormatFloat(v, 'f', -1, 64))
		}
	case string:
		n, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil || !wholeAtLeastOne(n) {
			return refusal(v)
		}
	default:
		return refusal(fmt.Sprint(value))
	}
	return ""
}

// VCPUCount coerces a guard-passed vcpus value to its canonical INTEGER
// (converged v2, sync 2026-07-17 — apply-time normalization): the SAME
// float-tolerant parsing as VCPUProblem, the whole float truncating to int —
// so a value the guard passed NEVER falls back to the default at apply time
// (intOr's ParseInt would drop the string "4.0" to the fallback and silently
// apply the wrong count). Non-parseable answers fallback — the guard already
// refused those upstream.
func VCPUCount(value any, fallback int64) int64 {
	switch v := value.(type) {
	case int:
		return int64(v)
	case int64:
		return v
	case uint64:
		if v > math.MaxInt64 {
			return fallback
		}
		return int64(v)
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return fallback
		}
		return int64(v)
	case string:
		n, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
			return fallback
		}
		return int64(n)
	}
	return fallback
}

// MemoryToMB exposes the memory size parser (Hosts.rb's rules) for the
// server's resource validation.
func MemoryToMB(value any) int64 { return memoryToMB(value) }

// SizeToMB exposes the disk size parser (Hosts.rb's rules) for the server's
// resource validation.
func SizeToMB(value any) int64 { return sizeToMB(value) }

// Generic document-value coercions (the document is YAML/JSON-typed).
func stringOr(value any, fallback string) string {
	switch v := value.(type) {
	case string:
		if v != "" {
			return v
		}
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case uint64:
		return strconv.FormatUint(v, 10)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return fallback
}

func intOr(value any, fallback int64) int64 {
	switch v := value.(type) {
	case int:
		return int64(v)
	case int64:
		return v
	case uint64:
		if v > math.MaxInt64 {
			return fallback
		}
		return int64(v)
	case float64:
		return int64(v)
	case string:
		if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			return n
		}
	}
	return fallback
}

func mapOr(value any) map[string]any {
	if m, ok := value.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func listOr(value any) []any {
	if l, ok := value.([]any); ok {
		return l
	}
	return nil
}

// sizePattern extracts the numeric part of a size string ("48G", "512M").
var sizePattern = regexp.MustCompile(`(\d+(?:\.\d+)?)`)

// sizeToMB converts a disk-size value to megabytes (Hosts.rb's rule: G → ×
// 1024; M → as-is; bare numbers are gigabytes for disks).
func sizeToMB(value any) int64 {
	s := strings.TrimSpace(stringOr(value, ""))
	if s == "" {
		return 0
	}
	match := sizePattern.FindString(s)
	if match == "" {
		return 0
	}
	number, err := strconv.ParseFloat(match, 64)
	if err != nil {
		return 0
	}
	lower := strings.ToLower(s)
	if strings.Contains(lower, "m") {
		return int64(number)
	}
	return int64(number * 1024)
}

// memoryToMB converts the memory setting to megabytes (Hosts.rb: gb/g →
// × 1024, mb/m → as-is; bare numbers are megabytes).
func memoryToMB(value any) int64 {
	s := strings.TrimSpace(stringOr(value, ""))
	if s == "" {
		return 2048
	}
	match := sizePattern.FindString(s)
	if match == "" {
		return 2048
	}
	number, err := strconv.ParseFloat(match, 64)
	if err != nil {
		return 2048
	}
	lower := strings.ToLower(s)
	if strings.Contains(lower, "g") {
		return int64(number * 1024)
	}
	return int64(number)
}
