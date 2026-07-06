package machines

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/Makr91/hyperweaver-agent/internal/provisioner"
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
	// Document is the rendered hosts[0] — settings/networks/disks/zones plus
	// the provisioner sections (folders/provisioning/vars/roles).
	Document map[string]any `json:"document"`
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
// ssls, hash-verified installer mounts), parse hosts[0], and pass the
// document forward.
func (e *executors) prepareDocument(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	meta, err := readCreateMetadata(task)
	if err != nil {
		return err
	}
	spec := meta.Spec
	e.taskProgress(task, 10, "rendering_document")

	version, err := e.env.Registry.GetVersion(spec.Provisioner.Name, spec.Provisioner.Version)
	if err != nil {
		return fmt.Errorf("provisioner %s/%s: %w", spec.Provisioner.Name, spec.Provisioner.Version, err)
	}

	settings := effectiveSettings(ctx, e.env, spec)
	mounts, roles, err := e.resolveInstallerFiles(ctx, spec, out)
	if err != nil {
		return err
	}
	rendered, err := provisioner.RenderHostsFile(&provisioner.GenerateInput{
		Version:            version,
		Settings:           settings,
		Networks:           spec.Networks,
		Roles:              roles,
		UserProperties:     spec.Properties,
		AdvancedProperties: spec.AdvancedProperties,
		SecretsVars:        e.env.SecretsVars(),
	})
	if err != nil {
		return err
	}
	if markers := provisioner.LegacyMarkers(rendered); len(markers) > 0 {
		out.Write("stderr", "WARNING: rendered document still contains ::TOKEN:: markers ("+
			strings.Join(markers, ", ")+") — the package template was never converted to Jinja2\n")
	}

	document, err := parseHostsDocument(rendered)
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

// ParseHostsDocument extracts hosts[0] from a rendered Hosts.yml.
func ParseHostsDocument(rendered []byte) (map[string]any, error) {
	return parseHostsDocument(rendered)
}

// parseHostsDocument extracts hosts[0] from a rendered Hosts.yml.
func parseHostsDocument(rendered []byte) (map[string]any, error) {
	var parsed struct {
		Hosts []map[string]any `yaml:"hosts"`
	}
	if err := yaml.Unmarshal(rendered, &parsed); err != nil {
		return nil, fmt.Errorf("parse rendered document: %w", err)
	}
	if len(parsed.Hosts) == 0 {
		return nil, errors.New("rendered document carries no hosts[] entry")
	}
	return parsed.Hosts[0], nil
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
	output, err := e.dependencyOutput(ctx, task)
	if err != nil {
		return err
	}
	document := MachineConfig(output.Document)
	settings := document.Section("settings")
	disks := document.Section("disks")

	vboxExe := VBoxManagePath(ctx)
	if vboxExe == "" {
		return errors.New("VirtualBox is not installed")
	}

	e.taskProgress(task, 10, "preparing_storage")
	org, box, ok := strings.Cut(stringOr(settings["box"], ""), "/")
	if !ok || org == "" || box == "" {
		return errors.New(`settings.box must be "organization/box-name"`)
	}
	template, err := e.store.FindTemplate(ctx, org, box,
		stringOr(settings["box_version"], "latest"), stringOr(settings["box_arch"], "amd64"))
	if err != nil {
		return fmt.Errorf("template %s/%s: %w (download it first — POST /templates/pull or let create chain it)", org, box, err)
	}

	workdir := e.machineWorkdir(task.MachineName)
	media := []string{}
	rollback := func() {
		for i := len(media) - 1; i >= 0; i-- {
			if cerr := vbox.CloseMedium(context.Background(), vboxExe, media[i], true); cerr != nil {
				out.Write("stderr", "Rollback of "+media[i]+" failed: "+cerr.Error()+"\n")
			}
		}
	}

	e.taskProgress(task, 30, "importing_template")
	bootPath := filepath.Join(workdir, "boot"+filepath.Ext(template.DiskPath))
	out.Write("stdout", "Cloning template "+template.DiskPath+" → "+bootPath+"\n")
	if cerr := vbox.CloneMedium(ctx, vboxExe, template.DiskPath, bootPath, ""); cerr != nil {
		rollback()
		return cerr
	}
	media = append(media, bootPath)

	boot := mapOr(disks["boot"])
	if sizeMB := sizeToMB(boot["size"]); sizeMB > 0 {
		if rerr := vbox.ResizeMedium(ctx, vboxExe, bootPath, sizeMB); rerr != nil {
			out.Write("stderr", "Boot volume resize failed (continuing with template size): "+rerr.Error()+"\n")
		}
	}

	e.taskProgress(task, 60, "creating_additional_disks")
	disksDir := filepath.Join(workdir, "disks")
	for i, entry := range listOr(disks["additional_disks"]) {
		disk := mapOr(entry)
		if len(disk) == 0 {
			continue
		}
		name := stringOr(disk["volume_name"], fmt.Sprintf("disk%d", i+1))
		sizeMB := sizeToMB(disk["size"])
		if sizeMB <= 0 {
			continue
		}
		if merr := os.MkdirAll(disksDir, 0o750); merr != nil {
			rollback()
			return merr
		}
		diskPath := filepath.Join(disksDir, name+".vdi")
		sparse := true
		if v, bok := disk["sparse"].(bool); bok {
			sparse = v
		}
		out.Write("stdout", fmt.Sprintf("Creating %s (%d MB)\n", diskPath, sizeMB))
		if cerr := vbox.CreateMedium(ctx, vboxExe, diskPath, sizeMB, sparse); cerr != nil {
			rollback()
			return cerr
		}
		media = append(media, diskPath)
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
	document := MachineConfig(output.Document)
	settings := document.Section("settings")

	vboxExe := VBoxManagePath(ctx)
	if vboxExe == "" {
		return errors.New("VirtualBox is not installed")
	}

	e.taskProgress(task, 20, "creating_vm")
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
		if uerr := vbox.UnregisterVM(context.Background(), vboxExe, task.MachineName, false); uerr != nil {
			out.Write("stderr", "Unregister failed: "+uerr.Error()+"\n")
		}
		return ferr
	}

	e.taskProgress(task, 40, "configuring_vm")
	if merr := vbox.ModifyVM(ctx, vboxExe, task.MachineName, modifyFlags(document)); merr != nil {
		return failed("modifyvm", merr)
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

// modifyFlags assembles the modifyvm set FROM THE DOCUMENT — zoneweaver's
// model: core config + the document-driven attribute map, nothing hardcoded.
// settings drive resources/console/firmware, networks[] drive the adapters
// (1:1 from adapter 1 — no vagrant, no reserved NAT NIC), and
// vbox.directives is the generic passthrough (the zonecfg attr-map analog).
func modifyFlags(document MachineConfig) []string {
	settings := document.Section("settings")
	flags := []string{
		"--cpus=" + strconv.FormatInt(intOr(settings["vcpus"], 2), 10),
		"--memory=" + strconv.FormatInt(memoryToMB(settings["memory"]), 10),
	}
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
	if autostart, ok := document.Section("zones")["autostart"].(bool); ok && autostart {
		flags = append(flags, "--autostart-enabled=on")
	}

	// Adapters map 1:1 from networks[] — the agent SSHes to the control IP
	// directly (zoneweaver's model), so no adapter is reserved for NAT.
	for i, entry := range document.List("networks") {
		network := mapOr(entry)
		n := strconv.Itoa(i + 1)
		switch stringOr(network["type"], "external") {
		case "host":
			flags = append(flags, "--nic"+n+"=hostonly")
		default:
			flags = append(flags, "--nic"+n+"=bridged")
			if bridge := stringOr(network["bridge"], ""); bridge != "" {
				flags = append(flags, "--bridge-adapter"+n+"="+bridge)
			}
		}
		if mac := stringOr(network["mac"], ""); mac != "" && !strings.EqualFold(mac, "auto") {
			flags = append(flags, "--mac-address"+n+"="+strings.ReplaceAll(mac, ":", ""))
		}
	}

	// The vbox.directives passthrough: the document's own modifyvm attributes.
	for _, entry := range listOr(document.Section("vbox")["directives"]) {
		directive := mapOr(entry)
		if name := stringOr(directive["directive"], ""); name != "" {
			flags = append(flags, "--"+name+"="+stringOr(directive["value"], ""))
		}
	}
	return flags
}

// attachStorage wires the media: one SATA controller, boot at port 0,
// additional disks at their declared ports, cdroms as dvddrives after.
func (e *executors) attachStorage(ctx context.Context, vboxExe, name string,
	document MachineConfig, output *createExecutionOutput, out *tasks.OutputWriter,
) error {
	const controller = "SATA Controller"
	if err := vbox.AddStorageController(ctx, vboxExe, name, controller, "sata"); err != nil {
		return err
	}
	if err := vbox.StorageAttach(ctx, vboxExe, name, controller, 0, "hdd", output.BootdiskPath); err != nil {
		return err
	}

	disks := document.Section("disks")
	nextPort := 1
	for i, entry := range listOr(disks["additional_disks"]) {
		disk := mapOr(entry)
		if len(disk) == 0 {
			continue
		}
		diskName := stringOr(disk["volume_name"], fmt.Sprintf("disk%d", i+1))
		path := filepath.Join(e.machineWorkdir(name), "disks", diskName+".vdi")
		port := int(intOr(disk["port"], int64(nextPort)))
		out.Write("stdout", fmt.Sprintf("Attaching %s at port %d\n", path, port))
		if err := vbox.StorageAttach(ctx, vboxExe, name, controller, port, "hdd", path); err != nil {
			return err
		}
		nextPort = port + 1
	}

	for _, entry := range listOr(disks["cdroms"]) {
		cdrom := mapOr(entry)
		iso := stringOr(cdrom["path"], "")
		if iso == "" {
			continue
		}
		if err := vbox.StorageAttach(ctx, vboxExe, name, controller, nextPort, "dvddrive", iso); err != nil {
			return err
		}
		nextPort++
	}
	return nil
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
	document := MachineConfig(output.Document)

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
	sections := map[string]any{}
	for _, key := range []string{"settings", "zones", "networks", "disks", "metadata"} {
		if value, ok := document[key]; ok {
			sections[key] = value
		}
	}
	// The rendered document's provisioning half IS the provisioner document
	// (folders/provisioning/vars/roles) — stored exactly where PUT stores it;
	// a later PUT overrides it verbatim.
	provisionerDoc := map[string]any{
		"provisioner_name":    meta.Spec.Provisioner.Name,
		"provisioner_version": meta.Spec.Provisioner.Version,
	}
	for _, key := range []string{"folders", "provisioning", "vars", "roles", "pre_tasks", "post_tasks"} {
		if value, ok := document[key]; ok {
			provisionerDoc[key] = value
		}
	}
	sections["provisioner"] = provisionerDoc
	if merr := e.store.MergeConfigurationSections(ctx, task.MachineName, sections); merr != nil {
		return merr
	}

	if output.UUID != "" {
		if uerr := e.store.SetUUID(ctx, task.MachineName, output.UUID); uerr != nil {
			return uerr
		}
	}
	e.taskProgress(task, 100, "completed")
	out.Write("stdout", "Machine "+task.MachineName+" finalized\n")
	return nil
}

// DocString coerces a document value to string (the handlers read the
// rendered document's box tuple through it).
func DocString(value any, fallback string) string {
	return stringOr(value, fallback)
}

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
