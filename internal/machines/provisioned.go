package machines

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/Makr91/hyperweaver-agent/internal/assets"
	"github.com/Makr91/hyperweaver-agent/internal/prereqs"
	"github.com/Makr91/hyperweaver-agent/internal/provisioner"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vagrant"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// The provisioned-machine pipeline (architecture §8, D9/D10): machines
// created through a provisioner start via vagrant — render Hosts.yml,
// refresh the working copy, ensure the vagrant-scp-sync plugin, `vagrant up`
// — so the UNCHANGED Hosts.rb builds the VirtualBox configuration and runs
// the Ansible collections. VBoxManage remains the direct path for raw
// machines and for stop/suspend/delete power actions.

// scpSyncPlugin is the plugin SHI auto-installs before every start (the
// syncback mechanism Hosts.rb's folders: blocks use).
const scpSyncPlugin = "vagrant-scp-sync"

// Sync methods — SHI's per-machine Rsync/SCP setting. The effective value is
// injected into the template context (settings.sync_method / SYNC_METHOD),
// which is where SHI consumes it too (its generators seed SYNC_METHOD).
const (
	SyncRsync = "rsync"
	SyncSCP   = "scp"
)

// effectiveSyncMethod applies SHI's platform rules to the requested method:
// forced rsync on Windows, and macOS auto-falls back to SCP when the system
// rsync is the ancient Apple 2.x build (its broken chown handling is why SCP
// support exists at all). The stored spec keeps the user's preference; only
// the render sees the effective value. reason narrates a forced change ("").
func effectiveSyncMethod(ctx context.Context, requested string) (method, reason string) {
	if runtime.GOOS == "windows" {
		return SyncRsync, "forced on Windows (SHI rule)"
	}
	if requested == "" {
		requested = SyncRsync
	}
	if requested == SyncRsync && runtime.GOOS == "darwin" && ancientRsync(ctx) {
		return SyncSCP, "system rsync is the ancient Apple build — auto-fallback to SCP (SHI rule)"
	}
	return requested, ""
}

// ancientRsync reports a system rsync older than major version 3 (or none at
// all — SCP is then the only working path).
func ancientRsync(ctx context.Context) bool {
	for _, tool := range prereqs.Detect(ctx) {
		if tool.Name != "rsync" {
			continue
		}
		if !tool.Installed || tool.Version == "" {
			return true
		}
		major, err := strconv.Atoi(strings.SplitN(tool.Version, ".", 2)[0])
		return err == nil && major < 3
	}
	return true
}

// ProvisionerRef names the package version a machine builds from.
type ProvisionerRef struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Spec is the machine-create request document (the Hosts.yml-shaped
// structure of design §4), stored verbatim on the machine row.
type Spec struct {
	Provisioner        ProvisionerRef          `json:"provisioner"`
	Settings           map[string]any          `json:"settings"`
	Networks           []any                   `json:"networks"`
	Roles              []provisioner.RoleInput `json:"roles"`
	Properties         map[string]any          `json:"properties"`
	AdvancedProperties map[string]any          `json:"advanced_properties"`
	SyncMethod         string                  `json:"sync_method"`
	SafeIDPath         string                  `json:"safe_id_path"`
	StartAfterCreate   bool                    `json:"start_after_create"`
}

// ParseSpec reads a machine row's stored spec.
func ParseSpec(machine *Machine) (*Spec, error) {
	if len(machine.Spec) == 0 {
		return nil, errors.New("machine has no creation spec")
	}
	var spec Spec
	if err := json.Unmarshal(machine.Spec, &spec); err != nil {
		return nil, fmt.Errorf("parse machine spec: %w", err)
	}
	return &spec, nil
}

// ProvisionEnv wires the provisioning pipeline's dependencies into the
// executors: the package registry, the secrets-derived template vars, the
// machines root (workdir containment), the file cache (nil when
// assets.enabled is off), and the agent CA pair seeding each working copy's
// ssls tree.
type ProvisionEnv struct {
	Registry    *provisioner.Registry
	SecretsVars func() map[string]string
	MachinesDir string
	Assets      *assets.Store
	CACertPath  string
	CAKeyPath   string
	// KeepFailedRunning leaves a machine running after a failed vagrant up
	// (SHI's keepfailedserversrunning); false powers the half-up VM off.
	KeepFailedRunning bool
	// DefaultSyncMethod fills specs without an explicit sync_method (SHI's
	// global syncmethod preference); platform rules still apply on top.
	DefaultSyncMethod string
	// DefaultNetworkInterface reaches the template context as
	// settings.default_network_interface / DEFAULT_NETWORK_INTERFACE when
	// the spec sets none (SHI's bridge-interface fallback).
	DefaultNetworkInterface string
}

// resolveInstallerFiles verifies every role file reference against the file
// cache (Mark's ruling 2026-07-06: hash verification is the point — a file
// that is absent, unhashed, or mismatching NEVER reaches a machine) and
// returns the verified mounts plus a hash-enriched copy of the roles for the
// template context. With the assets subsystem disabled, references pass
// through un-mounted with a loud warning.
func (e *executors) resolveInstallerFiles(ctx context.Context, spec *Spec, out *tasks.OutputWriter) ([]provisioner.InstallerFile, []provisioner.RoleInput, error) {
	roles := make([]provisioner.RoleInput, len(spec.Roles))
	copy(roles, spec.Roles)

	if e.env.Assets == nil {
		for i := range roles {
			if roles[i].Files != (provisioner.RoleFiles{}) {
				out.Write("stderr", "WARNING: assets.enabled is false — installer files are NOT mounted or hash-verified\n")
				break
			}
		}
		return nil, roles, nil
	}

	mounts := []provisioner.InstallerFile{}
	for i := range roles {
		role := &roles[i]
		references := []struct {
			kind    string
			name    *string
			hash    *string
			version *string
		}{
			{assets.KindInstaller, &role.Files.Installer, &role.Files.InstallerHash, &role.Files.InstallerVersion},
			{assets.KindFixpack, &role.Files.Fixpack, &role.Files.FixpackHash, &role.Files.FixpackVersion},
			{assets.KindHotfix, &role.Files.Hotfix, &role.Files.HotfixHash, &role.Files.HotfixVersion},
		}
		for _, ref := range references {
			if *ref.name == "" {
				continue
			}
			artifact, err := e.env.Assets.Find(ctx, role.Name, ref.kind, *ref.name)
			if errors.Is(err, assets.ErrNotFound) {
				return nil, nil, fmt.Errorf("%s %q for role %s is not in the file cache — upload, register, or download it first",
					ref.kind, *ref.name, role.Name)
			}
			if err != nil {
				return nil, nil, err
			}
			if !artifact.Exists {
				return nil, nil, fmt.Errorf("%s %q for role %s is an expectation only — the file itself is not in the cache",
					ref.kind, *ref.name, role.Name)
			}
			if !artifact.Verified() {
				return nil, nil, fmt.Errorf("%s %q for role %s FAILS hash verification: file %s, expected %s",
					ref.kind, *ref.name, role.Name, artifact.SHA256, artifact.ExpectedSHA256)
			}
			if *ref.hash != "" && !strings.EqualFold(*ref.hash, artifact.SHA256) {
				return nil, nil, fmt.Errorf("%s %q for role %s: the spec expects hash %s but the cached file is %s",
					ref.kind, *ref.name, role.Name, *ref.hash, artifact.SHA256)
			}
			*ref.hash = artifact.SHA256
			if *ref.version == "" {
				*ref.version = artifact.Version
			}
			mounts = append(mounts, provisioner.InstallerFile{
				SourcePath: artifact.Path,
				Role:       role.Name,
				Subdir:     assets.WorkdirSubdir(ref.kind),
				Filename:   *ref.name,
				SHA256:     artifact.SHA256,
			})
			out.Write("stdout", "Verified "+ref.kind+" "+*ref.name+" ("+artifact.SHA256+")\n")
		}
	}
	return mounts, roles, nil
}

// taskProgress records a task's own progress (zoneweaver's
// lib/TaskProgressHelper.updateTaskProgress: percent + {status} info, failures
// logged and swallowed — progress never fails an operation). Bookkeeping uses
// a background context so a cancelled task still records its last state.
func (e *executors) taskProgress(task *tasks.Task, percent float64, status string) {
	if task == nil {
		return
	}
	info, err := json.Marshal(map[string]string{"status": status})
	if err != nil {
		return
	}
	if uerr := e.queue.Store().UpdateProgress(context.Background(), task.ID, percent, info); uerr != nil {
		mlog().Debug("progress update failed", "task_id", task.ID, "error", uerr)
	}
}

// prepareWorkdir renders Hosts.yml and refreshes the machine's working
// directory — the pre-up half of SHI's start flow. The effective sync method
// (platform rules applied) is injected into the render context; the stored
// spec keeps the user's preference.
func (e *executors) prepareWorkdir(ctx context.Context, machine *Machine, spec *Spec, out *tasks.OutputWriter) error {
	version, err := e.env.Registry.GetVersion(spec.Provisioner.Name, spec.Provisioner.Version)
	if err != nil {
		return fmt.Errorf("provisioner %s/%s: %w", spec.Provisioner.Name, spec.Provisioner.Version, err)
	}

	requested := spec.SyncMethod
	if requested == "" {
		requested = e.env.DefaultSyncMethod
	}
	method, reason := effectiveSyncMethod(ctx, requested)
	note := "Sync method: " + method
	if reason != "" {
		note += " — " + reason
	}
	out.Write("stdout", note+"\n")
	settings := make(map[string]any, len(spec.Settings)+2)
	maps.Copy(settings, spec.Settings)
	settings["sync_method"] = method
	if _, present := settings["default_network_interface"]; !present && e.env.DefaultNetworkInterface != "" {
		settings["default_network_interface"] = e.env.DefaultNetworkInterface
	}

	// Every referenced installer file must verify against the cache BEFORE
	// anything renders — the roles the template sees carry the verified
	// hashes.
	mounts, roles, err := e.resolveInstallerFiles(ctx, spec, out)
	if err != nil {
		return err
	}

	out.Write("stdout", "Rendering Hosts.yml from "+spec.Provisioner.Name+"/"+spec.Provisioner.Version+"\n")
	hostsYML, err := provisioner.RenderHostsFile(&provisioner.GenerateInput{
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
	if markers := provisioner.LegacyMarkers(hostsYML); len(markers) > 0 {
		out.Write("stderr", "WARNING: rendered Hosts.yml still contains haxe.Template markers ("+
			strings.Join(markers, ", ")+") — this package's template was never converted to Jinja2 "+
			"(the one-time conversion Mark's D-B ruling requires); the guest will receive them as literal text\n")
	}

	out.Write("stdout", "Materializing working directory "+*machine.Home+"\n")
	return provisioner.Materialize(&provisioner.MaterializeInput{
		MachineDir: *machine.Home,
		Version:    version,
		HostsYML:   hostsYML,
		Roles:      roles,
		Installers: mounts,
		SafeIDPath: spec.SafeIDPath,
		CACertPath: e.env.CACertPath,
		CAKeyPath:  e.env.CAKeyPath,
	})
}

// The provisioned start runs as zoneweaver's orchestration shape (its zone
// creation pipeline: a parent anchor whose chained children ARE the coarse
// progress): machine_prepare → machine_plugin_check → machine_vagrant_up,
// each reporting its own {status} progress like zoneweaver's sub-task
// executors. Bulk starts arrive as one plain start task instead and run the
// same steps inline (zoneweaver's bulk controller skips orchestration too).

// prepare executes machine_prepare: render Hosts.yml + refresh the working
// copy.
func (e *executors) prepare(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	machine, err := e.provisionedMachine(ctx, task.MachineName)
	if err != nil {
		return err
	}
	e.taskProgress(task, 10, "rendering_hosts_yml")
	spec, err := ParseSpec(machine)
	if err != nil {
		return err
	}
	if perr := e.prepareWorkdir(ctx, machine, spec, out); perr != nil {
		return perr
	}
	e.taskProgress(task, 100, "completed")
	return nil
}

// pluginCheck executes machine_plugin_check: ensure vagrant-scp-sync (a
// visible step, SHI behavior).
func (e *executors) pluginCheck(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	vagrantExe := VagrantPath(ctx)
	if vagrantExe == "" {
		return errors.New("vagrant is not installed")
	}
	e.taskProgress(task, 10, "checking_plugin")
	out.Write("stdout", "Checking "+scpSyncPlugin+" plugin\n")
	installed, err := vagrant.PluginInstalled(ctx, vagrantExe, scpSyncPlugin)
	if err != nil {
		return err
	}
	if !installed {
		e.taskProgress(task, 40, "installing_plugin")
		out.Write("stdout", "Installing "+scpSyncPlugin+"\n")
		if ierr := vagrant.PluginInstall(ctx, vagrantExe, scpSyncPlugin, out.Write); ierr != nil {
			return ierr
		}
	}
	e.taskProgress(task, 100, "completed")
	return nil
}

// vagrantUp executes machine_vagrant_up: `vagrant up`, then record the VM
// identity vagrant produced.
func (e *executors) vagrantUp(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	machine, err := e.provisionedMachine(ctx, task.MachineName)
	if err != nil {
		return err
	}
	if exe := VBoxManagePath(ctx); exe != "" {
		defer e.refreshStatus(machine.Name, exe)
	}
	vagrantExe := VagrantPath(ctx)
	if vagrantExe == "" {
		return errors.New("vagrant is not installed")
	}

	e.taskProgress(task, 5, "running_vagrant_up")
	out.Write("stdout", "Running vagrant up in "+*machine.Home+"\n")
	if uerr := vagrant.Up(ctx, vagrantExe, *machine.Home, true, out.Write); uerr != nil {
		e.handleFailedUp(machine, out)
		return uerr
	}

	e.taskProgress(task, 90, "recording_identity")
	e.recordIdentity(machine, out)
	e.taskProgress(task, 100, "completed")
	return nil
}

// handleFailedUp applies SHI's keepfailedserversrunning rule after a failed
// vagrant up: by default the half-provisioned VM stays running for
// debugging; with the setting off it is powered off (the fresh UUID comes
// from the working directory's vagrant state — the failed up may have just
// created it).
func (e *executors) handleFailedUp(machine *Machine, out *tasks.OutputWriter) {
	if e.env.KeepFailedRunning {
		out.Write("stderr", "vagrant up failed — machine left as-is for debugging (provisioning.keep_failed_machines_running)\n")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	exe := VBoxManagePath(ctx)
	if exe == "" {
		return
	}
	target := machine.VBoxTarget()
	if uuid := vagrantMachineUUID(*machine.Home); uuid != "" {
		target = uuid
	}
	out.Write("stderr", "vagrant up failed — powering the machine off (provisioning.keep_failed_machines_running: false)\n")
	if perr := vbox.ControlVM(ctx, exe, target, "poweroff"); perr != nil {
		out.Write("stderr", "Power off after failed up: "+perr.Error()+"\n")
	}
}

// recordIdentity ties the VM vagrant built to the registry row: the
// VirtualBox name is Hosts.rb's own, so the UUID from the working
// directory's vagrant state is the join key (discovery matches on it from
// now on). The welcome page is narrated when the provision already wrote it.
func (e *executors) recordIdentity(machine *Machine, out *tasks.OutputWriter) {
	if uuid := vagrantMachineUUID(*machine.Home); uuid != "" {
		if serr := e.store.SetUUID(context.Background(), machine.Name, uuid); serr != nil {
			mlog().Error("record machine uuid", "machine", machine.Name, "error", serr)
		} else {
			out.Write("stdout", "Machine registered in VirtualBox as "+uuid+"\n")
		}
	}
	if url := WelcomeURL(*machine.Home); url != "" {
		out.Write("stdout", "Welcome page: "+url+"\n")
	}
}

// startProvisioned runs the whole pipeline inline — the bulk-start path,
// where each machine is one plain start task.
func (e *executors) startProvisioned(ctx context.Context, task *tasks.Task, machine *Machine, out *tasks.OutputWriter) error {
	spec, err := ParseSpec(machine)
	if err != nil {
		return err
	}
	vagrantExe := VagrantPath(ctx)
	if vagrantExe == "" {
		return errors.New("vagrant is not installed")
	}

	e.taskProgress(task, 5, "rendering_hosts_yml")
	if perr := e.prepareWorkdir(ctx, machine, spec, out); perr != nil {
		return perr
	}

	e.taskProgress(task, 30, "checking_plugin")
	if perr := e.pluginCheck(ctx, nil, out); perr != nil {
		return perr
	}

	e.taskProgress(task, 40, "running_vagrant_up")
	out.Write("stdout", "Running vagrant up in "+*machine.Home+"\n")
	if uerr := vagrant.Up(ctx, vagrantExe, *machine.Home, true, out.Write); uerr != nil {
		e.handleFailedUp(machine, out)
		return uerr
	}

	e.taskProgress(task, 90, "recording_identity")
	e.recordIdentity(machine, out)
	return nil
}

// provisionedMachine loads a machine and requires it to be
// provisioner-managed.
func (e *executors) provisionedMachine(ctx context.Context, name string) (*Machine, error) {
	machine, err := e.store.Get(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("machine %s: %w", name, err)
	}
	if !machine.Provisioned() {
		return nil, errors.New("machine " + name + " is not provisioner-managed")
	}
	return machine, nil
}

// runVagrantOp is the shared shape of the provision and sync operations:
// vagrant-backed machines only, working directory required.
func (e *executors) runVagrantOp(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter,
	verb string, run func(ctx context.Context, exe, dir string, stream vagrant.StreamFunc) error,
) error {
	machine, err := e.store.Get(ctx, task.MachineName)
	if err != nil {
		return fmt.Errorf("machine %s: %w", task.MachineName, err)
	}
	if !machine.Provisioned() {
		return errors.New("machine " + machine.Name + " is not provisioner-managed — nothing to " + verb)
	}
	vagrantExe := VagrantPath(ctx)
	if vagrantExe == "" {
		return errors.New("vagrant is not installed")
	}

	// provision re-renders first so configuration edits reach the guest —
	// SHI regenerates Hosts.yml before every provisioning pass.
	if verb == "provision" {
		spec, serr := ParseSpec(machine)
		if serr != nil {
			return serr
		}
		e.taskProgress(task, 10, "rendering_hosts_yml")
		if perr := e.prepareWorkdir(ctx, machine, spec, out); perr != nil {
			return perr
		}
		e.taskProgress(task, 25, "running_vagrant_provision")
	}

	out.Write("stdout", "Running vagrant "+verb+" in "+*machine.Home+"\n")
	if rerr := run(ctx, vagrantExe, *machine.Home, out.Write); rerr != nil {
		return rerr
	}
	out.Write("stdout", "vagrant "+verb+" completed\n")
	return nil
}

// vagrantMachineUUID reads the VirtualBox UUID from the working directory's
// vagrant state (.vagrant/machines/<name>/virtualbox/id).
func vagrantMachineUUID(home string) string {
	machinesDir := filepath.Join(home, ".vagrant", "machines")
	entries, err := os.ReadDir(machinesDir)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		raw, rerr := os.ReadFile(filepath.Clean(filepath.Join(machinesDir, entry.Name(), "virtualbox", "id")))
		if rerr != nil {
			continue
		}
		if uuid := strings.TrimSpace(string(raw)); uuid != "" {
			return uuid
		}
	}
	return ""
}

// WelcomeURL returns the machine's post-provision web address (the machine
// detail payload's web_address): results.yml's open_url, falling back to
// .vagrant/done.txt — the SHI 0.1.23+ mechanism Hosts.rb writes.
func WelcomeURL(home string) string {
	raw, err := os.ReadFile(filepath.Clean(filepath.Join(home, "results.yml")))
	if err == nil {
		var results struct {
			OpenURL string `yaml:"open_url"`
		}
		if uerr := yaml.Unmarshal(raw, &results); uerr == nil && results.OpenURL != "" {
			return strings.TrimSpace(results.OpenURL)
		}
	}
	raw, err = os.ReadFile(filepath.Clean(filepath.Join(home, ".vagrant", "done.txt")))
	if err == nil {
		if line := strings.TrimSpace(strings.SplitN(string(raw), "\n", 2)[0]); line != "" {
			return line
		}
	}
	return ""
}

// StopAllProvisioned force-powers-off every spec-carrying machine — SHI's
// keepserversrunning:false on-quit behavior (direct commands, no task queue:
// the agent is exiting). Machines merely discovered from VirtualBox are the
// user's own and are never touched.
func StopAllProvisioned(ctx context.Context, store *Store) {
	exe := VBoxManagePath(ctx)
	if exe == "" {
		return
	}
	list, err := store.List(ctx, &ListFilter{})
	if err != nil {
		mlog().Error("stop-on-exit: list machines", "error", err)
		return
	}
	for _, machine := range list {
		if !machine.Provisioned() || machine.UUID == nil {
			continue
		}
		info, ierr := vbox.ShowVMInfo(ctx, exe, machine.VBoxTarget())
		if ierr != nil || MapVBoxState(info.State) != StatusRunning {
			continue
		}
		mlog().Info("stop-on-exit: powering off machine", "machine", machine.Name)
		if perr := vbox.ControlVM(ctx, exe, machine.VBoxTarget(), "poweroff"); perr != nil {
			mlog().Error("stop-on-exit: poweroff failed", "machine", machine.Name, "error", perr)
		}
	}
}

// removeWorkdir deletes a provisioned machine's working directory — ONLY
// when it is one of ours: a spec-carrying machine whose home sits under the
// configured machines root. A DISCOVERED vagrant machine's home is the
// user's own project and is never touched.
func (e *executors) removeWorkdir(machine *Machine, out *tasks.OutputWriter) {
	if !machine.Provisioned() || e.env.MachinesDir == "" {
		return
	}
	home := *machine.Home
	contained, err := safepath.Under(e.env.MachinesDir, filepath.Base(home))
	if err != nil || !strings.EqualFold(contained, home) {
		out.Write("stderr", "Working directory "+home+" is outside the machines root — left in place\n")
		return
	}
	out.Write("stdout", "Removing working directory "+home+"\n")
	if rerr := provisioner.RemoveTree(home); rerr != nil {
		out.Write("stderr", "Working directory removal failed: "+rerr.Error()+"\n")
	}
}
