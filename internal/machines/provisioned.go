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

	"github.com/goccy/go-yaml"

	"github.com/Makr91/hyperweaver-agent/internal/prereqs"
	"github.com/Makr91/hyperweaver-agent/internal/provisioner"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vagrant"
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
// machines root (workdir containment), and the agent CA pair seeding each
// working copy's ssls tree.
type ProvisionEnv struct {
	Registry    *provisioner.Registry
	SecretsVars func() map[string]string
	MachinesDir string
	CACertPath  string
	CAKeyPath   string
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

	method, reason := effectiveSyncMethod(ctx, spec.SyncMethod)
	note := "Sync method: " + method
	if reason != "" {
		note += " — " + reason
	}
	out.Write("stdout", note+"\n")
	settings := make(map[string]any, len(spec.Settings)+1)
	maps.Copy(settings, spec.Settings)
	settings["sync_method"] = method

	out.Write("stdout", "Rendering Hosts.yml from "+spec.Provisioner.Name+"/"+spec.Provisioner.Version+"\n")
	hostsYML, err := provisioner.RenderHostsFile(&provisioner.GenerateInput{
		Version:            version,
		Settings:           settings,
		Networks:           spec.Networks,
		Roles:              spec.Roles,
		UserProperties:     spec.Properties,
		AdvancedProperties: spec.AdvancedProperties,
		SecretsVars:        e.env.SecretsVars(),
	})
	if err != nil {
		return err
	}

	out.Write("stdout", "Materializing working directory "+*machine.Home+"\n")
	return provisioner.Materialize(&provisioner.MaterializeInput{
		MachineDir: *machine.Home,
		Version:    version,
		HostsYML:   hostsYML,
		Roles:      spec.Roles,
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
		return uerr
	}

	e.taskProgress(task, 90, "recording_identity")
	e.recordIdentity(machine, out)
	e.taskProgress(task, 100, "completed")
	return nil
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
