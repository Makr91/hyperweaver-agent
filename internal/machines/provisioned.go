package machines

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/goccy/go-yaml"

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

// prepareWorkdir renders Hosts.yml and refreshes the machine's working
// directory — the pre-up half of SHI's start flow.
func (e *executors) prepareWorkdir(machine *Machine, spec *Spec, out *tasks.OutputWriter) error {
	version, err := e.env.Registry.GetVersion(spec.Provisioner.Name, spec.Provisioner.Version)
	if err != nil {
		return fmt.Errorf("provisioner %s/%s: %w", spec.Provisioner.Name, spec.Provisioner.Version, err)
	}

	out.Write("stdout", "Rendering Hosts.yml from "+spec.Provisioner.Name+"/"+spec.Provisioner.Version+"\n")
	hostsYML, err := provisioner.RenderHostsFile(&provisioner.GenerateInput{
		Version:            version,
		Settings:           spec.Settings,
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

// startProvisioned is the provisioned start: prepare the working copy,
// ensure the scp-sync plugin (a visible step, SHI behavior), vagrant up,
// then record the UUID the VM landed under.
func (e *executors) startProvisioned(ctx context.Context, machine *Machine, out *tasks.OutputWriter) error {
	spec, err := ParseSpec(machine)
	if err != nil {
		return err
	}
	vagrantExe := VagrantPath(ctx)
	if vagrantExe == "" {
		return errors.New("vagrant is not installed")
	}

	if perr := e.prepareWorkdir(machine, spec, out); perr != nil {
		return perr
	}

	out.Write("stdout", "Checking "+scpSyncPlugin+" plugin\n")
	installed, err := vagrant.PluginInstalled(ctx, vagrantExe, scpSyncPlugin)
	if err != nil {
		return err
	}
	if !installed {
		out.Write("stdout", "Installing "+scpSyncPlugin+"\n")
		if ierr := vagrant.PluginInstall(ctx, vagrantExe, scpSyncPlugin, out.Write); ierr != nil {
			return ierr
		}
	}

	out.Write("stdout", "Running vagrant up in "+*machine.Home+"\n")
	if uerr := vagrant.Up(ctx, vagrantExe, *machine.Home, true, out.Write); uerr != nil {
		return uerr
	}

	// The VM's identity from vagrant's own state — the VirtualBox name is
	// Hosts.rb's, so the UUID is what ties the VM to this row (discovery
	// matches on it from now on).
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
	return nil
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
		if perr := e.prepareWorkdir(machine, spec, out); perr != nil {
			return perr
		}
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
