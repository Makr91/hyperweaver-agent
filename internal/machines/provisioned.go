package machines

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// Provisioned-machine support (Mark's provisioning-engine ruling: the agent
// recreates zoneweaver's mechanisms — native hypervisor lifecycle, agent-
// driven sync + ansible-local; vagrant/Hosts.rb are never executed): the
// creation spec, the pipeline environment, hash-verified installer
// resolution, and the working-directory rules.

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
	// DefaultSyncMethod fills specs without an explicit sync_method (SHI's
	// global syncmethod preference); platform rules still apply on top.
	DefaultSyncMethod string
	// DefaultNetworkInterface reaches the template context as
	// settings.default_network_interface / DEFAULT_NETWORK_INTERFACE when
	// the spec sets none (SHI's bridge-interface fallback).
	DefaultNetworkInterface string
	// TemplatesDir is the box-template storage root (the base's
	// template_sources.local_storage_path).
	TemplatesDir string
	// TemplateSources are the configured Vagrant/BoxVault registries.
	TemplateSources []TemplateSource
	// ProvisionKeyPath is the agent's own SSH provisioning key
	// (provisioning.ssh.key_path — generated at startup when absent).
	ProvisionKeyPath string
	// SSHTimeout/SSHPollInterval bound machine_wait_ssh
	// (provisioning.ssh.timeout_seconds / poll_interval_seconds).
	SSHTimeout      time.Duration
	SSHPollInterval time.Duration
	// AnsibleInstallTimeout/PlaybookTimeout bound machine_provision's two
	// phases (provisioning.ansible_install_timeout_seconds /
	// playbook_timeout_seconds).
	AnsibleInstallTimeout time.Duration
	PlaybookTimeout       time.Duration
	// Network is the dedicated provisioning network (provisioning.network —
	// the base's etherstub+dhcpd block as a host-only interface + VirtualBox
	// DHCP with per-VM fixed leases).
	Network NetworkEnv
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
