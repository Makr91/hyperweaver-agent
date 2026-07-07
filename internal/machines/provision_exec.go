package machines

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/sshrun"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// The provision pipeline children — zoneweaver's ZoneProvisionManager ported
// 1:1: machine_wait_ssh polls the guest, machine_sync lands ONE folder
// (transport per the folder's own type: rsync | scp; virtualbox/disabled
// skip), machine_provision runs ONE playbook ansible-local inside the guest
// with the full extra_vars document; the run's FINAL playbook stamps
// provisioner_state (Hosts.rb semantics — the one deliberate divergence
// from the base's per-playbook stamping, Mark's ruling 2026-07-07).

// Provision-chain operations.
const (
	OpProvisionOrchestration = "machine_provision_orchestration"
	OpWaitSSH                = "machine_wait_ssh"
	OpSyncParent             = "machine_sync_parent"
	OpSyncFolder             = "machine_sync"
	OpProvisionParent        = "machine_provision_parent"
	OpProvisionPlaybook      = "machine_provision"
)

// provisionTaskMetadata is the wait_ssh/sync/provision children's metadata —
// the base's exact shape: {ip, port, credentials, folder?, playbook?} plus
// final, marking the run's LAST playbook (the provisioned-state stamp rides
// it — Hosts.rb's results.yml semantics).
type provisionTaskMetadata struct {
	IP          string             `json:"ip"`
	Port        int                `json:"port"`
	Credentials sshrun.Credentials `json:"credentials"`
	Folder      *Folder            `json:"folder,omitempty"`
	Playbook    *Playbook          `json:"playbook,omitempty"`
	Final       bool               `json:"final,omitempty"`
}

func readProvisionMetadata(task *tasks.Task) (*provisionTaskMetadata, error) {
	if task.Metadata == nil {
		return nil, errors.New("provision task has no metadata")
	}
	var meta provisionTaskMetadata
	if err := json.Unmarshal([]byte(*task.Metadata), &meta); err != nil {
		return nil, fmt.Errorf("parse provision metadata: %w", err)
	}
	if meta.IP == "" {
		return nil, errors.New("ip is required in task metadata")
	}
	if meta.Port == 0 {
		meta.Port = 22
	}
	return &meta, nil
}

// waitSSH executes machine_wait_ssh: poll until the guest answers over SSH
// (config timeouts; the document's settings.setup_wait wins when larger).
func (e *executors) waitSSH(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	meta, err := readProvisionMetadata(task)
	if err != nil {
		return err
	}
	timeout := e.env.SSHTimeout
	if timeout <= 0 {
		timeout = 300 * time.Second
	}
	if machine, gerr := e.store.Get(ctx, task.MachineName); gerr == nil {
		settings := ParseConfiguration(machine).Section("settings")
		if wait := intOr(settings["setup_wait"], 0); wait > 0 {
			if document := time.Duration(wait) * time.Second; document > timeout {
				timeout = document
			}
		}
	}
	interval := e.env.SSHPollInterval
	if interval <= 0 {
		interval = 10 * time.Second
	}

	e.taskProgress(task, 10, "waiting_for_ssh")
	out.Write("stdout", fmt.Sprintf("Waiting for SSH on %s:%d (timeout %ds)\n",
		meta.IP, meta.Port, int(timeout.Seconds())))
	elapsed, err := sshrun.WaitForSSH(ctx, meta.IP, meta.Port, meta.Credentials,
		e.machineWorkdir(task.MachineName), e.env.ProvisionKeyPath, timeout, interval, out.Write)
	if err != nil {
		return err
	}
	e.taskProgress(task, 100, "completed")
	out.Write("stdout", fmt.Sprintf("SSH available on %s (%s:%d) after %ds\n",
		task.MachineName, meta.IP, meta.Port, int(elapsed.Seconds())))
	return nil
}

// syncFolder executes machine_sync — ONE folder (executeZoneSyncTask 1:1):
// skip disabled/virtualbox entries, resolve a relative map against the
// working directory, pre-create the destination, transport per the folder's
// type (rsync flags + --rsync-path='sudo rsync' | scp -r), chown to
// owner:group after.
func (e *executors) syncFolder(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	meta, err := readProvisionMetadata(task)
	if err != nil {
		return err
	}
	if meta.Folder == nil {
		return errors.New("folder is required in task metadata")
	}
	folder := meta.Folder
	if folder.Disabled || strings.EqualFold(folder.Type, "virtualbox") {
		out.Write("stdout", "Folder sync skipped ("+skipReason(folder)+")\n")
		return nil
	}
	if folder.Map == "" || folder.To == "" {
		return errors.New("folder missing source (map) or destination (to)")
	}

	workdir := e.machineWorkdir(task.MachineName)
	source := folder.Map
	if !strings.HasPrefix(source, "/") && !strings.Contains(source, ":") {
		source = workdir + "/" + strings.TrimPrefix(strings.TrimPrefix(source, "./"), ".")
	}

	e.taskProgress(task, 10, "creating_destination")
	out.Write("stdout", "Syncing "+source+" → "+folder.To+" ("+transportFor(folder)+")\n")
	if rerr := sshrun.Run(ctx, meta.IP, meta.Port, meta.Credentials,
		"sudo mkdir -p "+folder.To, workdir, e.env.ProvisionKeyPath, time.Minute, out.Write); rerr != nil {
		return fmt.Errorf("pre-create %s: %w", folder.To, rerr)
	}

	e.taskProgress(task, 30, "syncing_files")
	switch transportFor(folder) {
	case SyncSCP:
		scpExe, lerr := sshrun.FindTool("scp")
		if lerr != nil {
			return lerr
		}
		if serr := sshrun.SCPSync(ctx, scpExe, meta.IP, meta.Port, meta.Credentials,
			source, folder.To, workdir, e.env.ProvisionKeyPath, out.Write); serr != nil {
			return fmt.Errorf("%s → %s: %w", folder.Map, folder.To, serr)
		}
	default:
		// PATH first, then vagrant's embedded toolchain (Mark's rule: a
		// vagrant install carries a working rsync on every platform).
		rsyncExe, lerr := sshrun.FindTool("rsync")
		if lerr != nil {
			return fmt.Errorf("%w — set the folder type to scp or install rsync", lerr)
		}
		if serr := sshrun.SyncFiles(ctx, rsyncExe, meta.IP, meta.Port, meta.Credentials,
			source, folder.To, workdir, e.env.ProvisionKeyPath, &sshrun.SyncOptions{
				Args:    folder.Args,
				Exclude: folder.Exclude,
				Delete:  folder.Delete,
			}, out.Write); serr != nil {
			return fmt.Errorf("%s → %s: %w", folder.Map, folder.To, serr)
		}
	}

	e.taskProgress(task, 85, "setting_ownership")
	owner := folder.Owner
	if owner == "" {
		owner = meta.Credentials.Username
	}
	if owner == "" {
		owner = "root"
	}
	group := folder.Group
	if group == "" {
		group = owner
	}
	if cerr := sshrun.Run(ctx, meta.IP, meta.Port, meta.Credentials,
		"sudo chown -R "+owner+":"+group+" "+folder.To,
		workdir, e.env.ProvisionKeyPath, time.Minute, out.Write); cerr != nil {
		out.Write("stderr", "chown "+folder.To+" failed: "+cerr.Error()+"\n")
	}
	e.taskProgress(task, 100, "completed")
	return nil
}

func skipReason(folder *Folder) string {
	if folder.Disabled {
		return "disabled"
	}
	return "virtualbox shared folders are never used"
}

// transportFor resolves a folder's sync transport: the folder's own type
// wins; anything not scp is rsync (the base is rsync-only; scp exists for
// Mark's broken-macOS-rsync rule and the document's per-folder choice).
func transportFor(folder *Folder) string {
	if strings.EqualFold(folder.Type, SyncSCP) {
		return SyncSCP
	}
	return SyncRsync
}

// provisionPlaybook executes machine_provision — ONE playbook
// (executeZoneProvisionTask + runAnsibleLocalProvisioner 1:1): extra_vars
// built AT RUN TIME from the stored document + working-directory secrets,
// ansible installed in the guest (pip or pkg), galaxy collections --force,
// then ansible-playbook -i 'localhost,' -c local with the JSON extra_vars;
// provisioner_state.last_provisioned_at stamps only on the run's final
// playbook (metadata final: true).
func (e *executors) provisionPlaybook(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	meta, err := readProvisionMetadata(task)
	if err != nil {
		return err
	}
	if meta.Playbook == nil || meta.Playbook.Playbook == "" {
		return errors.New("playbook is required in task metadata")
	}
	playbook := meta.Playbook

	machine, err := e.store.Get(ctx, task.MachineName)
	if err != nil {
		return fmt.Errorf("machine %s: %w", task.MachineName, err)
	}
	config := ParseConfiguration(machine)
	e.fillLiveMACs(ctx, machine, config, out)
	workdir := e.machineWorkdir(task.MachineName)

	installTimeout := e.env.AnsibleInstallTimeout
	if installTimeout <= 0 {
		installTimeout = 300 * time.Second
	}
	playbookTimeout := e.env.PlaybookTimeout
	if playbookTimeout <= 0 {
		playbookTimeout = 21600 * time.Second
	}

	e.taskProgress(task, 10, "installing_ansible")
	if playbook.InstallMode != "" {
		installCommand := "pkg install ansible 2>/dev/null || sudo apt-get install -y ansible 2>/dev/null || sudo yum install -y ansible 2>/dev/null"
		if playbook.InstallMode == "pip" {
			installCommand = "pip3 install ansible 2>/dev/null || pip install ansible 2>/dev/null"
		}
		if ierr := sshrun.Run(ctx, meta.IP, meta.Port, meta.Credentials, installCommand,
			workdir, e.env.ProvisionKeyPath, installTimeout, out.Write); ierr != nil {
			out.Write("stderr", "ansible install reported: "+ierr.Error()+" (continuing — it may already be present)\n")
		}
	}

	e.taskProgress(task, 25, "installing_collections")
	if playbook.RemoteCollections {
		for _, collection := range playbook.Collections {
			if cerr := sshrun.Run(ctx, meta.IP, meta.Port, meta.Credentials,
				"ansible-galaxy collection install "+collection+" --force",
				workdir, e.env.ProvisionKeyPath, installTimeout, out.Write); cerr != nil {
				return fmt.Errorf("install collection %s: %w", collection, cerr)
			}
		}
	} else if len(playbook.Collections) > 0 {
		// Hosts.rb's remote_collections:false contract (Mark's ruling
		// 2026-07-07): the collections ship INSIDE the provisioner package
		// and reach the guest through the folder sync — the galaxy is never
		// called (guests need no internet for them; zoneweaver's
		// always-install is its routed-network reality, not the contract).
		out.Write("stdout", "Collections are package-local (remote_collections: false) — skipping ansible-galaxy\n")
	}

	e.taskProgress(task, 40, "running_playbook")
	extraVars := BuildPlaybookExtraVars(
		BuildExtraVars(config, config.Provisioner(), workdir), playbook)
	varsJSON, err := json.Marshal(extraVars)
	if err != nil {
		return err
	}
	// The base's single-quote escaping for the remote shell.
	escaped := strings.ReplaceAll(string(varsJSON), "'", `'\''`)

	// The base's command shape exactly: cd to provisioning_path (default
	// /vagrant), ANSIBLE_CONFIG only when the playbook names a config_file.
	provisioningPath := playbook.ProvisioningPath
	if provisioningPath == "" {
		provisioningPath = "/vagrant"
	}
	// Hosts.rb:519 sets ansible.config_file to /vagrant/ansible/ansible.cfg
	// unconditionally for every local playbook — the document's own value
	// wins here, the vagrant default covers documents that omit it (Mark's
	// review 2026-07-07: it was never the template's job).
	configFile := playbook.ConfigFile
	if configFile == "" {
		configFile = "/vagrant/ansible/ansible.cfg"
	}
	ansibleConfig := "ANSIBLE_CONFIG=" + configFile + " "
	command := fmt.Sprintf("cd %s && %sansible-playbook -i 'localhost,' -c local %s --extra-vars '%s'",
		provisioningPath, ansibleConfig, playbook.Playbook, escaped)

	out.Write("stdout", "Running ansible-local playbook "+playbook.Playbook+"\n")
	if rerr := sshrun.Run(ctx, meta.IP, meta.Port, meta.Credentials, command,
		workdir, e.env.ProvisionKeyPath, playbookTimeout, out.Write); rerr != nil {
		return fmt.Errorf("ansible-local failed: %w", rerr)
	}

	// The provisioned-state stamp fires ONLY on the run's final playbook —
	// Hosts.rb's results.yml semantics (Mark's ruling 2026-07-07): a partial
	// run must not mark the machine provisioned, or the once/not_first
	// filters flip after a mid-chain failure (runtime-proven: a successful
	// generate-playbook alone skipped the main playbook forever). zoneweaver
	// stamps after EVERY playbook — flagged to its session as the same defect.
	if meta.Final {
		e.taskProgress(task, 95, "recording_provision_state")
		if serr := e.store.StampProvisionerState(context.Background(), task.MachineName); serr != nil {
			out.Write("stderr", "Failed to record provision state: "+serr.Error()+"\n")
		}
	}
	e.taskProgress(task, 100, "completed")
	out.Write("stdout", "Playbook completed: "+playbook.Playbook+"\n")
	return nil
}

// fillLiveMACs resolves auto/empty networks[].mac entries in the PARSED
// configuration copy feeding the extra_vars — the networking role's netplan
// matches guest adapters BY MAC (runtime-proven 2026-07-07: a vars mac of
// "auto" left the second adapter addressless mid-provision), while the
// STORED document keeps the user's own words verbatim (Mark's ruling: the
// document is the user's source of truth — hypervisor facts are resolved
// into the run's variable document ONLY, zoneweaver's live-scan model).
// Adapter numbering follows the create layout: NAT at 1, document network i
// at adapter i+2. The row's merged live view answers first; a fresh machine
// the sweeps haven't merged yet falls back to one live showvminfo. Failures
// narrate and never fail the run.
func (e *executors) fillLiveMACs(ctx context.Context, machine *Machine, config MachineConfig, out *tasks.OutputWriter) {
	var live *vbox.Info
	for i, entry := range config.List("networks") {
		network := mapOr(entry)
		if mac := stringOr(network["mac"], ""); mac != "" && !strings.EqualFold(mac, "auto") {
			continue
		}
		adapter := "macaddress" + strconv.Itoa(i+2)
		raw, _ := config[adapter].(string)
		if raw == "" {
			if live == nil {
				vboxExe := VBoxManagePath(ctx)
				if vboxExe == "" {
					out.Write("stderr", "Live MAC resolution skipped: VirtualBox is not installed\n")
					return
				}
				info, ierr := vbox.ShowVMInfo(ctx, vboxExe, machine.VBoxTarget())
				if ierr != nil {
					out.Write("stderr", "Live MAC resolution failed: "+ierr.Error()+"\n")
					return
				}
				live = info
			}
			raw = live.Raw[adapter]
		}
		if raw == "" {
			out.Write("stderr", fmt.Sprintf("No live MAC for adapter %d — networks[%d] keeps its document value\n", i+2, i))
			continue
		}
		network["mac"] = formatMAC(raw)
		out.Write("stdout", fmt.Sprintf("Resolved live MAC for networks[%d]: %s\n", i, network["mac"]))
	}
}

// formatMAC converts machinereadable's bare MAC ("080027018B40") into the
// colon form the roles expect ("08:00:27:01:8B:40").
func formatMAC(raw string) string {
	raw = strings.ToUpper(strings.TrimSpace(raw))
	if len(raw) != 12 {
		return raw
	}
	pairs := make([]string, 0, 6)
	for i := 0; i < len(raw); i += 2 {
		pairs = append(pairs, raw[i:i+2])
	}
	return strings.Join(pairs, ":")
}

// syncParentAnchor is the zone_sync_parent/zone_provision_parent executor —
// the parents are pure anchors: their children's completion drives their
// aggregation (they are created as running containers and finish through the
// parent-progress rollup).
func (e *executors) parentAnchor(_ context.Context, _ *tasks.Task, _ *tasks.OutputWriter) error {
	return nil
}
