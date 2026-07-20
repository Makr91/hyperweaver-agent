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

// provisionPlaybook executes machine_provision — ONE playbook
// (executeZoneProvisionTask + runAnsibleLocalProvisioner 1:1): extra_vars
// built AT RUN TIME from the stored document + working-directory secrets,
// ansible installed in the guest (pip or pkg), galaxy collections --force,
// then ansible-playbook -i 'localhost,' -c local with the JSON extra_vars;
// provisioner_state.last_provisioned_at stamps only on the walk's final task
// (metadata final: true — stampIfFinal).
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
		BuildExtraVars(machine, config, workdir), playbook)
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
	// STARTcloud progress adoption: watch the streamed ansible output for the
	// packages' callback marker (PROGRESS::{json}, progress_scan.go) and fold
	// it into the task's progress_info live (the guest's percent maps into
	// this task's running_playbook window, 40→95 — the task percent stays
	// honest across the install/collections phases before it and the stamp
	// after).
	scanner := newProgressScanner(func(percent int, description string) {
		e.playbookProgress(task, percent, description)
	})
	streamWrite := func(stream, data string) {
		scanner.Scan(stream, data)
		out.Write(stream, data)
	}
	if rerr := sshrun.Run(ctx, meta.IP, meta.Port, meta.Credentials, command,
		workdir, e.env.ProvisionKeyPath, playbookTimeout, streamWrite); rerr != nil {
		return fmt.Errorf("ansible-local failed: %w", rerr)
	}

	e.stampIfFinal(task, meta, out)
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
