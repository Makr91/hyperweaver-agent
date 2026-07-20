package server

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// handleProvisionMachine starts the provisioning pipeline (provisionZone).
//
//	@Summary		Start the provisioning pipeline
//	@Description	Minimum role: operator. Orchestrates the full provisioning run against the STORED provisioner document (the zoneweaver mechanism). THERE ARE NO PHASES: the run executes the stored document's provisioning: section AS WRITTEN — method keys in the order they appear in the stored document, entries within each method in list order — bracketed by the folder sync (outermost) and the pre[]/post[] hooks; the method children chain DIRECTLY under the orchestration parent. The chain: machine_prepare (re-render + refresh the working copy — regenerated before every provision) → boot (the plain start operation as a child, skipped when running or skip_boot) → machine_wait_ssh (credentials = settings.vagrant_user/vagrant_user_pass/vagrant_user_private_key_path — SSH keys resolve over the THREE-TIER ladder (Mark's three-tier ruling, sync 2026-07-17): tier 1 = the working copy's vagrant_user_private_key_path when the file EXISTS (rotated, or user-supplied); tier 2 = the packaged bootstrap key inside the working copy (driver/ssh_keys/id_rsa, then the legacy core/ssh_keys/id_rsa) when the named key is missing or none is named — never a guest fetch; the agent provisioning key is the last existence-checked candidate, and password auth engages ONLY when no key file exists anywhere — a key file on disk always beats a document password (zoneweaver's exact ladder). TIER 3 is RECOVERY ONLY: when the wait exhausts on key auth and the guest-agent channel is enabled, the agent recovers the rotated key over QGA (guest-exec cat of /home/<vagrant_user>/.ssh/id_ssh_rsa), lands it at the working-copy key path (0600), and retries the wait ONCE — without a QGA channel the failure honestly names 'both known keys were rejected and no SSH-free transport exists'; transport = the provisioning NIC's NAT ssh port-forward at 127.0.0.1 when the machine carries one — vagrant's model, immune to guest network reconfiguration — else the control IP from networks[] is_control → provisional → first; neither existing is a 400) → machine_sync_parent + one machine_sync per folders[] entry (transport per folder.type: rsync | scp, each with a pure-Go fallback when the binary is absent — embedded rsync client / SFTP, loudly narrated in the task output; vagrant is optional; disabled entries skipped; type virtualbox registers a REAL VirtualBox shared folder instead of copying — hot-added with automount, guest-mounted via vboxsf when Guest Additions run, a failed guest mount narrates and never fails the pipeline) → one machine_hook per provisioning.pre[] SEQUENCE HOOK entry, before the first method ({script, target: host|guest default guest, on_failure: abort|continue default abort, run: always|once default always} — design §5's ruled shape: guest hooks upload+sudo-run like shell scripts, host hooks run the working-copy script ON THE AGENT HOST gated by provisioning.host_hooks (default ON here), on_failure continue narrates and proceeds, run once skips after the first successful provision) → THE METHOD WALK — provisioning:'s keys in stored-document order, entries in list order: shell → one machine_shell per scripts[] string (the package-relative path resolves against the working copy, uploads over the built-in SFTP to a /tmp path, chmod +x, runs with sudo — shebang honored — then removes itself; a nonzero exit fails the task; bare string entries carry no run directive and execute every time the walk reaches them); ansible → groups in list order, each group's local[] then its remote[] per its own lists — ONE chain, each entry local (machine_provision) or remote (machine_provision_remote — design §5: ansible-playbook ON THE AGENT HOST dialing the guest over the pipeline transport, inventory pinned to the resolved ip/port, credentials from the stored settings with the agent provisioning key as fallback, ANSIBLE_CONFIG/ANSIBLE_COLLECTIONS_PATH resolved against the working copy, remote_collections galaxy-installs host-side; the control node resolves natively where the OS carries ansible and through WSL on Windows hosts — the default WSL distribution's ansible, host paths translated to their /mnt form, extra-vars via an @file in the working copy, the private key riding a chmod-600 mktemp copy (keys on /mnt mounts are world-readable and OpenSSH refuses them), and 127.0.0.1 forward targets (ssh and winrm alike) reached through a RUN-SCOPED twin forward bound to the WSL gateway address (NAT-mode WSL2 shares no loopback with the Windows host and the create-time forwards bind 127.0.0.1 — the twin is added before the run, removed after, host-internal, and the loopback rule is untouched) — and NO control node anywhere fails honestly) per its OWN list, never all-locals-then-all-remotes; run directives filter PER ENTRY (always = every run; not_first = only after a prior success; once/unset = only when never provisioned — judged by configuration.provisioner_state.last_provisioned_at); docker → one machine_docker_compose per docker_compose[] (or docker-compose[]) file (guest path, `up -d`, compose v2 plugin first then docker-compose) — NO engine installation: an absent guest engine fails the task honestly, and compose entries carry no run pin; UNKNOWN method keys SURVIVE in the stored document and are narrate-skipped by the walk — named loudly in the response and the parent's metadata, never a failure → one machine_hook per provisioning.post[] entry, after the last method → when any folder carries syncback: true, machine_syncback_parent + one machine_syncback per flagged folder pulls those folders guest→host — the post-provision results landing (folder.to → folder.map reversed; delete never honored on a pull, no chown) → KEY ROTATION (settings.vagrant_ssh_insert_key, the on/true/1/yes vocabulary — the key_rotate proposal, sync 2026-07-17): ONE machine_key_rotate child AFTER the syncback bracket adopts the box's ROTATED private key — SFTP-reads /home/<vagrant_user>/.ssh/id_ssh_rsa from the guest (a missing remote file is a narrated skip and the task SUCCEEDS — box built without rotation), lands it at settings.vagrant_user_private_key_path in the working copy (0600), then strips the bootstrap pubkey line from the guest file (sed '/vagrantup/d' — Hosts.rb:706's hack; a strip failure fails the task HONESTLY — the landed key stays, and the whole-walk stamp never sits on this child). It NEVER owns the whole-walk stamp; the response task_chain[] carries {step: 'key_rotate', task_id}, and winrm guests get the response-only {step: 'key_rotate_skipped_winrm'} entry instead. THE STAMP: provisioner_state.last_provisioned_at records ONLY when the ENTIRE walk succeeds, whatever type its last entry is — it rides the chain's final task, and the linear chain makes that equivalent to whole-run success; a partial run never marks the machine provisioned. THE PIPELINE-OWNED POWER CYCLE (Mark's execution ruling, sync 2026-07-18): when the machine is flagged for transport removal (settings.remove_transport_on_completion true, or any networks[] entry's remove_on_completion — absent = this agent's default FALSE) the chain appends stop → machine_transport_remove → start AFTER the stamp (task_chain steps post_provision_stop / transport_remove / post_provision_boot): the flagged adapters are removed (the intrinsic NAT's forwards deleted with it), the document updates to match (entries removed, is_control flipped to the first survivor, the settings flag cleared), and the post-removal boot gates on NOTHING — the run is COMPLETE at the boot, the machine comes up on its real NICs. vbox.post_provision_boot (the cycle-after-provisioning knob — per-hypervisor key, sync 2026-07-19) triggers the SAME stop→start cycle without the removal step. The extra_vars networks[] carry each adapter's LIVE MAC when the document leaves mac auto/empty (adapter = network index + 2; resolved into the run's variable document only — the stored document is never modified). Prerequisites: provisioner config stored (create auto-fills it; PUT overrides) and a control IP in networks[]. WINRM MACHINES (settings.communicator: winrm — the converged transport, sync 2026-07-17): the wait step verifies the guest via HOST-ANSIBLE win_ping instead of an SSH dial (ansible + pywinrm on the AGENT HOST are required — on Windows hosts that means ansible + pywinrm inside WSL's default distribution; their absence is an honest task failure, never a pre-flight); shell scripts and guest hooks run via host-ansible win_copy/win_shell/win_file; remote playbooks connect over winrm. Folder sync/syncback, ansible LOCAL playbooks, and docker compose CANNOT run over winrm — they are skipped as RESPONSE-ONLY task_chain entries ({step: 'sync_skipped_winrm', folder_count}, {step: 'syncback_skipped_winrm', folder_count}, {step: 'ansible_local_skipped_winrm', playbook_count}, {step: 'docker_skipped_winrm'}), and unknown methods additionally emit {step: 'method_not_executable', method}.
//	@Tags			Machine Management
//	@Accept			json
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Param			request		body	map[string]interface{}	false	"Optional {skip_boot, confirm_host_hooks}"
//	@Success		200	{object}	map[string]interface{}	"Provisioning pipeline started"
//	@Failure		400	"No provisioner config stored, missing settings.vagrant_user, no control IP in networks[], or host-target hooks while provisioning.host_hooks is false"
//	@Failure		404	"Machine not found"
//	@Failure		409	{object}	map[string]interface{}	"Host-target hooks need the one-time confirmation — STRICTLY pre-flight, never a mid-sequence failure"
//	@Router			/machines/{machineName}/provision [post]
func (s *Server) handleProvisionMachine(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	var body struct {
		SkipBoot bool `json:"skip_boot"`
		// ConfirmHostHooks answers the one-time host-hooks confirmation
		// (design §5): true on the retry records it per machine and proceeds.
		ConfirmHostHooks bool `json:"confirm_host_hooks"`
	}
	if r.ContentLength > 0 {
		if err := decodeBody(r, &body); err != nil {
			taskError(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
	}
	validation, problem := validateProvisionRequest(machine)
	if problem != "" {
		taskError(w, http.StatusBadRequest, problem)
		return
	}
	if problem := resolveTransport(r.Context(), machine, validation); problem != "" {
		taskError(w, http.StatusBadRequest, problem)
		return
	}
	// Host-hooks pre-flight (design §5's ruled shape): the refusal is UP
	// FRONT and clearly needs-confirmation — never a mid-sequence failure.
	if problem, needsConfirmation := s.hostHooksPreflight(r.Context(), machine,
		validation, body.ConfirmHostHooks); problem != "" {
		taskError(w, http.StatusBadRequest, problem)
		return
	} else if needsConfirmation {
		writeJSONStatus(w, http.StatusConflict, map[string]any{
			"needs_confirmation": true,
			"reason":             "This machine's document carries host-target sequence hooks from a NON-SEEDED package — they run scripts on the agent host itself",
			"confirm_with":       `re-POST with {"confirm_host_hooks": true} (recorded once per machine)`,
		})
		return
	}

	createdBy := auth.FromContext(r.Context()).Name
	parentID, chain, skippedMethods, err := s.startProvisionPipeline(r.Context(), machine,
		validation, body.SkipBoot, createdBy)
	if err != nil {
		slog.Error("start provision pipeline", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to start provisioning pipeline")
		return
	}

	response := map[string]any{
		"success":        true,
		"message":        "Provisioning pipeline started for " + machine.Name,
		"machine_name":   machine.Name,
		"parent_task_id": parentID,
		"steps":          len(chain),
		"task_chain":     chain,
	}
	// The QG2 narrate-skip: unknown provisioning: method keys are named
	// loudly, never a failure.
	if len(skippedMethods) > 0 {
		response["skipped_methods"] = skippedMethods
	}
	writeJSON(w, response)
}

// handleSyncMachine creates the ad-hoc parentless sync chain (syncZone).
// Body {"syncback": true} reverses it: ONLY the syncback-flagged folders
// pull guest→host (folders[].syncback — the on-demand half of Mark's ruling
// 2026-07-12; the plain call stays host→guest for every folder).
//
//	@Summary		Sync folders to a machine ad-hoc
//	@Description	Minimum role: operator. Creates the parentless sync chain: one machine_sync per folders[] entry from the stored document (transport per folder.type), independent of the full pipeline — the machine must be running with SSH reachable. Body {"syncback": true} REVERSES it (folders[].syncback — the on-demand half of the syncback contract): ONLY the syncback-flagged folders pull guest→host (guest folder.to → host folder.map, one machine_syncback per folder; folder.delete is never honored on a pull, no chown, args/exclude apply on the rsync path; the remote sender runs sudo rsync so root-owned results are readable). The provision walk ends with this same syncback (after the post[] hooks) when any folder carries the flag. WINRM machines are refused outright — 400 "Folder sync needs ssh (rsync/scp) — this machine uses the winrm communicator, which cannot carry folders".
//	@Tags			Machine Management
//	@Accept			json
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Param			request		body	map[string]interface{}	false	"Optional {syncback}"
//	@Success		200	{object}	map[string]interface{}	"Sync (or syncback) chain created"
//	@Failure		400	"No provisioner config, no folders configured, (syncback) no folders flagged syncback: true, or the machine uses the winrm communicator (folder sync needs ssh)"
//	@Failure		404	"Machine not found"
//	@Router			/machines/{machineName}/sync [post]
func (s *Server) handleSyncMachine(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	var body struct {
		Syncback bool `json:"syncback"`
	}
	if r.ContentLength > 0 {
		if err := decodeBody(r, &body); err != nil {
			taskError(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
	}
	validation, problem := validateProvisionRequest(machine)
	if problem != "" {
		taskError(w, http.StatusBadRequest, problem)
		return
	}
	// /sync's winrm gate is a pre-flight 400 (W-Q1..W-Q5): folders only ride
	// ssh transports. Shadowed keys LOG only here — /sync has no task_chain.
	if len(validation.shadowedKeys) > 0 {
		slog.Warn("communicator keys shadowed by their new spellings",
			"machine", machine.Name, "keys", validation.shadowedKeys)
	}
	if validation.communicator == "winrm" {
		taskError(w, http.StatusBadRequest,
			"Folder sync needs ssh (rsync/scp) — this machine uses the winrm communicator, which cannot carry folders")
		return
	}
	if problem := resolveTransport(r.Context(), machine, validation); problem != "" {
		taskError(w, http.StatusBadRequest, problem)
		return
	}
	if body.Syncback {
		createdBy := auth.FromContext(r.Context()).Name
		// stampFinal false: an ad-hoc syncback is never a provision walk.
		chain, serr := s.buildSyncbackChain(r.Context(), machine.Name, validation,
			nil, "", createdBy, false)
		if serr != nil {
			slog.Error("create syncback chain", "machine", machine.Name, "error", serr)
			taskError(w, http.StatusInternalServerError, "Failed to create syncback task chain")
			return
		}
		if chain == nil {
			taskError(w, http.StatusBadRequest,
				"No folders are flagged syncback: true in provisioner metadata")
			return
		}
		writeJSON(w, map[string]any{
			"success":        true,
			"message":        "Machine syncback task chain created for " + machine.Name,
			"machine_name":   machine.Name,
			"parent_task_id": chain[0]["task_id"],
			"folder_count":   chain[0]["folder_count"],
		})
		return
	}
	folders := machines.ProvisionerFolders(validation.provisioner)
	if len(folders) == 0 {
		taskError(w, http.StatusBadRequest, "No folders configured in provisioner metadata")
		return
	}

	createdBy := auth.FromContext(r.Context()).Name
	parentMeta, err := json.Marshal(map[string]any{"total_folders": len(folders)})
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to create sync task chain")
		return
	}
	metadata := string(parentMeta)
	syncParent, err := s.createChainTask(r.Context(), machine.Name, machines.OpSyncParent,
		&metadata, nil, "", createdBy)
	if err != nil {
		slog.Error("create sync parent", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to create sync task chain")
		return
	}
	previous := &syncParent.ID
	for i := range folders {
		folderMeta, ferr := childMetadata(validation, map[string]any{"folder": folders[i]})
		if ferr != nil {
			taskError(w, http.StatusInternalServerError, "Failed to create sync task chain")
			return
		}
		child, cerr := s.createChainTask(r.Context(), machine.Name, machines.OpSyncFolder,
			folderMeta, previous, syncParent.ID, createdBy)
		if cerr != nil {
			slog.Error("create sync child", "machine", machine.Name, "error", cerr)
			taskError(w, http.StatusInternalServerError, "Failed to create sync task chain")
			return
		}
		previous = &child.ID
	}

	writeJSON(w, map[string]any{
		"success":        true,
		"message":        "Machine sync task chain created for " + machine.Name,
		"machine_name":   machine.Name,
		"parent_task_id": syncParent.ID,
		"folder_count":   len(folders),
	})
}

// handleRunProvisioners runs the SAME document walk ad-hoc — minus
// prepare/boot/wait_ssh/sync/syncback — under ONE machine_provision_parent
// anchor (its only surviving role): pre[] hooks → the provisioning: methods
// in stored-document key order → post[] hooks; the last planned child
// carries the whole-walk stamp. Nothing configured is a 400; everything
// run-skipped answers a 200 no-op with the skipped list.
//
//	@Summary		Run provisioners ad-hoc
//	@Description	Minimum role: operator. The SAME document walk as POST /provision minus the infra and folder brackets, under a machine_provision_parent anchor: one machine_hook per provisioning.pre[] entry, then the stored document's provisioning: method keys in the order they appear (shell scripts, ansible local/remote entries — run-filtered per entry, and docker compose entries all execute here too), then one machine_hook per post[] entry. The machine must be running with SSH reachable. The whole-walk stamp rides the final task — last_provisioned_at records only when the ENTIRE walk succeeds. All entries skipped by their run directives answers a 200 no-op carrying the skipped list; an empty provisioning: section is a 400. The response carries task_chain[] like /provision, and the WINRM rules apply here too (settings.communicator: winrm): shell scripts and guest hooks run via host-ansible win_copy/win_shell/win_file, remote playbooks connect over winrm, while ansible LOCAL playbooks and docker compose entries are skipped as response-only task_chain entries ({step: 'ansible_local_skipped_winrm', playbook_count}, {step: 'docker_skipped_winrm'}) and unknown methods emit {step: 'method_not_executable', method}.
//	@Tags			Machine Management
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{object}	map[string]interface{}	"Provisioner tasks created (or the all-skipped no-op)"
//	@Failure		400	"No provisioner config, no playbooks configured, missing credentials, or no control IP"
//	@Failure		404	"Machine not found"
//	@Router			/machines/{machineName}/run-provisioners [post]
func (s *Server) handleRunProvisioners(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	validation, problem := validateProvisionRequest(machine)
	if problem != "" {
		taskError(w, http.StatusBadRequest, problem)
		return
	}
	if problem := resolveTransport(r.Context(), machine, validation); problem != "" {
		taskError(w, http.StatusBadRequest, problem)
		return
	}
	walk, skippedMethods, skippedPlaybooks, playbookCount := planWalk(machine, validation,
		machines.HasProvisionedBefore(validation.config))

	// task_chain[] mirrors the provision response's channel (W-Q1..W-Q5):
	// shadowed-key narration first, then the labeled/skip entries as the
	// walk lands them.
	taskChain := []map[string]any{}
	if len(validation.shadowedKeys) > 0 {
		slog.Warn("communicator keys shadowed by their new spellings",
			"machine", machine.Name, "keys", validation.shadowedKeys)
		taskChain = append(taskChain, map[string]any{
			"step": "communicator_keys_shadowed", "keys": validation.shadowedKeys,
		})
	}
	lastRealWalk := -1
	for i := range walk {
		if walk[i].operation != "" {
			lastRealWalk = i
		}
	}
	if lastRealWalk < 0 {
		// Nothing executable. Response-only entries (winrm skips) still
		// answer a 200 no-op with the narration; the run-directive no-op and
		// the plain 400 keep their existing branches.
		for i := range walk {
			entry := map[string]any{"step": walk[i].step}
			for key, value := range walk[i].stepInfo {
				entry[key] = value
			}
			taskChain = append(taskChain, entry)
		}
		if len(skippedPlaybooks) > 0 || len(walk) > 0 {
			response := map[string]any{
				"success":           true,
				"machine_name":      machine.Name,
				"message":           "All configured playbooks were skipped by their run directives",
				"playbooks_skipped": skippedPlaybooks,
			}
			if len(walk) > 0 {
				response["message"] = "Nothing is executable on this machine's communicator — see task_chain"
			}
			if len(taskChain) > 0 {
				response["task_chain"] = taskChain
			}
			if len(skippedMethods) > 0 {
				response["skipped_methods"] = skippedMethods
			}
			writeJSON(w, response)
			return
		}
		taskError(w, http.StatusBadRequest, "No provisioners configured in provisioner metadata")
		return
	}

	createdBy := auth.FromContext(r.Context()).Name
	parentDoc := map[string]any{
		"total_playbooks":   playbookCount,
		"skipped_playbooks": skippedPlaybooks,
	}
	if len(skippedMethods) > 0 {
		parentDoc["skipped_methods"] = skippedMethods
	}
	parentMeta, err := json.Marshal(parentDoc)
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to create provisioner tasks")
		return
	}
	metadata := string(parentMeta)
	provisionParent, err := s.createChainTask(r.Context(), machine.Name,
		machines.OpProvisionParent, &metadata, nil, "", createdBy)
	if err != nil {
		slog.Error("create provision parent", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to create provisioner tasks")
		return
	}
	previous := &provisionParent.ID
	for i := range walk {
		if walk[i].operation == "" {
			// Response-only entries (winrm skips, method_not_executable) —
			// task_chain[] at document position, never tasks.
			entry := map[string]any{"step": walk[i].step}
			for key, value := range walk[i].stepInfo {
				entry[key] = value
			}
			taskChain = append(taskChain, entry)
			continue
		}
		extra := walk[i].extra
		if i == lastRealWalk {
			// The walk's last REAL child carries the whole-walk stamp —
			// response-only entries never own final.
			extra["final"] = true
		}
		stepMeta, ferr := childMetadata(validation, extra)
		if ferr != nil {
			taskError(w, http.StatusInternalServerError, "Failed to create provisioner tasks")
			return
		}
		child, cerr := s.createChainTask(r.Context(), machine.Name, walk[i].operation,
			stepMeta, previous, provisionParent.ID, createdBy)
		if cerr != nil {
			slog.Error("create provision child", "machine", machine.Name, "error", cerr)
			taskError(w, http.StatusInternalServerError, "Failed to create provisioner tasks")
			return
		}
		if walk[i].step != "" {
			entry := map[string]any{"step": walk[i].step, "task_id": child.ID}
			for key, value := range walk[i].stepInfo {
				entry[key] = value
			}
			taskChain = append(taskChain, entry)
		}
		previous = &child.ID
	}

	response := map[string]any{
		"success":           true,
		"machine_name":      machine.Name,
		"parent_task_id":    provisionParent.ID,
		"playbook_count":    playbookCount,
		"playbooks_skipped": skippedPlaybooks,
	}
	if len(taskChain) > 0 {
		response["task_chain"] = taskChain
	}
	if len(skippedMethods) > 0 {
		response["skipped_methods"] = skippedMethods
	}
	writeJSON(w, response)
}

// handleProvisionStatus reports the pipeline state (getProvisioningStatus):
// configured flag, provisioned|not_started, last_provisioned_at, and the 20
// most recent provisioning tasks.
//
//	@Summary		Provisioning pipeline status
//	@Description	Minimum role: viewer. Whether provisioner config is stored, whether a provision ever succeeded, and the most recent provisioning tasks.
//	@Tags			Machine Management
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{object}	map[string]interface{}	"Provisioning status"
//	@Failure		404	"Machine not found"
//	@Router			/machines/{machineName}/provision/status [get]
func (s *Server) handleProvisionStatus(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	config := machines.ParseConfiguration(machine)
	state := config.Section("provisioner_state")
	lastProvisioned, _ := state["last_provisioned_at"].(string)

	recent := []*tasks.Task{}
	for _, operation := range []string{
		machines.OpProvisionOrchestration, machines.OpPrepare, machines.OpWaitSSH,
		machines.OpSyncParent, machines.OpSyncFolder,
		machines.OpShellScript,
		machines.OpProvisionParent, machines.OpProvisionPlaybook,
		machines.OpRemotePlaybook, machines.OpDockerCompose,
		machines.OpSyncbackParent, machines.OpSyncbackFolder,
		machines.OpHook,
	} {
		filter := tasks.ListFilter{MachineName: machine.Name, Operation: operation, Limit: 20}
		list, err := s.tasks.Store().List(r.Context(), &filter)
		if err != nil {
			slog.Warn("list provisioning tasks", "machine", machine.Name, "error", err)
			continue
		}
		recent = append(recent, list...)
	}
	if len(recent) > 20 {
		recent = recent[:20]
	}

	status := "not_started"
	if lastProvisioned != "" {
		status = "provisioned"
	}
	writeJSON(w, map[string]any{
		"success":                 true,
		"machine_name":            machine.Name,
		"provisioning_configured": len(config.Provisioner()) > 0,
		"provisioning_status":     status,
		"last_provisioned_at":     nullableString(lastProvisioned),
		"recent_tasks":            recent,
	})
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
