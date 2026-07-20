package server

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// buildProvisionChain queues the provision pipeline: extract (machine_prepare
// — render + materialize the working copy) → boot (the plain start op when
// not running) → wait_ssh → the document walk: folder sync under its
// sub-parent, then pre[] hooks, methods, post[] hooks as DIRECT children of
// the orchestration parent, then syncback under its sub-parent. The walk is
// PLANNED first and created second so the final flag lands on its overall
// last task. Per-machine queue exclusivity serializes the chain exactly like
// the base's one-task-per-zone rule.
func (s *Server) buildProvisionChain(ctx context.Context, machine *machines.Machine,
	v *provisionValidation, skipBoot bool, parentID, createdBy string,
) (chain []map[string]any, skippedMethods []string, err error) {
	chain = []map[string]any{}
	var previous *string

	// Shadowed communicator keys narrate onto the response task_chain[]
	// (zoneweaver's channel — W-Q1..W-Q5) AND the log; the stored document is
	// never rewritten.
	if len(v.shadowedKeys) > 0 {
		slog.Warn("communicator keys shadowed by their new spellings",
			"machine", machine.Name, "keys", v.shadowedKeys)
		chain = append(chain, map[string]any{
			"step": "communicator_keys_shadowed", "keys": v.shadowedKeys,
		})
	}

	// Extract slot: re-render + re-materialize the working copy from the
	// registry package (SHI regenerates before every provision; zoneweaver
	// extracts its artifact here). Only when the spec NAMES a package —
	// provisioner-less machines have nothing to render (their document
	// arrived via PUT and is consumed as stored, the base's model).
	if spec, serr := machines.ParseSpec(machine); serr == nil && spec.HasProvisioner() {
		specMeta, merr := json.Marshal(map[string]any{"spec": machine.Spec})
		if merr != nil {
			return nil, nil, merr
		}
		metadata := string(specMeta)
		task, terr := s.createChainTask(ctx, machine.Name, machines.OpPrepare,
			&metadata, nil, parentID, createdBy)
		if terr != nil {
			return nil, nil, terr
		}
		chain = append(chain, map[string]any{"step": "extract", "task_id": task.ID})
		previous = &task.ID
	}

	// Boot: the plain start operation queued as a child.
	if !skipBoot && machine.Status != machines.StatusRunning {
		task, terr := s.createChainTask(ctx, machine.Name, machines.OpStart,
			nil, previous, parentID, createdBy)
		if terr != nil {
			return nil, nil, terr
		}
		chain = append(chain, map[string]any{"step": "boot", "task_id": task.ID})
		previous = &task.ID
	}

	// Wait for SSH.
	sshMeta, err := childMetadata(v, nil)
	if err != nil {
		return nil, nil, err
	}
	sshTask, err := s.createChainTask(ctx, machine.Name, machines.OpWaitSSH,
		sshMeta, previous, parentID, createdBy)
	if err != nil {
		return nil, nil, err
	}
	chain = append(chain, map[string]any{"step": "wait_ssh", "task_id": sshTask.ID})
	previous = &sshTask.ID

	// The walk, PLANNED before any of its tasks exist.
	provisionedBefore := machines.HasProvisionedBefore(v.config)
	folders := machines.ProvisionerFolders(v.provisioner)
	syncbackFolders := machines.SyncbackFolders(folders)
	walk, skippedMethods, skippedPlaybooks, _ := planWalk(machine, v, provisionedBefore)
	if len(skippedPlaybooks) > 0 {
		slog.Info("playbooks skipped by run directive",
			"machine", machine.Name, "skipped", len(skippedPlaybooks))
	}

	// FINAL flag: exactly ONE task in the whole chain carries final: true —
	// the walk's overall LAST task in chain order. When the walk is
	// completely empty (no folders, no hooks, no methods), nothing stamps: a
	// document with nothing to execute never marks the machine provisioned.
	// winrm guests skip both folder brackets (no ssh, no rsync/scp — W-Q1..
	// W-Q5), so the final owner accounts for the skipped brackets: the walk's
	// last REAL task carries the stamp. Response-only walk entries (empty
	// operation) never own final.
	isWinRM := v.communicator == "winrm"
	lastRealWalk := -1
	for i := range walk {
		if walk[i].operation != "" {
			lastRealWalk = i
		}
	}
	finalOwner := ""
	switch {
	case len(syncbackFolders) > 0 && !isWinRM:
		finalOwner = "syncback"
	case lastRealWalk >= 0:
		finalOwner = "walk"
	case len(folders) > 0 && !isWinRM:
		finalOwner = "sync"
	}

	// FOLDER SYNC — the walk's opening bracket by document structure: one
	// machine_sync per folders[] entry under the sync sub-parent. winrm
	// guests skip the bracket whole — a RESPONSE-ONLY task_chain[] entry
	// (zoneweaver's exact named shape), never a task.
	if isWinRM && len(folders) > 0 {
		chain = append(chain, map[string]any{
			"step": "sync_skipped_winrm", "folder_count": len(folders),
		})
	}
	if !isWinRM && len(folders) > 0 {
		parentMeta, merr := json.Marshal(map[string]any{"total_folders": len(folders)})
		if merr != nil {
			return nil, nil, merr
		}
		metadata := string(parentMeta)
		syncParent, serr := s.createChainTask(ctx, machine.Name, machines.OpSyncParent,
			&metadata, previous, parentID, createdBy)
		if serr != nil {
			return nil, nil, serr
		}
		chain = append(chain, map[string]any{
			"step": "sync_parent", "task_id": syncParent.ID, "folder_count": len(folders),
		})
		childPrevious := &syncParent.ID
		for i := range folders {
			extra := map[string]any{"folder": folders[i]}
			if finalOwner == "sync" && i == len(folders)-1 {
				extra["final"] = true
			}
			folderMeta, ferr := childMetadata(v, extra)
			if ferr != nil {
				return nil, nil, ferr
			}
			child, cerr := s.createChainTask(ctx, machine.Name, machines.OpSyncFolder,
				folderMeta, childPrevious, syncParent.ID, createdBy)
			if cerr != nil {
				return nil, nil, cerr
			}
			childPrevious = &child.ID
		}
		// The next chain element gates on the LAST sync child, not the sync
		// parent: the parent anchor completes instantly, so depending on it
		// let a playbook overtake the folder syncs (runtime-proven
		// 2026-07-07 — "playbook not found" while its sync was still
		// running). The base carries the same latent hazard, masked only by
		// its ordering luck — flagged in the sync for the zoneweaver session.
		previous = childPrevious
	}

	// pre[] hooks → methods → post[] hooks: DIRECT children of the
	// orchestration parent, one linear chain in document order. Response-only
	// entries (winrm skips, method_not_executable) land in task_chain[] at
	// their document position and never become tasks.
	for i := range walk {
		if walk[i].operation == "" {
			entry := map[string]any{"step": walk[i].step}
			for key, value := range walk[i].stepInfo {
				entry[key] = value
			}
			chain = append(chain, entry)
			continue
		}
		extra := walk[i].extra
		if finalOwner == "walk" && i == lastRealWalk {
			extra["final"] = true
		}
		stepMeta, ferr := childMetadata(v, extra)
		if ferr != nil {
			return nil, nil, ferr
		}
		child, cerr := s.createChainTask(ctx, machine.Name, walk[i].operation,
			stepMeta, previous, parentID, createdBy)
		if cerr != nil {
			return nil, nil, cerr
		}
		if walk[i].step != "" {
			entry := map[string]any{"step": walk[i].step, "task_id": child.ID}
			for key, value := range walk[i].stepInfo {
				entry[key] = value
			}
			chain = append(chain, entry)
		}
		previous = &child.ID
	}

	// SYNCBACK (folders[].syncback — Mark's ruling 2026-07-12, replacing his
	// Hosts.rb results hack) — the walk's closing bracket by document
	// structure: one machine_syncback per flagged folder under the syncback
	// sub-parent, gated on the previous chain element. winrm guests skip the
	// bracket whole — response-only, like the opening one.
	if isWinRM && len(syncbackFolders) > 0 {
		chain = append(chain, map[string]any{
			"step": "syncback_skipped_winrm", "folder_count": len(syncbackFolders),
		})
	}
	if !isWinRM {
		if syncbackChain, serr := s.buildSyncbackChain(ctx, machine.Name, v,
			previous, parentID, createdBy, finalOwner == "syncback"); serr != nil {
			return nil, nil, serr
		} else if syncbackChain != nil {
			chain = append(chain, syncbackChain...)
			// Advance the chain cursor to the syncback TAIL (last_task_id —
			// the bracket's true tail; the parent anchor completes instantly)
			// so the key-rotation child below genuinely follows the closing
			// bracket instead of racing it.
			if last, ok := syncbackChain[0]["last_task_id"].(string); ok && last != "" {
				lastID := last
				previous = &lastID
			}
		}
	}

	// KEY ROTATION (machine_key_rotate — key_rotate proposal, sync
	// 2026-07-17): when the document sets settings.vagrant_ssh_insert_key —
	// read via docEnabled, the same on/true/1/yes vocabulary the method gates
	// use (Hosts.rb reads the raw truthy; docEnabled keeps this agent's one
	// enabled-word set) — and the communicator is not winrm, ONE child chained
	// after the syncback bracket adopts the box's rotated key into the
	// working copy. It NEVER carries final: the whole-walk stamp stays on the
	// document walk's last task (finalOwner above), never on this
	// bookkeeping child. winrm guests get the response-only skip entry
	// (no ssh, no SFTP pull — zoneweaver's named-skip shape).
	settings := v.config.Section("settings")
	if docEnabled(settings["vagrant_ssh_insert_key"]) {
		if isWinRM {
			chain = append(chain, map[string]any{"step": "key_rotate_skipped_winrm"})
		} else {
			rotateKeyPath, _ := settings["vagrant_user_private_key_path"].(string)
			rotateMeta, merr := childMetadata(v, map[string]any{"key_path": rotateKeyPath})
			if merr != nil {
				return nil, nil, merr
			}
			rotateTask, terr := s.createChainTask(ctx, machine.Name, machines.OpKeyRotate,
				rotateMeta, previous, parentID, createdBy)
			if terr != nil {
				return nil, nil, terr
			}
			chain = append(chain, map[string]any{"step": "key_rotate", "task_id": rotateTask.ID})
			previous = &rotateTask.ID
		}
	}

	// THE PIPELINE-OWNED POWER CYCLE (MARK'S EXECUTION RULING, sync
	// 2026-07-18 — remove-on-completion + the reconciled
	// zones.post_provision_boot vocabulary): AFTER the whole-walk stamp (it
	// rode the walk's final task above), a machine flagged for transport
	// removal — settings.remove_transport_on_completion or any networks[]
	// entry's remove_on_completion (absent = this agent's ruled default
	// FALSE) — gets stop → machine_transport_remove → start as pipeline
	// steps, so the removal takes effect immediately. settings.post_provision_boot
	// (the cycle-after-provisioning knob — rehomed from zones, sync 2026-07-19)
	// triggers the SAME stop→start cycle without the removal step — reused,
	// never a second sequencing. The post-cycle boot gates on NOTHING: no
	// wait_ssh, no reconnect check — the transport is gone by design and the
	// run is COMPLETE at the boot.
	removalFlagged := machines.TransportRemovalFlagged(v.config)
	if removalFlagged || docEnabled(v.config.Section("vbox")["post_provision_boot"]) {
		stopTask, terr := s.createChainTask(ctx, machine.Name, machines.OpStop,
			nil, previous, parentID, createdBy)
		if terr != nil {
			return nil, nil, terr
		}
		chain = append(chain, map[string]any{"step": "post_provision_stop", "task_id": stopTask.ID})
		previous = &stopTask.ID
		if removalFlagged {
			removeTask, rerr := s.createChainTask(ctx, machine.Name, machines.OpTransportRemove,
				nil, previous, parentID, createdBy)
			if rerr != nil {
				return nil, nil, rerr
			}
			chain = append(chain, map[string]any{"step": "transport_remove", "task_id": removeTask.ID})
			previous = &removeTask.ID
		}
		bootTask, berr := s.createChainTask(ctx, machine.Name, machines.OpStart,
			nil, previous, parentID, createdBy)
		if berr != nil {
			return nil, nil, berr
		}
		chain = append(chain, map[string]any{"step": "post_provision_boot", "task_id": bootTask.ID})
	}

	// The narrate-skip and run-directive records land on the orchestration
	// parent's metadata (the POST /provision response carries them too).
	if len(skippedMethods) > 0 || len(skippedPlaybooks) > 0 {
		doc := map[string]any{"ip": v.ip, "port": v.port}
		if len(skippedMethods) > 0 {
			doc["skipped_methods"] = skippedMethods
		}
		if len(skippedPlaybooks) > 0 {
			doc["skipped_playbooks"] = skippedPlaybooks
		}
		raw, merr := json.Marshal(doc)
		if merr != nil {
			return nil, nil, merr
		}
		if uerr := s.tasks.Store().UpdateMetadata(ctx, parentID, string(raw)); uerr != nil {
			slog.Warn("record walk skips on orchestration parent",
				"task_id", parentID, "error", uerr)
		}
	}
	return chain, skippedMethods, nil
}

// buildSyncbackChain queues the syncback parent + one machine_syncback child
// per flagged folder (nil when the document flags none). Shared by the
// provision walk's closing bracket and the ad-hoc sync handler. stampFinal
// marks the LAST child final: true — the whole-walk stamp rides it when the
// syncback closes a provision walk; the ad-hoc handler never stamps.
func (s *Server) buildSyncbackChain(ctx context.Context, machineName string,
	v *provisionValidation, previous *string, parentID, createdBy string, stampFinal bool,
) ([]map[string]any, error) {
	syncbackFolders := machines.SyncbackFolders(machines.ProvisionerFolders(v.provisioner))
	if len(syncbackFolders) == 0 {
		return nil, nil
	}
	parentMeta, err := json.Marshal(map[string]any{"total_folders": len(syncbackFolders)})
	if err != nil {
		return nil, err
	}
	metadata := string(parentMeta)
	syncbackParent, err := s.createChainTask(ctx, machineName, machines.OpSyncbackParent,
		&metadata, previous, parentID, createdBy)
	if err != nil {
		return nil, err
	}
	childPrevious := &syncbackParent.ID
	for i := range syncbackFolders {
		extra := map[string]any{"folder": syncbackFolders[i]}
		if stampFinal && i == len(syncbackFolders)-1 {
			extra["final"] = true
		}
		folderMeta, ferr := childMetadata(v, extra)
		if ferr != nil {
			return nil, ferr
		}
		child, cerr := s.createChainTask(ctx, machineName, machines.OpSyncbackFolder,
			folderMeta, childPrevious, syncbackParent.ID, createdBy)
		if cerr != nil {
			return nil, cerr
		}
		childPrevious = &child.ID
	}
	// last_task_id = the LAST child — the chain's true tail (the parent
	// anchor completes instantly); the response reports it.
	return []map[string]any{{
		"step": "syncback_parent", "task_id": syncbackParent.ID,
		"folder_count": len(syncbackFolders), "last_task_id": *childPrevious,
	}}, nil
}

// startProvisionPipeline creates the provision orchestration parent and its
// chain — handleProvisionMachine's core, shared with the provision-on-start
// hook (machines.provision_on_start). A chain-build failure cancels the
// half-built parent before the error returns.
func (s *Server) startProvisionPipeline(ctx context.Context, machine *machines.Machine,
	validation *provisionValidation, skipBoot bool, createdBy string,
) (parentID string, chain []map[string]any, skippedMethods []string, err error) {
	metadata, err := json.Marshal(map[string]any{
		"ip": validation.ip, "port": validation.port,
	})
	if err != nil {
		return "", nil, nil, err
	}
	metadataStr := string(metadata)
	parent, err := s.tasks.Store().Create(ctx, &tasks.NewTask{
		MachineName: machine.Name,
		Operation:   machines.OpProvisionOrchestration,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   createdBy,
		Metadata:    &metadataStr,
		Parent:      true,
	})
	if err != nil {
		return "", nil, nil, err
	}

	chain, skippedMethods, err = s.buildProvisionChain(ctx, machine, validation, skipBoot, parent.ID, createdBy)
	if err != nil {
		if _, cerr := s.tasks.Cancel(ctx, parent.ID); cerr != nil {
			slog.Warn("cancel half-built provision chain", "task_id", parent.ID, "error", cerr)
		}
		return "", nil, nil, err
	}
	return parent.ID, chain, skippedMethods, nil
}

// provisionOnStartPipeline queues the full provision pipeline for a start
// request when machines.provision_on_start applies — the machine's VERY
// FIRST start only (Mark's semantics 2026-07-07): a stored provisioner
// document, never provisioned. Anything that disqualifies the machine (no
// document, already provisioned, no transport, chain failure) answers false
// and the caller boots plainly — auto-provisioning must never block a start.
func (s *Server) provisionOnStartPipeline(ctx context.Context, machine *machines.Machine,
	createdBy string,
) (parentID string, ok bool) {
	if !s.cfg.Machines.ProvisionOnStart {
		return "", false
	}
	validation, problem := validateProvisionRequest(machine)
	if problem != "" {
		slog.Info("provision_on_start skipped — plain start queued",
			"machine", machine.Name, "reason", problem)
		return "", false
	}
	if machines.HasProvisionedBefore(validation.config) {
		return "", false
	}
	if problem := resolveTransport(ctx, machine, validation); problem != "" {
		slog.Info("provision_on_start skipped — plain start queued",
			"machine", machine.Name, "reason", problem)
		return "", false
	}
	// Host-hooks confirmation is an INTERACTIVE gate — auto-provisioning
	// never answers it, so the machine boots plainly and POST /provision
	// carries the confirmation flow.
	if problem, needsConfirmation := s.hostHooksPreflight(ctx, machine,
		validation, false); problem != "" || needsConfirmation {
		slog.Info("provision_on_start skipped — plain start queued (host hooks need confirmation or the gate is off)",
			"machine", machine.Name)
		return "", false
	}
	parent, _, _, err := s.startProvisionPipeline(ctx, machine, validation, false, createdBy)
	if err != nil {
		slog.Error("provision_on_start pipeline failed — plain start queued",
			"machine", machine.Name, "error", err)
		return "", false
	}
	slog.Info("provision_on_start: first start runs the provision pipeline",
		"machine", machine.Name, "parent_task_id", parent)
	return parent, true
}
