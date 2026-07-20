package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// PUT /machines/{machineName} — zoneweaver's modifyZone ported whole
// (ZoneModificationController.js): one endpoint, three change classes.
// notes/tags apply immediately (registry-only); the provisioner document
// stores immediately (configuration.provisioner — the next /provision
// consumes it); every infrastructure field queues a machine_modify task and
// the answer carries requires_restart: true. Changed-fields-only body — the
// task metadata is the body verbatim, exactly like the base.

// modifyChangeFields is the base's changeFields list verbatim: at least one
// must be present or the request is a 400.
var modifyChangeFields = []string{
	"ram", "vcpus", "bootrom", "hostbridge", "diskif", "netif", "os_type",
	"vnc", "acpi", "xhci", "autoboot", "guest_agent", "boot_order", "vbox", "utm",
	"add_nics", "remove_nics", "nics", "add_disks", "remove_disks",
	"add_cdroms", "remove_cdroms", "add_controllers", "remove_controllers",
	"cloud_init", "provisioner", "notes", "tags",
	"boot_priority", "snapshots",
	"vagrant_user", "vagrant_user_pass", "vagrant_user_private_key_path",
}

// credentialFields is the SSH credentials family (configuration.settings keys
// — the vocabulary ExtractCredentials and the SSH terminal read). DB-immediate
// like the provisioner document: the fix for machines created without wizard
// credentials, which could otherwise never SSH.
var credentialFields = []string{
	"vagrant_user", "vagrant_user_pass", "vagrant_user_private_key_path",
}

// modifyCompleted answers the base's DB-only early returns: the change is
// already applied, nothing queued, no restart needed.
func modifyCompleted(w http.ResponseWriter, machineName, message string) {
	writeJSON(w, map[string]any{
		"success":          true,
		"machine_name":     machineName,
		"operation":        machines.OpModify,
		"status":           tasks.StatusCompleted,
		"message":          message,
		"requires_restart": false,
	})
}

// accrueModifyChanges implements the accrue half of PUT: when the machine's
// VM exists and is NOT powered off (running/paused/saved/transitioning), the
// remaining body merges into configuration.pending_changes and the answer is
// pending_power_cycle. True = response written. Body must already be stripped
// of the DB-immediate fields; "provisioner" is stripped here (stored above).
func (s *Server) accrueModifyChanges(w http.ResponseWriter, r *http.Request,
	machine *machines.Machine, body map[string]any, resourceWarnings []map[string]any,
) bool {
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		return false
	}
	info, err := vbox.ShowVMInfo(r.Context(), exe, machine.VBoxTarget())
	if err != nil {
		// No VM yet — the queued task answers that case honestly.
		return false
	}
	switch machines.MapVBoxState(info.State) {
	case machines.StatusStopped, machines.StatusAborted:
		return false
	}

	pendingDoc := map[string]any{}
	for key, value := range body {
		if key == "provisioner" || key == "notes" || key == "tags" ||
			key == "boot_priority" || key == "snapshots" {
			continue
		}
		pendingDoc[key] = value
	}
	if len(pendingDoc) == 0 {
		return false
	}
	// PUT-time dry validation — unknown knobs reject NOW, not at apply time.
	if verr := machines.ValidateModifyDocument(pendingDoc, info); verr != nil {
		taskError(w, http.StatusBadRequest, verr.Error())
		return true
	}

	merged, merr := s.machines.MergePendingChanges(r.Context(), machine.Name, pendingDoc)
	if merr != nil {
		slog.Error("merge pending changes", "machine", machine.Name, "error", merr)
		taskError(w, http.StatusInternalServerError, "Failed to store pending changes")
		return true
	}
	slog.Info("machine changes accrued for next power cycle", "machine", machine.Name,
		"keys", len(merged), "by", auth.FromContext(r.Context()).Name)
	response := map[string]any{
		"success":          true,
		"machine_name":     machine.Name,
		"operation":        machines.OpModify,
		"status":           "pending_power_cycle",
		"requires_restart": true,
		"pending_changes":  merged,
		"message":          "Machine is not powered off — changes stored and will apply at the next agent-driven power cycle (stop, start, or restart). DELETE /machines/{name}/pending-changes cancels them.",
	}
	if len(resourceWarnings) > 0 {
		response["resource_warnings"] = resourceWarnings
	}
	writeJSON(w, response)
	return true
}

// handleModifyMachine executes the modify mechanism end to end.
//
//	@Summary		Modify machine configuration
//	@Description	Minimum role: operator (the machine-modify capability token). The zoneweaver modify mechanism, changed-fields-only body with three change classes. (1) DB-immediate: notes/tags (registry-only), boot_priority (spec settings), and the SSH CREDENTIALS family — vagrant_user/vagrant_user_pass/vagrant_user_private_key_path merge key-by-key into configuration.settings (the rest of settings survives; empty string or null DELETES a key), instantly live for the SSH terminal, SFTP, and provisioning pipeline — the way to give any machine (wizard-less creates, discovered VMs) working SSH. Credential values never enter task metadata. (2) provisioner: the PROVISIONER DOCUMENT stored verbatim into configuration.provisioner — a Hosts.yml host entry (folders[], provisioning.ansible.playbooks in object or list form, vars, roles[], secrets, pre_tasks/post_tasks, ssh_port); an immediate DB-only update the next /provision consumes; create's finalize auto-fills it from the rendered package template and PUT overrides it whole. When the document carries settings.consoleport it must be an integer in 1025-65535 (number or numeric string — the value feeds VRDE's TCP/Ports); anything else answers 400 `consoleport <value> is outside the valid console port range (1025-65535)` BEFORE the document stores (the converged pre-flight, sync 2026-07-17; an absent consoleport is fine). The TOP-LEVEL vcpus field, when present, must be a WHOLE number >= 1 (integral floats like 2.0 pass; 2.5, zero, negatives, and non-numerics refuse); anything else answers 400 `vcpus <value> is not a valid vCPU count (whole number >= 1)` BEFORE ANY field applies — even the DB-immediate ones (the same converged pre-flight; an absent vcpus is fine). (3) infrastructure fields: against a POWERED-OFF machine they queue a machine_modify task (requires_restart: true) exactly as before; against ANYTHING ELSE (running/paused/saved/transitioning — VirtualBox only modifies powered-off machines) the ACCRUE-CHANGES contract applies: the fields are DRY-VALIDATED (unknown vbox knobs and malformed serial/parallel entries reject at the PUT), merged into the machine's pending set (per top-level key the last edit wins; vbox merges per section.key so successive edits of different knobs coexist), and the answer is status pending_power_cycle with the merged pending_changes document and NO task_id. Pending changes apply automatically at the next agent-driven power transition — stop chains the modify after the power-off, start runs it FIRST (start depends on it: a bad pending value fails the boot honestly rather than silently skipping), restart slots it between stop and start, and bulk start/stop chain the same way. A successful apply clears the set; a failed one keeps it pending. DELETE /machines/{name}/pending-changes cancels the whole set. Pure-GUI stop+start never passes through the agent, so pending changes wait for the next agent-driven transition. Translations from the base vocabulary: ram→memory, vcpus→cpus, os_type→ostype, vnc→VRDE on/off, acpi/xhci→--acpi/--usb-xhci, autoboot→autostart, bootrom→firmware (efi when the value names EFI, else bios), hostbridge→chipset (i440fx→piix3), netif (virtio|e1000)→every configured adapter's hardware type. diskif and complex CPU topology have no modifyvm analog — reported as skipped in task output, never silently accepted. add_nics land on the first free adapters (bridged; global_nic = the bridge interface, mac_addr honored; vlan_id/allowed_address have no analog and are noted); remove_nics name adapter numbers 1-8 — on agent-created machines adapter 1 is the reserved NAT (egress) and document networks sit on 2+, so removing adapter 1 cuts the guest's internet. add_disks create media under the machine's working directory (volume_name/size/sparse) or attach an existing file by path, at the next free SATA port; add_cdroms attach ISOs by raw path or by cached-ISO filename (iso — resolved through the artifact registry). remove_disks/remove_cdroms name SATA PORT numbers 1 and up — port 0 is the boot medium and is refused; detached files are PRESERVED (the base never destroys the volume). cloud_init keys update the machine's guest properties. When only DB-immediate fields changed, the answer is status completed with requires_restart: false and no task. THE TYPED DISK SPEC (disks.boot.type — see POST /machines) governs disks at CREATE, and add_disks[] SPEAKS THE SAME TYPED ENTRIES (the modify cut, sync 2026-07-18): type REQUIRED (image|blank), per-type keys and the frozen refusal strings with the add_disks[<n>] prefix (1-based), answered AT THE PUT on both the queue and accrue paths; blank entries are stamped and honor directory, image entries pre-check existence and holders at task time. remove_disks/add_cdroms/remove_cdroms are unchanged, and existing machines' stored documents are never re-read for disks (no migration). UTM MACHINES (the scripting-API subset, machine STOPPED): ram/vcpus apply via the config API, utm.notes and utm.qemu_args[] apply verbatim, add_nics become vmnet QEMU-arg pairs (global_nic → vmnet-bridged+ifname, absent → vmnet-shared; mac_addr honored, else a random MAC), remove_nics name netdev ids (strings like net2), and nics[] applies mac only (adapter = the 0-based interface index); every drive family (add/remove disks, cdroms, controllers) is REFUSED — UTM's scripting API does not expose drives — and os_type/vnc/acpi/xhci/bootrom/hostbridge/netif/diskif/boot_order/autoboot/guest_agent/cloud_init/vbox narrate as skipped (no UTM scripting analog).
//	@Tags			Machine Management
//	@Accept			json
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Param			request	body	map[string]interface{}	true	"Changed fields only — at least one of the modify vocabulary"
//	@Success		200	{object}	map[string]interface{}	"Modification queued (infrastructure fields) or applied (DB-immediate fields only)"
//	@Failure		400	"No modification fields specified, an invalid field value, a provisioner document whose settings.consoleport is out of range or non-numeric (the exact refusal: `consoleport <value> is outside the valid console port range (1025-65535)` — the converged pre-flight, sync 2026-07-17), a top-level vcpus that is not a whole number >= 1 (the exact refusal: `vcpus <value> is not a valid vCPU count (whole number >= 1)` — same converged pre-flight, refused before anything applies; integral floats like 2.0 pass), or Insufficient resources ({error, details[]} — the resource validation rejection)"
//	@Failure		404	"Machine not found"
//	@Router			/machines/{machineName} [put]
func (s *Server) handleModifyMachine(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	// The body bytes are read ONCE and unmarshaled twice: the map view drives
	// the field logic, the raw view carries the provisioner document's OWN
	// bytes into storage (a re-marshaled map would alphabetize its key order
	// — the document is the program). decodeBody's empty-body-as-empty-object
	// contract is preserved.
	bodyBytes, rerr := io.ReadAll(r.Body)
	if rerr != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	body := map[string]any{}
	rawBody := map[string]json.RawMessage{}
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		if err := json.Unmarshal(bodyBytes, &body); err != nil {
			taskError(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		if err := json.Unmarshal(bodyBytes, &rawBody); err != nil {
			taskError(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
	}

	present := func(field string) bool {
		_, ok := body[field]
		return ok
	}
	hasChanges := false
	for _, field := range modifyChangeFields {
		if present(field) {
			hasChanges = true
			break
		}
	}
	if !hasChanges {
		taskError(w, http.StatusBadRequest, "No modification fields specified")
		return
	}

	// vcpus pre-flight (converged, sync 2026-07-17 — zoneweaver's proposal,
	// ACKED): PUT's vcpus rides TOP-LEVEL in the modify body; when present it
	// must be a whole number >= 1 (integral floats like 2.0 pass). Refused
	// BEFORE the DB-immediate fields apply, so a bad request changes nothing.
	if value, ok := body["vcpus"]; ok {
		if problem := machines.VCPUProblem(value); problem != "" {
			taskError(w, http.StatusBadRequest, problem)
			return
		}
	}
	// Typed add_disks pre-flight (the modify cut, sync 2026-07-18): the frozen
	// refusal strings answer at the PUT on both the queue and accrue paths.
	if list, ok := body["add_disks"].([]any); ok {
		if verr := machines.ValidateAddDisks(list); verr != nil {
			taskError(w, http.StatusBadRequest, verr.Error())
			return
		}
	}

	// notes/tags/boot_priority apply immediately (DB only, no task —
	// boot_priority is orchestration metadata in the spec, the base's
	// zonecfg-attr analog; VirtualBox never sees it).
	if present("notes") && !s.applyModifyNotes(w, r, machine.Name, body) {
		return
	}
	if present("tags") && !s.applyModifyTags(w, r, machine.Name, body) {
		return
	}
	if present("boot_priority") && !s.applyModifyBootPriority(w, r, machine, body) {
		return
	}
	// The per-machine snapshot retention policy is DB-immediate too
	// (zoneweaver's rule — the rotation service reads it live each tick).
	if present("snapshots") && !s.applyModifySnapshots(w, r, machine.Name, body) {
		return
	}
	// The SSH credentials family joins the DB-immediate class: merged into
	// configuration.settings, live for the terminal/SFTP/pipeline instantly.
	credentialsChanged := false
	for _, field := range credentialFields {
		if present(field) {
			credentialsChanged = true
			break
		}
	}
	if credentialsChanged && !s.applyModifyCredentials(w, r, machine.Name, body) {
		return
	}
	// remove_on_completion flips ride nics[] entries but are DOCUMENT/settings
	// state, never VBox knobs (the converged flip wire, sync 2026-07-18) —
	// extracted and applied DB-immediately; the keys strip so the
	// infrastructure path never sees them, and flip-only entries drop whole
	// (a flip-only PUT queues nothing).
	if !s.applyRemoveOnCompletionFlips(w, r, machine, body) {
		return
	}
	immediate := map[string]bool{"notes": true, "tags": true, "boot_priority": true, "snapshots": true}
	for _, field := range credentialFields {
		immediate[field] = true
	}
	hasOther := false
	for _, field := range modifyChangeFields {
		if immediate[field] {
			continue
		}
		if present(field) {
			hasOther = true
			break
		}
	}
	if !hasOther {
		message := "Machine metadata updated successfully."
		if credentialsChanged && !present("notes") && !present("tags") && !present("boot_priority") {
			message = "SSH credentials updated successfully."
		}
		modifyCompleted(w, machine.Name, message)
		return
	}

	// The provisioner document stores immediately (the base's rule: available
	// to /provision without waiting for the task).
	if present("provisioner") {
		// The RAW request bytes store — key order is the document's program
		// order. Validation decodes one object level only.
		provisionerRaw := rawBody["provisioner"]
		provisionerDoc := map[string]json.RawMessage{}
		if uerr := json.Unmarshal(provisionerRaw, &provisionerDoc); uerr != nil || len(provisionerDoc) == 0 {
			taskError(w, http.StatusBadRequest,
				"provisioner must be a non-empty object — the Hosts.yml host-entry document")
			return
		}
		// consoleport pre-flight (converged, sync 2026-07-17): the modify body
		// carries settings.consoleport only inside the provisioner document
		// (merged sections) — when present it must be an integer 1025-65535
		// (number or numeric string), the same refusal the create pre-flight
		// answers, BEFORE the document stores. Absent stays absent.
		if provisionerMap, mok := body["provisioner"].(map[string]any); mok {
			if settings, sok := provisionerMap["settings"].(map[string]any); sok {
				if value, vok := settings["consoleport"]; vok {
					if problem := machines.ConsolePortProblem(value); problem != "" {
						taskError(w, http.StatusBadRequest, problem)
						return
					}
				}
			}
		}
		if err := s.machines.MergeConfigurationSections(r.Context(), machine.Name,
			map[string]any{"provisioner": provisionerRaw}); err != nil {
			slog.Error("store provisioner document", "machine", machine.Name, "error", err)
			taskError(w, http.StatusInternalServerError, "Failed to store provisioner configuration")
			return
		}
		slog.Info("provisioner configuration updated", "machine", machine.Name,
			"by", auth.FromContext(r.Context()).Name)
		otherThanProvisioner := false
		for _, field := range modifyChangeFields {
			if field == "provisioner" {
				continue
			}
			if present(field) {
				otherThanProvisioner = true
				break
			}
		}
		if !otherThanProvisioner {
			modifyCompleted(w, machine.Name, "Provisioner configuration updated successfully.")
			return
		}
	}

	// Pre-flight resource validation on the changed fields (add_disks/ram/
	// vcpus), excluding this machine from committed sums — the base's modify
	// hook.
	resourceErrors, resourceWarnings := s.validateModificationResources(r.Context(), body, machine.Name)
	if len(resourceErrors) > 0 {
		insufficientResources(w, resourceErrors)
		return
	}

	// Infrastructure changes queue the machine_modify task — metadata is the
	// body verbatim (the base's rule), minus the already-applied credentials
	// (a password must never land in the task table) and the already-applied
	// snapshot policy (DB-immediate, not the executor's business).
	for _, field := range credentialFields {
		delete(body, field)
	}
	delete(body, "snapshots")

	// The accrue-changes contract (agreed in the sync 2026-07-09): VirtualBox
	// only modifies powered-off machines, so against anything else the PUT
	// ACCRUES into configuration.pending_changes instead of queueing a task
	// doomed to fail — applied by the chained modify at the next agent-driven
	// power cycle. Dry-validated here so bad keys reject at the PUT.
	if done := s.accrueModifyChanges(w, r, machine, body, resourceWarnings); done {
		return
	}
	metadata, err := json.Marshal(body)
	if err != nil {
		slog.Error("serialize modify metadata", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue machine modification task")
		return
	}
	metadataStr := string(metadata)
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: machine.Name,
		Operation:   machines.OpModify,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   auth.FromContext(r.Context()).Name,
		Metadata:    &metadataStr,
	})
	if err != nil {
		slog.Error("queue modify task", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue machine modification task")
		return
	}
	slog.Info("machine modification queued", "machine", machine.Name,
		"task_id", task.ID, "by", auth.FromContext(r.Context()).Name)
	response := map[string]any{
		"success":          true,
		"task_id":          task.ID,
		"machine_name":     machine.Name,
		"operation":        machines.OpModify,
		"status":           tasks.StatusPending,
		"message":          "Modification queued. The machine must be powered off for the task to apply; changes take effect on next boot.",
		"requires_restart": true,
	}
	if len(resourceWarnings) > 0 {
		response["resource_warnings"] = resourceWarnings
	}
	writeJSON(w, response)
}
