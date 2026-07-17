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
	"vnc", "acpi", "xhci", "autoboot", "guest_agent", "boot_order", "vbox", "hardware",
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

// applyModifyNotes handles the notes field (the base's immediate DB update:
// falsy clears). False return = response already written.
func (s *Server) applyModifyNotes(w http.ResponseWriter, r *http.Request, machineName string, body map[string]any) bool {
	value := body["notes"]
	var notes *string
	if text, ok := value.(string); ok && text != "" {
		notes = &text
	} else if value != nil {
		if _, ok := value.(string); !ok {
			taskError(w, http.StatusBadRequest, "notes must be a string or null")
			return false
		}
	}
	if err := s.machines.SetNotes(r.Context(), machineName, notes); err != nil {
		slog.Error("update machine notes", "machine", machineName, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to update machine notes")
		return false
	}
	return true
}

// applyModifyTags handles the tags field (the base's immediate DB update:
// non-array clears; this agent's empty-clears convention matches its own
// tags endpoint). False return = response already written.
func (s *Server) applyModifyTags(w http.ResponseWriter, r *http.Request, machineName string, body map[string]any) bool {
	tags := []string{}
	if list, ok := body["tags"].([]any); ok {
		for _, entry := range list {
			if tag, tok := entry.(string); tok && tag != "" {
				tags = append(tags, tag)
			}
		}
	}
	var stored json.RawMessage
	if len(tags) > 0 {
		encoded, err := json.Marshal(tags)
		if err != nil {
			slog.Error("serialize machine tags", "error", err)
			taskError(w, http.StatusInternalServerError, "Failed to update machine tags")
			return false
		}
		stored = encoded
	}
	if err := s.machines.SetTags(r.Context(), machineName, stored); err != nil {
		slog.Error("update machine tags", "machine", machineName, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to update machine tags")
		return false
	}
	return true
}

// applyModifyBootPriority stores settings.boot_priority into the machine's
// spec (1-100; DB-immediate — orchestration reads it, VirtualBox never does).
// False return = response already written.
func (s *Server) applyModifyBootPriority(w http.ResponseWriter, r *http.Request,
	machine *machines.Machine, body map[string]any,
) bool {
	priority := int(machines.DocInt(body["boot_priority"], 0))
	if priority < 1 || priority > 100 {
		taskError(w, http.StatusBadRequest, "boot_priority must be 1-100")
		return false
	}
	spec, err := machines.ParseSpec(machine)
	if err != nil {
		taskError(w, http.StatusBadRequest,
			"Only machines this agent created carry a spec to hold boot_priority (discovered VM)")
		return false
	}
	if spec.Settings == nil {
		spec.Settings = map[string]any{}
	}
	spec.Settings["boot_priority"] = priority
	raw, err := json.Marshal(spec)
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to update boot priority")
		return false
	}
	serverID := machines.DocString(spec.Settings["server_id"], "")
	if err := s.machines.SetSpec(r.Context(), machine.Name, raw, serverID); err != nil {
		slog.Error("update boot priority", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to update boot priority")
		return false
	}
	return true
}

// applyModifySnapshots handles the snapshots field — the per-machine
// snapshot retention override (zoneweaver's setSnapshotPolicy contract,
// DB-immediate): an object with a valid type stores verbatim into
// configuration.snapshots (unknown extra keys ride along, ignored by the
// rotation service); null or a typeless object clears back to the agent
// default. False return = response already written.
func (s *Server) applyModifySnapshots(w http.ResponseWriter, r *http.Request, machineName string, body map[string]any) bool {
	value := body["snapshots"]
	var policy map[string]any
	if value != nil {
		object, ok := value.(map[string]any)
		if !ok {
			taskError(w, http.StatusBadRequest, "snapshots must be an object or null")
			return false
		}
		kind, _ := object["type"].(string)
		switch kind {
		case "":
			// A typeless object clears, exactly like null (the base's rule).
		case "none", "simple", "age", "rotation":
			policy = object
		default:
			taskError(w, http.StatusBadRequest,
				"snapshots.type must be one of none, simple, age, rotation")
			return false
		}
	}
	if err := s.machines.SetSnapshotPolicy(r.Context(), machineName, policy); err != nil {
		slog.Error("update snapshot policy", "machine", machineName, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to update snapshot policy")
		return false
	}
	slog.Info("snapshot policy updated", "machine", machineName,
		"cleared", policy == nil, "by", auth.FromContext(r.Context()).Name)
	return true
}

// applyModifyCredentials merges the credentials family into
// configuration.settings key-by-key (the provisioner document's DB-immediate
// rule, one level deeper — the rest of settings survives). Empty string or
// null deletes a key. False return = response already written.
func (s *Server) applyModifyCredentials(w http.ResponseWriter, r *http.Request, machineName string, body map[string]any) bool {
	updates := map[string]any{}
	for _, field := range credentialFields {
		value, ok := body[field]
		if !ok {
			continue
		}
		if value != nil {
			if _, sok := value.(string); !sok {
				taskError(w, http.StatusBadRequest, field+" must be a string or null")
				return false
			}
		}
		updates[field] = value
	}
	if err := s.machines.MergeSettingsKeys(r.Context(), machineName, updates); err != nil {
		slog.Error("update ssh credentials", "machine", machineName, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to update SSH credentials")
		return false
	}
	slog.Info("ssh credentials updated", "machine", machineName,
		"by", auth.FromContext(r.Context()).Name)
	return true
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
