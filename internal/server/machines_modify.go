package server

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
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
	"vnc", "acpi", "xhci", "autoboot", "boot_order", "vbox",
	"add_nics", "remove_nics", "add_disks", "remove_disks",
	"add_cdroms", "remove_cdroms", "cloud_init", "provisioner", "notes", "tags",
	"boot_priority",
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

// handleModifyMachine executes the modify mechanism end to end.
func (s *Server) handleModifyMachine(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	body := map[string]any{}
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
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
	hasOther := false
	for _, field := range modifyChangeFields {
		if field == "notes" || field == "tags" || field == "boot_priority" {
			continue
		}
		if present(field) {
			hasOther = true
			break
		}
	}
	if !hasOther {
		modifyCompleted(w, machine.Name, "Machine metadata updated successfully.")
		return
	}

	// The provisioner document stores immediately (the base's rule: available
	// to /provision without waiting for the task).
	if present("provisioner") {
		provisioner, ok := body["provisioner"].(map[string]any)
		if !ok || len(provisioner) == 0 {
			taskError(w, http.StatusBadRequest,
				"provisioner must be a non-empty object — the Hosts.yml host-entry document")
			return
		}
		if err := s.machines.MergeConfigurationSections(r.Context(), machine.Name,
			map[string]any{"provisioner": provisioner}); err != nil {
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
	// body verbatim (the base's rule). VirtualBox applies them only to a
	// powered-off machine; the executor enforces that.
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
