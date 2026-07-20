package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// handleCloneMachine clones a spec-carrying machine: the source spec with the
// caller's settings/overrides merged, network identity stripped, then the
// SAME create orchestration (the clone builds real infrastructure too).
//
//	@Summary		Clone a machine
//	@Description	Minimum role: operator. Spec-carrying machines only. Clones are DATA-COMPLETE BY DEFAULT (Mark's ruling, sync 2026-07-18: a clone carries the same data, every disk, never blank). TWO disk semantics via source: "current" (DEFAULT) runs ONE machine_clone_current task — VBoxManage clonevm copies EVERY attached disk's data into the clone's own folder (those copies stamp "clone" — the clone's own media, destroyed by its delete; referenced ISOs stay shared and unstamped), the clone gets a fresh provisioning ssh port-forward and VRDE off, MACs reinitialize, and the row lands with the identity-stripped spec — the source must be stopped unless snapshot names a source snapshot to clone from (linked=true makes a differencing clone against it); "template" is the EXPLICIT OPT-IN rebuild: the spec copy feeds the SAME create orchestration as POST /machines — a fresh build from the original template, additional disks recreated per their typed declaration, no data copy (response shape identical to create, plus source_machine). settings.hostname is required (a clone must not reuse the source hostname); domain and everything else default from the source spec; overrides (memory, vcpus, …) merge into settings; consoleport and server_id never survive (prefix mode requires a fresh server_id in settings). Cloned networks lose mac/address/gateway/netmask/dns so source and clone can never collide; provisional entries clone as dhcp4 with NO address — the provisioning dhcpd allocates on first boot (the static clone-time allocator died; converged clone conformance, sync 2026-07-18). Resource validation runs first (400 Insufficient resources; storage is skipped for source=current — the footprint is the source's current usage, unknowable from the spec). UTM MACHINES: source=current copies the current state via utm export → import (the source must be STOPPED; fresh MAC + fresh ssh forward on the emulated interface) — snapshot/linked are VirtualBox mechanisms and answer 400 on utm; source=template rebuilds through the same create orchestration.
//	@Tags			Machine Management
//	@Accept			json
//	@Produce		json
//	@Param			machineName	path	string	true	"The SOURCE machine"
//	@Param			request	body		map[string]interface{}	true	"Clone request: name, settings (hostname required), overrides, and disk source"
//	@Success		200	{object}	map[string]interface{}	"Clone create orchestration queued (the row lands at the finalize child); source=current answers {task_id, operation: machine_clone_current, ...} (+start_task_id) instead"
//	@Failure		400	"Missing settings.hostname, invalid name, source has no creation spec, or the source's provisioner/safe-ID/box no longer resolves"
//	@Failure		404	"Source machine not found"
//	@Failure		409	"Clone name, server_id, or working directory already in use"
//	@Router			/machines/{machineName}/clone [post]
func (s *Server) handleCloneMachine(w http.ResponseWriter, r *http.Request) {
	source := s.findMachine(w, r)
	if source == nil {
		return
	}
	if len(source.Spec) == 0 {
		taskError(w, http.StatusBadRequest,
			"Only machines this agent created can be cloned — this machine has no creation spec (discovered VM)")
		return
	}
	var body struct {
		Name             string         `json:"name"`
		Settings         map[string]any `json:"settings"`
		Overrides        map[string]any `json:"overrides"`
		StartAfterCreate bool           `json:"start_after_create"`
		// Source picks the disk semantics: "template" (default) re-runs the
		// source SPEC through create — a fresh build from the original
		// template; "current" copies the source's CURRENT disk state via
		// VBoxManage clonevm (the base's ZFS-snapshot clone semantics).
		Source string `json:"source"`
		// Snapshot/Linked apply to source=current: clone from a named source
		// snapshot, optionally as a linked (differencing) clone.
		Snapshot string `json:"snapshot"`
		Linked   bool   `json:"linked"`
	}
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	switch body.Source {
	case "", "template", "current":
	default:
		taskError(w, http.StatusBadRequest, `source must be "current" (data-complete clonevm, the default) or "template" (explicit spec rebuild)`)
		return
	}
	// Clones are DATA-COMPLETE by default (Mark's ruling, sync 2026-07-18: a
	// clone carries the same data, every disk, never blank) — template is the
	// explicit opt-in rebuild.
	if body.Source == "" {
		body.Source = "current"
	}
	if source.Hypervisor == machines.HypervisorUTM && (body.Snapshot != "" || body.Linked) {
		taskError(w, http.StatusBadRequest,
			"linked/snapshot clones are VirtualBox mechanisms — utm clones copy current state")
		return
	}
	if hostname, _ := body.Settings["hostname"].(string); hostname == "" {
		taskError(w, http.StatusBadRequest,
			"settings.hostname is required — a clone must not reuse the source hostname")
		return
	}

	spec, err := machines.ParseSpec(source)
	if err != nil {
		slog.Error("parse source machine spec", "machine", source.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to clone machine")
		return
	}
	if spec.Settings == nil {
		spec.Settings = map[string]any{}
	}
	delete(spec.Settings, "server_id")
	delete(spec.Settings, "consoleport")
	for key, value := range body.Settings {
		spec.Settings[key] = value
	}
	for key, value := range body.Overrides {
		spec.Settings[key] = value
	}
	stripCloneNetworks(spec.Networks)
	spec.StartAfterCreate = false

	cloneOK, cloneDiskWarnings := s.validateSpec(w, spec)
	if !cloneOK {
		return
	}
	name, status, problem := s.resolveMachineName(r.Context(), body.Name, spec)
	if problem != "" {
		taskError(w, status, problem)
		return
	}
	if _, gerr := s.machines.Get(r.Context(), name); gerr == nil {
		taskError(w, http.StatusConflict, "Machine "+name+" already exists in database")
		return
	} else if !errors.Is(gerr, machines.ErrNotFound) {
		taskError(w, http.StatusInternalServerError, "Failed to clone machine")
		return
	}

	// source=current: one clonevm task copies today's disk state — no create
	// orchestration (the disks come from the source VM, not the template).
	// Memory/CPU validate from the spec; storage is skipped (the clone's disk
	// footprint is the source's CURRENT usage, unknowable from the spec).
	if body.Source == "current" {
		if exe := machines.VBoxManagePath(r.Context()); exe != "" {
			if _, verr := vbox.ShowVMInfo(r.Context(), exe, name); verr == nil {
				taskError(w, http.StatusConflict, "Machine "+name+" already exists on the system")
				return
			}
		}
		if resourceErrors, _ := s.validateCreationResources(r.Context(),
			map[string]any{"settings": spec.Settings}); len(resourceErrors) > 0 {
			insufficientResources(w, resourceErrors)
			return
		}
		s.queueCloneCurrent(w, r, source, spec, name, body.Snapshot, body.Linked, body.StartAfterCreate)
		return
	}

	document, err := s.resolutionDocument(r.Context(), spec)
	if err != nil {
		taskError(w, http.StatusBadRequest, "Template render failed: "+err.Error())
		return
	}
	resourceErrors, resourceWarnings := s.validateCreationResources(r.Context(), document)
	if len(resourceErrors) > 0 {
		insufficientResources(w, resourceErrors)
		return
	}
	// The typed-disk warning rows join the clone response too.
	resourceWarnings = append(diskWarningRows(cloneDiskWarnings), resourceWarnings...)
	createdBy := auth.FromContext(r.Context()).Name
	parentID, subTasks, requiresDownload, _, err := s.queueCreateOrchestration(
		r.Context(), name, spec, document, body.StartAfterCreate, createdBy, nil)
	if err != nil {
		taskError(w, http.StatusBadRequest, err.Error())
		return
	}
	slog.Info("machine clone queued", "source", source.Name, "clone", name, "by", createdBy)
	response := map[string]any{
		"success":           true,
		"parent_task_id":    parentID,
		"machine_name":      name,
		"source_machine":    source.Name,
		"operation":         machines.OpCreateOrchestration,
		"status":            tasks.StatusPending,
		"message":           "Machine clone creation queued",
		"requires_download": requiresDownload,
		"sub_tasks":         subTasks,
	}
	if len(resourceWarnings) > 0 {
		response["resource_warnings"] = resourceWarnings
	}
	writeJSON(w, response)
}

// queueCloneCurrent queues the machine_clone_current task (+ optional chained
// start): VBoxManage clonevm copies the source's CURRENT disk state, the
// executor fixes identity (fresh ssh forward, VRDE off) and lands the row
// with the stripped spec.
func (s *Server) queueCloneCurrent(w http.ResponseWriter, r *http.Request,
	source *machines.Machine, spec *machines.Spec, name, snapshot string, linked, startAfter bool,
) {
	if linked && snapshot == "" {
		taskError(w, http.StatusBadRequest, "linked clones require a snapshot to link against")
		return
	}
	raw, err := json.Marshal(map[string]any{
		"source":   source.Name,
		"spec":     spec,
		"snapshot": snapshot,
		"linked":   linked,
	})
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to clone machine")
		return
	}
	metadata := string(raw)
	createdBy := auth.FromContext(r.Context()).Name
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: name,
		Operation:   machines.OpCloneCurrent,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   createdBy,
		Metadata:    &metadata,
	})
	if err != nil {
		slog.Error("queue clone task", "source", source.Name, "clone", name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to clone machine")
		return
	}
	response := map[string]any{
		"success":        true,
		"task_id":        task.ID,
		"machine_name":   name,
		"source_machine": source.Name,
		"operation":      machines.OpCloneCurrent,
		"status":         tasks.StatusPending,
		"message":        "Current-state clone task queued (VBoxManage clonevm)",
	}
	if startAfter {
		start, serr := s.createChainTask(r.Context(), name, machines.OpStart, nil, &task.ID, "", createdBy)
		if serr != nil {
			slog.Warn("queue clone start task", "clone", name, "error", serr)
		} else {
			response["start_task_id"] = start.ID
		}
	}
	slog.Info("current-state clone queued", "source", source.Name, "clone", name, "by", createdBy)
	writeJSON(w, response)
}

// stripCloneNetworks removes identity and addressing so source and clone can
// never collide (converged clone conformance, sync 2026-07-18): provisional
// entries clone as dhcp4 with NO address — the provisioning dhcpd allocates
// on first boot; the static clone-time allocator died with the ruling.
func stripCloneNetworks(networks []any) {
	for _, entry := range networks {
		network, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		delete(network, "mac")
		if provisional, _ := network["provisional"].(bool); provisional {
			delete(network, "address")
			network["dhcp4"] = true
			continue
		}
		for _, key := range []string{"address", "gateway", "netmask", "dns"} {
			delete(network, key)
		}
	}
}
