package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/provisioner"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// Machine creation — zoneweaver's createZone mechanism: POST /machines
// validates, resolves the name (server_id prefix rule), 409s against the DB
// AND the hypervisor, resolves the box against the template registry
// (missing template auto-chains its download), then queues a create
// ORCHESTRATION — a parent whose chained children build real infrastructure:
// machine_prepare (render + materialize — the SHI registry layer, queued
// ONLY when the spec names a provisioner package) → machine_create_storage →
// machine_create_config → machine_create_finalize (+ optional start).
// The provisioner reference is OPTIONAL — the base's create is
// provisioner-free (Mark's ruling 2026-07-07: a machine is just a machine;
// provisioning is optional, never a gate on existence); without one the
// chain builds straight from the spec and provisioning attaches later via
// PUT's provisioner store + /provision, the base's exact model.
// PUT /machines/{name} is the modify mechanism (machines_modify.go) — create
// DROPS any provisioner config in its body beyond the package reference;
// provisioning config arrives via PUT's provisioner store or the render.

// serverIDPattern is the numeric server_id vocabulary.
var serverIDPattern = regexp.MustCompile(`^\d{1,8}$`)

// createMachineRequest is the POST /machines body: an optional explicit name
// plus the creation spec (an OPTIONAL package reference + the document
// inputs — with a package they feed the render, without one they ARE the
// document).
type createMachineRequest struct {
	Name string `json:"name"`
	machines.Spec
}

// resolveMachineName settles the machine's name — the base's resolveZoneName:
// base = hostname.(machine_domain || domain); with machines.prefix_machine_names
// the server_id is REQUIRED (numeric, padded to 4, uniqueness-checked — never
// auto-assigned; GET /machines/ids/next feeds the caller) and the final name
// is <id>--<base>. An explicit name always wins (free-form, D-G).
func (s *Server) resolveMachineName(ctx context.Context, explicit string, spec *machines.Spec) (name string, status int, problem string) {
	if explicit != "" {
		if !validMachineName(explicit) {
			return "", http.StatusBadRequest, "Invalid machine name"
		}
		return explicit, 0, ""
	}

	hostname, _ := spec.Settings["hostname"].(string)
	domain, _ := spec.Settings["domain"].(string)
	if machineDomain, _ := spec.Settings["machine_domain"].(string); machineDomain != "" {
		domain = machineDomain
	}
	base := hostname + "." + domain
	if !validMachineName(base) {
		return "", http.StatusBadRequest, "Derived machine name " + base + " is not usable — provide an explicit name"
	}
	if !s.cfg.Machines.PrefixMachineNames {
		return base, 0, ""
	}

	serverID := machines.DocString(spec.Settings["server_id"], "")
	if serverID == "" {
		return "", http.StatusBadRequest,
			"server_id required when prefix_machine_names is enabled — use GET /machines/ids/next"
	}
	if !serverIDPattern.MatchString(serverID) {
		return "", http.StatusBadRequest, "server_id must be numeric (1-8 digits)"
	}
	if len(serverID) < 4 {
		serverID = strings.Repeat("0", 4-len(serverID)) + serverID
	}
	spec.Settings["server_id"] = serverID

	used, err := s.machines.UsedServerIDs(ctx)
	if err != nil {
		slog.Error("list server ids", "error", err)
		return "", http.StatusInternalServerError, "Failed to create machine"
	}
	for _, entry := range used {
		if entry.ServerID == serverID {
			return "", http.StatusConflict,
				"Server ID " + serverID + " is already in use by " + entry.MachineName
		}
	}
	return serverID + "--" + base, 0, ""
}

// resolutionDocument returns the settings document the box resolution reads:
// the rendered package template when the spec names one (package defaults may
// supply the whole box tuple), else the spec's own effective settings — the
// base's model, where the create body IS the document.
func (s *Server) resolutionDocument(ctx context.Context, spec *machines.Spec) (map[string]any, error) {
	if spec.HasProvisioner() {
		return s.renderForResolution(ctx, spec)
	}
	return map[string]any{
		"settings": machines.EffectiveSettings(ctx, spec,
			s.cfg.Provisioning.DefaultSyncMethod, s.cfg.Provisioning.DefaultNetworkInterface),
		"networks": spec.Networks,
	}, nil
}

// renderForResolution renders the package template once so the handler sees
// the EFFECTIVE settings (template defaults applied) — the box tuple the
// template registry resolves may come entirely from package defaults.
func (s *Server) renderForResolution(ctx context.Context, spec *machines.Spec) (map[string]any, error) {
	hosts, err := s.renderAllHosts(ctx, spec)
	if err != nil {
		return nil, err
	}
	return hosts[0], nil
}

// renderAllHosts renders the package template once and returns EVERY hosts[]
// entry (multi-host converged wire, sync 2026-07-17: M-Q1): the DOCUMENT is
// the program — one rendered Hosts.yml may carry N>1 coordinated machines,
// and the create handler decides single vs multi from the count alone.
func (s *Server) renderAllHosts(ctx context.Context, spec *machines.Spec) ([]map[string]any, error) {
	version, err := s.provisioners.GetVersion(spec.Provisioner.Name, spec.Provisioner.Version)
	if err != nil {
		return nil, err
	}
	rendered, err := provisioner.RenderHostsFile(&provisioner.GenerateInput{
		Version:  version,
		Settings: machines.EffectiveSettings(ctx, spec, s.cfg.Provisioning.DefaultSyncMethod, s.cfg.Provisioning.DefaultNetworkInterface),
		Networks: spec.Networks,
		// disks in the render context, structured and verbatim — the
		// networks model exactly (converged, sync 2026-07-17): inert until
		// a template echoes it.
		Disks:          spec.Disks,
		Roles:          spec.Roles,
		UserProperties: spec.Properties,
		SecretsVars:    s.secrets.TemplateVars(),
	})
	if err != nil {
		return nil, err
	}
	return machines.ParseHostsDocuments(rendered)
}

// queueCreateOrchestration creates the parent + chained children (the base's
// createZoneCreationSubTasks + handleAutoDownload): template_download first
// when the box is not local, then prepare → storage → config → finalize
// (every child carries the spec verbatim), then the optional start child.
// dependsOn seeds the FIRST chain task's dependency (multi-host converged
// wire, sync 2026-07-17: M-Q1: machine k+1's first task gates on machine k's
// last — one queue-level chain across N parents); lastTaskID is that last
// task (the start child when startAfter, else finalize) for the next link.
func (s *Server) queueCreateOrchestration(ctx context.Context, name string, spec *machines.Spec,
	document map[string]any, startAfter bool, createdBy string, dependsOn *string,
) (parentID string, subTasks map[string]string, requiresDownload bool, lastTaskID string, err error) {
	// settings.box is OPTIONAL — the base's model (resolveBoxToTemplate
	// returns success with no box): a box-less create builds from a scratch
	// volume, an existing medium, or DISKLESS (a stub — Mark's ruling).
	// Template resolution and auto-download engage ONLY when the EFFECTIVE
	// boot type is template (typed disk spec, converged sync 2026-07-17): a
	// box named under a non-template type is unused (the pre-flight warned)
	// and must NOT chain a download.
	settings := machines.MachineConfig(document).Section("settings")
	docDisks := machines.MachineConfig(document).Section("disks")
	box := machines.DocString(settings["box"], "")
	var org, boxName, boxVersion, boxArch string
	if box != "" && machines.EffectiveBootType(docDisks, settings) == machines.DiskTypeTemplate {
		var boxOK bool
		org, boxName, boxOK = strings.Cut(box, "/")
		if !boxOK || org == "" || boxName == "" {
			return "", nil, false, "", errors.New(`settings.box must be "organization/box-name"`)
		}
		boxVersion = machines.DocString(settings["box_version"], "latest")
		boxArch = machines.DocString(settings["box_arch"], "amd64")

		_, terr := s.machines.FindTemplate(ctx, org, boxName, boxVersion,
			machines.TemplateProviderFor(spec.Hypervisor), boxArch)
		switch {
		case terr == nil:
		case errors.Is(terr, machines.ErrTemplateNotFound):
			requiresDownload = true
			if boxVersion == "" || boxVersion == "latest" {
				return "", nil, false, "", errors.New("template " + box + " is not local and box_version is not specific — set settings.box_version to download it")
			}
		default:
			return "", nil, false, "", terr
		}
	}

	specDoc, err := json.Marshal(map[string]any{"spec": spec})
	if err != nil {
		return "", nil, false, "", err
	}
	metadata := string(specDoc)

	parent, err := s.tasks.Store().Create(ctx, &tasks.NewTask{
		MachineName: name,
		Operation:   machines.OpCreateOrchestration,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   createdBy,
		Metadata:    &metadata,
		Parent:      true,
	})
	if err != nil {
		return "", nil, false, "", err
	}
	cancelChain := func() {
		if _, cerr := s.tasks.Cancel(ctx, parent.ID); cerr != nil {
			slog.Warn("cancel half-built create orchestration", "task_id", parent.ID, "error", cerr)
		}
	}

	subTasks = map[string]string{}
	previous := dependsOn
	if requiresDownload {
		source, serr := machines.FindTemplateSourceForURL(s.templateSources(),
			machines.DocString(settings["box_url"], ""))
		if serr != nil {
			cancelChain()
			return "", nil, false, "", serr
		}
		downloadMeta, merr := json.Marshal(&machines.TemplateDownloadMetadata{
			SourceName:   source.Name,
			Organization: org,
			BoxName:      boxName,
			Version:      boxVersion,
			Provider:     machines.TemplateProviderFor(spec.Hypervisor),
			Architecture: boxArch,
		})
		if merr != nil {
			cancelChain()
			return "", nil, false, "", merr
		}
		downloadStr := string(downloadMeta)
		download, derr := s.createChainTask(ctx, "system", machines.OpTemplateDownload,
			&downloadStr, previous, parent.ID, createdBy)
		if derr != nil {
			cancelChain()
			return "", nil, false, "", derr
		}
		subTasks["template_download"] = download.ID
		previous = &download.ID
	}

	// The prepare (render + materialize) child exists only for package-based
	// creates — the base's chain has no render step at all (its create body
	// IS the document); a provisioner-less create goes straight to storage.
	type chainStep struct {
		key       string
		operation string
	}
	steps := []chainStep{}
	if spec.HasProvisioner() {
		steps = append(steps, chainStep{"prepare", machines.OpPrepare})
	}
	steps = append(steps,
		chainStep{"storage", machines.OpCreateStorage},
		chainStep{"config", machines.OpCreateConfig},
		chainStep{"finalize", machines.OpCreateFinalize},
	)
	for _, step := range steps {
		child, cerr := s.createChainTask(ctx, name, step.operation, &metadata, previous, parent.ID, createdBy)
		if cerr != nil {
			cancelChain()
			return "", nil, false, "", cerr
		}
		subTasks[step.key] = child.ID
		previous = &child.ID
	}
	if startAfter {
		start, serr := s.createChainTask(ctx, name, machines.OpStart, nil, previous, parent.ID, createdBy)
		if serr != nil {
			cancelChain()
			return "", nil, false, "", serr
		}
		subTasks["start"] = start.ID
		previous = &start.ID
	}
	return parent.ID, subTasks, requiresDownload, *previous, nil
}

// handleCreateMachine executes the create mechanism end to end.
//
//	@Summary		Create a machine (orchestration)
//	@Description	Minimum role: operator (the machine-create capability token). Queues the CREATE ORCHESTRATION (the zoneweaver mechanism — the agent builds real infrastructure natively, no vagrant): a parent task plus chained children machine_prepare (render the package's Jinja2 template + materialize the working directory + hash-verified installer mounts — queued ONLY when the spec names a provisioner; the reference is OPTIONAL, a machine is just a machine and provisioning never gates its existence) → machine_create_storage (clone the box template's disk image, grow to disks.boot.size, create additional media; rollback on failure) → machine_create_config (createvm/modifyvm/storage/NICs from the document + vbox.directives passthrough + cloud-init guest properties; adapter 1 is the PROVISIONING NIC — NAT with an allocated ssh port-forward (127.0.0.1:<port> → guest 22), giving guest egress and the host's provisioning access, vagrant's exact layout; document networks[] ride adapters 2+) → machine_create_finalize (registry row + document sections + — package-based creates only — the render-produced provisioner document stored in configuration + UUID) → optional start. Provisioner-less creates build straight from the spec's own settings/networks; a provisioner document can attach later via PUT + POST /provision (the base's model). The machine ROW appears at finalize, not at POST. settings.hostname AND settings.domain are REQUIRED (settings.machine_domain overrides the naming domain). With machines.prefix_machine_names, settings.server_id is REQUIRED (numeric, padded to 4; never auto-assigned — GET /machines/ids/next feeds the field) and the name becomes <id>--<hostname>.<domain>. settings.box is OPTIONAL (the base's contract): present under an effective boot type of template, it resolves against the local template registry and a missing box chains a template_download child in front (requires_download: true; box_version must then be specific); absent, the boot medium comes from disks.boot's declared type (image | blank) or the machine is DISKLESS — a stub, Proxmox-style: hostname + domain alone makes a machine, media/NICs attach later via modify, first start is manual. notes/tags/cloud_init/vbox.directives are accepted at create too (zones is bhyve-only and inert here — see MachineSpec.zones). CONSOLEPORT PRE-FLIGHT (the converged validation, sync 2026-07-17 — both agents ship the identical refusal): settings.consoleport, when the request carries it, must be an integer in 1025-65535 (number or numeric string — the value feeds VRDE's TCP/Ports); anything else answers 400 `consoleport <value> is outside the valid console port range (1025-65535)`, and an ABSENT consoleport stays absent (no invented default). The RENDERED document's consoleport (the 0.1.31 package defaults it to server_id, which this pre-flight never sees — packaged creates render in the task chain) is guarded again by the machine_create_config task, which FAILS with the SAME message before any modifyvm instead of surfacing VRDE's cryptic mid-chain E_INVALIDARG. VCPUS PRE-FLIGHT (the converged validation, sync 2026-07-17 — zoneweaver's proposal, ACKED; both agents ship the identical refusal): settings.vcpus, when the request carries it, must be a WHOLE number >= 1 (integers pass, and an INTEGRAL float like 2.0 passes too — the 0.1.31 template renders it from the wizard's integer 2; 2.5, zero, negatives, and non-numerics refuse); anything else answers 400 `vcpus <value> is not a valid vCPU count (whole number >= 1)`, and an ABSENT vcpus keeps the existing default-2 behavior byte-identical. The RENDERED document's vcpus is guarded again by the machine_create_config task, which FAILS with the SAME message before any createvm/modifyvm. THE TYPED DISK SPEC (Mark's word, sync 2026-07-17 — the ZERO-inference model; both agents ship the identical frozen refusal strings): disks.boot.type is REQUIRED whenever disks.boot is present and is the ONLY dispatcher — template|image|blank|none. Per type: template clones from settings.box (size is the grow-to; REQUIRES settings.box; takes no path), image attaches an EXISTING file at path AS-IS — never created, deleted, or resized (size/volume_name refused; at task time the file must exist on this host and must not be attached to another machine — the refusal names the path and holder verbatim, and entry-level force: true skips the in-use pre-check), blank creates a fresh VDI (REQUIRES size; sparse?/volume_name? legal; takes no path), none is diskless (no other keys beside type). blank and template entries may carry directory (the converged addendum, sync 2026-07-17 — the pool/dataset mirror): the CREATED disk file lands in that agent-host folder; absent = the machine folder (the spelled default); the folder must already exist and be absolute — the machine_create_storage task refuses `<where> directory <path> is not an absolute existing directory on this host`, and image entries refuse the key outright (`<where> type image does not take directory`). Template clones name their file by volume_name (absent = "boot"), keeping the template's own extension. An ABSENT disks.boot is the SPELLED default: template when settings.box is present, none otherwise — exactly the old box/diskless ladder; the old presence-dispatch branches (path-only, size-only boot) DIED with the model. additional_disks[] entries REQUIRE type too (image|blank only, same per-type rules; every refusal indexes entries 1-BASED). cdroms[] entries take EXACTLY one of iso|path. controllers[] is unchanged. Unknown keys in disks entries (mount, filesystem, driver, ...) are NEVER read for behavior and always preserved verbatim in the stored document. Template resolution + auto-download run ONLY when the EFFECTIVE boot type is template — a box named under any other type never chains a download; it yields a warning instead. THE CLONE STRATEGY (frozen, sync 2026-07-19): disks.boot.clone_strategy on a template boot — copy (default, independent full copy) | clone (differencing child off the template's shared multiattach clone base; takes no size/volume_name/directory; localize refused as zfs-only) — see MachineSpec.disks for the full contract. WARNINGS (never refusals) ride the response's resource_warnings[] as {resource: "disks", message}: a bhyve-vocabulary key in any disk entry (pool/dataset/diskif — `<key> is bhyve vocabulary and has no effect on this hypervisor`), a clone_strategy in an additional_disks entry (`clone_strategy has no effect on additional disks`), and a settings.box the effective type never reads (`settings.box is unused when disks.boot.type is <type>`). Every medium the agent CREATES (template clones, blank VDIs) is provenance-STAMPED at materialization (the hyperweaver:source medium property, .hw-source sidecar fallback) — the delete flow destroys ONLY stamped media (GET /media surfaces the stamps); image media are never stamped and never the agent's to delete. The RENDERED document re-validates in the machine_create_storage task with the SAME frozen strings — SEQUENCING, honestly: package releases predating the typed-disk echo can render a disks.boot WITHOUT type, and those packaged creates REFUSE with the type-required string until the package release echoes the typed vocabulary. MULTI-HOST (the converged M-Q1 wire): when the named provisioner package's rendered document carries hosts[] with N>1 entries, this ONE request creates N machines — the answer is {success, multi_host: true, count, message, machines: [{machine_name, parent_task_id, sub_tasks}] in hosts[] order, resource_warnings? (a MAP of machine_name → warnings[])}. N orchestration parents, NO meta-parent; names are FINAL at POST (each entry's own settings.hostname/domain, the server_id prefix rules applying per entry). The pre-check is ATOMIC: any entry's conflict or validation problem refuses the WHOLE request, its message prefixed "multi-host entry N: " (N = the 1-BASED hosts[] position). An explicit request name is a 400 on a multi-host document, and auto-download is single-host only — a multi-host document whose box template is not all local answers 400. Machines create in hosts[] declaration order, and machine k+1's FIRST task depends_on machine k's LAST (the start when start_after_create, else the finalize) — a failed predecessor cancels the rest by dependency propagation. Join vars are template-rendered document data. A single-entry hosts[] (N==1) keeps the single-host wire unchanged.
//	@Tags			Machine Management
//	@Accept			json
//	@Produce		json
//	@Param			request	body		map[string]interface{}	true	"Optional explicit name plus the MachineSpec creation document (allOf)"
//	@Success		200	{object}	map[string]interface{}	"Create orchestration queued (single-host: the machine row lands at the finalize child; multi-host: one machines[] entry per hosts[] entry, in declaration order)"
//	@Failure		400	"Invalid spec, provisioner reference, server_id, safe_id_path, box reference, template render failure, an out-of-range or non-numeric settings.consoleport (the exact refusal: `consoleport <value> is outside the valid console port range (1025-65535)` — the converged pre-flight, sync 2026-07-17; multi-host entries whose RENDERED settings carry a bad consoleport refuse with the entry prefix), a non-whole or sub-1 settings.vcpus (the exact refusal: `vcpus <value> is not a valid vCPU count (whole number >= 1)` — same converged pre-flight; integral floats like 2.0 pass, and multi-host entries whose RENDERED settings carry a bad vcpus refuse with the entry prefix), a disks section breaking the TYPED DISK SPEC (the frozen strings, value/path 1-based-index verbatim: `disks.boot.type is required when disks.boot is present (template|image|blank|none)`, `disks.boot.type <value> is not a valid disk type (template|image|blank|none)`, `disks.boot.type template requires settings.box`, `disks.boot.type template does not take path`, `disks.boot.type image requires path`, `disks.boot.type image does not take size or volume_name (an image attaches as-is)`, `disks.boot.type image does not take directory`, `disks.boot.type blank requires size`, `disks.boot.type blank does not take path`, `disks.boot.type none takes no other keys`, `disks.boot.clone_strategy localize is zfs vocabulary with no analog on this hypervisor (clone|copy)`, `disks.boot.clone_strategy <value> is not a valid clone strategy (clone|copy)`, `disks.boot.clone_strategy requires disks.boot.type template`, `disks.boot.clone_strategy clone does not take size (a differencing disk keeps the template's size)`, `disks.boot.clone_strategy clone does not take directory (the differencing disk lives in the machine folder)`, `disks.boot.clone_strategy clone does not take volume_name (VirtualBox names the differencing disk)`, `disks.additional_disks[<n>].type is required (image|blank)`, `disks.additional_disks[<n>].type <value> is not a valid additional disk type (image|blank)`, `disks.cdroms[<n>] needs exactly one of iso or path` — the path-existence and in-use strings `disks.boot.path <path> does not exist on this host` / `disks.boot.path <path> is attached to <machine> (set force: true to attach anyway)` and their disks.additional_disks[<n>].path twins — plus the directory placement string `<where> directory <path> is not an absolute existing directory on this host` — are TASK-TIME failures in machine_create_storage; multi-host entries take every string with the entry prefix), Insufficient resources ({error, details[]} — the pre-flight resource validation rejection, machines.resource_validation), an explicit name on a multi-host document, or a multi-host document whose box templates are not all local (auto-download is single-host only). Multi-host refusals prefix the failing entry: "multi-host entry N: " (1-based) — the ATOMIC pre-check refuses the whole request"
//	@Failure		409	"Machine name (DB or hypervisor), server_id, or working directory already in use (multi-host: prefixed "multi-host entry N: " — any entry's conflict refuses the whole request)"
//	@Failure		422	{object}	map[string]interface{}	"Form answers fail the package's Field DSL — the body IS the {FIELD: message} map (design §3.1)"
//	@Router			/machines [post]
func (s *Server) handleCreateMachine(w http.ResponseWriter, r *http.Request) {
	var body createMachineRequest
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	specOK, specDiskWarnings := s.validateSpec(w, &body.Spec)
	if !specOK {
		return
	}

	// Multi-host detection (multi-host converged wire, sync 2026-07-17: M-Q1):
	// the DOCUMENT is the program — render once and count hosts[]. N>1 takes
	// the multi-host branch; N==1 falls through to the single-host path
	// untouched (it re-renders after the server_id write-back pads settings,
	// exactly as before — the detection render never feeds a single-host build).
	if body.HasProvisioner() {
		hosts, herr := s.renderAllHosts(r.Context(), &body.Spec)
		if herr != nil {
			taskError(w, http.StatusBadRequest, "Template render failed: "+herr.Error())
			return
		}
		if len(hosts) > 1 {
			s.createMultiHostMachines(w, r, &body, hosts)
			return
		}
	}

	name, status, problem := s.resolveMachineName(r.Context(), body.Name, &body.Spec)
	if problem != "" {
		taskError(w, status, problem)
		return
	}

	// 409 against the DB and the hypervisor (the base checks both).
	if _, gerr := s.machines.Get(r.Context(), name); gerr == nil {
		taskError(w, http.StatusConflict, "Machine "+name+" already exists in database")
		return
	} else if !errors.Is(gerr, machines.ErrNotFound) {
		slog.Error("check machine existence", "machine", name, "error", gerr)
		taskError(w, http.StatusInternalServerError, "Failed to create machine")
		return
	}
	if exe := machines.VBoxManagePath(r.Context()); exe != "" {
		if _, verr := vbox.ShowVMInfo(r.Context(), exe, name); verr == nil {
			taskError(w, http.StatusConflict, "Machine "+name+" already exists on the system")
			return
		}
	}
	if taken, home, terr := s.workdirTaken(r.Context(), name); terr != nil {
		taskError(w, http.StatusInternalServerError, "Failed to create machine")
		return
	} else if taken {
		taskError(w, http.StatusConflict,
			"Another machine already uses the working directory "+home+" — pick a name that sanitizes differently")
		return
	}

	document, err := s.resolutionDocument(r.Context(), &body.Spec)
	if err != nil {
		taskError(w, http.StatusBadRequest, "Template render failed: "+err.Error())
		return
	}

	// Pre-flight resource validation (the base's create hook): failing checks
	// reject BEFORE anything queues; warnings ride the success response —
	// the typed-disk rows (bhyve vocabulary, unused settings.box) join them.
	resourceErrors, resourceWarnings := s.validateCreationResources(r.Context(), document)
	if len(resourceErrors) > 0 {
		insufficientResources(w, resourceErrors)
		return
	}
	resourceWarnings = append(diskWarningRows(specDiskWarnings), resourceWarnings...)

	createdBy := auth.FromContext(r.Context()).Name
	parentID, subTasks, requiresDownload, _, err := s.queueCreateOrchestration(
		r.Context(), name, &body.Spec, document, body.StartAfterCreate, createdBy, nil)
	if err != nil {
		taskError(w, http.StatusBadRequest, err.Error())
		return
	}

	provisionerLabel := "none (provisioning is optional)"
	if body.HasProvisioner() {
		provisionerLabel = body.Provisioner.Name + "/" + body.Provisioner.Version
	}
	slog.Info("machine creation queued", "machine", name,
		"provisioner", provisionerLabel,
		"requires_download", requiresDownload, "by", createdBy)
	message := "Machine creation queued"
	if requiresDownload {
		message = "Template download and machine creation queued"
	}
	response := map[string]any{
		"success":           true,
		"parent_task_id":    parentID,
		"machine_name":      name,
		"operation":         machines.OpCreateOrchestration,
		"status":            tasks.StatusPending,
		"message":           message,
		"requires_download": requiresDownload,
		"sub_tasks":         subTasks,
	}
	if len(resourceWarnings) > 0 {
		response["resource_warnings"] = resourceWarnings
	}
	writeJSON(w, response)
}
