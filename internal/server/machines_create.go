package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/provisioner"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
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

// validateSpec checks the creation spec: the provisioner reference is
// OPTIONAL (the base's provisioner-free create — Mark's ruling 2026-07-07)
// and validated against the registry only when given; hostname and domain are
// required (the name derives from them), the typed disk spec must hold, role
// names must be usable, the safe-ID source must exist, sync_method must be
// valid. diskWarnings carry the typed-disk never-refuse rows (bhyve
// vocabulary keys, an unused settings.box) for the create response's
// resource_warnings.
func (s *Server) validateSpec(w http.ResponseWriter, spec *machines.Spec) (ok bool, diskWarnings []string) {
	if (spec.Provisioner.Name == "") != (spec.Provisioner.Version == "") {
		taskError(w, http.StatusBadRequest,
			"provisioner needs both name and version — or neither: provisioning is optional")
		return false, nil
	}
	if spec.HasProvisioner() {
		version, err := s.provisioners.GetVersion(spec.Provisioner.Name, spec.Provisioner.Version)
		if err != nil {
			if errors.Is(err, provisioner.ErrNotFound) || errors.Is(err, provisioner.ErrVersionNotFound) {
				taskError(w, http.StatusBadRequest,
					"provisioner "+spec.Provisioner.Name+"/"+spec.Provisioner.Version+" is not in the registry")
				return false, nil
			}
			slog.Error("resolve provisioner for machine spec", "error", err)
			taskError(w, http.StatusInternalServerError, "Failed to resolve provisioner")
			return false, nil
		}
		// Authoritative pre-render answer validation (Field DSL, design §3.1):
		// the ruled wire is a 422 whose body IS the {FIELD: message} map.
		problems, derr := provisioner.ValidateVersionAnswers(version, spec.Roles,
			spec.Properties, nil, false)
		if derr != nil {
			taskError(w, http.StatusBadRequest, derr.Error())
			return false, nil
		}
		if len(problems) > 0 {
			writeJSONStatus(w, http.StatusUnprocessableEntity, problems)
			return false, nil
		}
	}
	if spec.Settings == nil {
		spec.Settings = map[string]any{}
	}
	hostname, _ := spec.Settings["hostname"].(string)
	domain, _ := spec.Settings["domain"].(string)
	if hostname == "" || domain == "" {
		taskError(w, http.StatusBadRequest,
			"Missing required parameters: settings.hostname and settings.domain are required")
		return false, nil
	}
	// consoleport pre-flight (converged, sync 2026-07-17): when the request's
	// settings carry consoleport it must be an integer 1025-65535 (number or
	// numeric string) — the value feeds VRDE's TCP/Ports, and an out-of-range
	// value otherwise dies mid-chain as a cryptic modifyvm E_INVALIDARG. An
	// ABSENT consoleport is fine; the render-time default is the executor
	// guard's business (create_exec.go).
	if value, ok := spec.Settings["consoleport"]; ok {
		if problem := machines.ConsolePortProblem(value); problem != "" {
			taskError(w, http.StatusBadRequest, problem)
			return false, nil
		}
	}
	// vcpus pre-flight (converged, sync 2026-07-17 — zoneweaver's proposal,
	// ACKED): a present settings.vcpus must be a whole number >= 1 (integral
	// floats like 2.0 pass — the 0.1.31 template renders them from wizard
	// integers). Absent keeps the default-2 behavior byte-identical; the
	// render-time value is the executor guard's business (create_exec.go).
	if value, ok := spec.Settings["vcpus"]; ok {
		if problem := machines.VCPUProblem(value); problem != "" {
			taskError(w, http.StatusBadRequest, problem)
			return false, nil
		}
	}
	// Typed disk spec pre-flight (Mark's word, sync 2026-07-17 — the
	// ZERO-inference model): disks.boot.type dispatches everything; the FIRST
	// frozen-string problem answers the 400, warnings ride the response's
	// resource_warnings. The rendered document re-validates at task time —
	// this gate covers the request's own disks.
	diskProblems, diskWarnings := machines.ValidateDisks(spec.Disks, spec.Settings)
	if len(diskProblems) > 0 {
		taskError(w, http.StatusBadRequest, diskProblems[0])
		return false, nil
	}
	// Per-machine hypervisor selection (phase 3): ""/virtualbox = VirtualBox,
	// utm = UTM — anything else refuses with the value verbatim. utm gates on
	// a macOS agent host and, until the other boot types land, on the
	// template boot type (create = box.utm bundle import).
	switch spec.Hypervisor {
	case "", machines.HypervisorVirtualBox, machines.HypervisorUTM:
	default:
		taskError(w, http.StatusBadRequest,
			"hypervisor "+spec.Hypervisor+" is not a valid hypervisor (virtualbox|utm)")
		return false, nil
	}
	if spec.Hypervisor == machines.HypervisorUTM {
		if runtime.GOOS != "darwin" {
			taskError(w, http.StatusBadRequest, "hypervisor utm requires a macOS agent host")
			return false, nil
		}
		if effective := machines.EffectiveBootType(spec.Disks, spec.Settings); effective != machines.DiskTypeTemplate {
			taskError(w, http.StatusBadRequest,
				"hypervisor utm builds from a box (settings.box) — disks.boot.type "+effective+" is not yet supported on utm")
			return false, nil
		}
	}
	for i := range spec.Roles {
		if !provisioner.ValidName(spec.Roles[i].Name) {
			taskError(w, http.StatusBadRequest, "role name "+spec.Roles[i].Name+" is not usable")
			return false, nil
		}
	}
	if spec.SafeIDPath != "" {
		clean, err := safepath.CleanAbs(spec.SafeIDPath)
		if err != nil {
			taskError(w, http.StatusBadRequest, "safe_id_path is not a usable path")
			return false, nil
		}
		if info, serr := os.Stat(clean); serr != nil || info.IsDir() {
			taskError(w, http.StatusBadRequest, "safe_id_path does not name a file on the agent host")
			return false, nil
		}
		spec.SafeIDPath = clean
	}
	switch spec.SyncMethod {
	case "", machines.SyncRsync, machines.SyncSCP:
	default:
		taskError(w, http.StatusBadRequest, "sync_method must be rsync or scp")
		return false, nil
	}
	return true, diskWarnings
}

// diskWarningRows wraps the typed-disk warning strings into the create
// response's resource_warnings row shape (converged, sync 2026-07-17):
// {"resource": "disks", "message": ...}.
func diskWarningRows(warnings []string) []resourceIssue {
	rows := make([]resourceIssue, 0, len(warnings))
	for _, warning := range warnings {
		rows = append(rows, resourceIssue{"resource": "disks", "message": warning})
	}
	return rows
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

// createMultiHostMachines executes the multi-host branch of POST /machines
// (multi-host converged wire, sync 2026-07-17: M-Q1 — zoneweaver's shipped
// wire, matched exactly): ONE request whose RENDER produced hosts[] with N>1
// entries makes N coordinated machines. The DOCUMENT is the program — every
// machine's name comes from ITS OWN entry's settings (hostname +
// machine_domain||domain, the server_id prefix rules applied PER ENTRY), join
// vars are template-rendered document data (the agent injects NOTHING between
// hosts), and the whole request is ATOMIC: every entry validates and
// conflict-checks (DB 409, hypervisor 409, workdir collision, in-document
// duplicates, box locality, resources) BEFORE anything queues — the first
// problem refuses everything, prefixed "multi-host entry N: " (N = the
// 1-BASED hosts[] position — the UI's converged ruling; the resource
// details[] rows carry the same 1-based entry). Machines queue in hosts[]
// DECLARATION ORDER,
// machine k+1's first task depends_on machine k's last (start when
// start_after_create, else finalize) — one queue-level chain across N
// separate create-orchestration parents, NO meta-parent. Auto-download is
// single-host only: any entry naming a non-local box refuses the request.
func (s *Server) createMultiHostMachines(w http.ResponseWriter, r *http.Request,
	body *createMachineRequest, hosts []map[string]any,
) {
	if body.Name != "" {
		taskError(w, http.StatusBadRequest,
			"multi-host documents name every machine from their own hosts[] entries — an explicit name is only legal for single-host creates")
		return
	}
	// Entry labels are 1-BASED (the UI's converged ruling, sync 2026-07-17:
	// details rows carry {entry (1-based), machine_name}; zoneweaver's message
	// prefixes count the same way).
	entryError := func(index, status int, problem string) {
		taskError(w, status, "multi-host entry "+strconv.Itoa(index+1)+": "+problem)
	}

	prefix := s.cfg.Machines.PrefixMachineNames
	dbIDs := map[string]string{}
	if prefix {
		used, uerr := s.machines.UsedServerIDs(r.Context())
		if uerr != nil {
			slog.Error("list server ids", "error", uerr)
			taskError(w, http.StatusInternalServerError, "Failed to create machines")
			return
		}
		for _, entry := range used {
			dbIDs[entry.ServerID] = entry.MachineName
		}
	}

	type entryPlan struct {
		name     string
		spec     *machines.Spec
		document map[string]any
	}
	plans := make([]entryPlan, 0, len(hosts))
	seenNames := map[string]bool{}
	seenIDs := map[string]bool{}
	seenHomes := map[string]bool{}
	warningsByMachine := map[string]any{}
	for k, document := range hosts {
		settings := machines.MachineConfig(document).Section("settings")
		hostname := machines.DocString(settings["hostname"], "")
		domain := machines.DocString(settings["domain"], "")
		machineDomain := machines.DocString(settings["machine_domain"], "")
		if machineDomain != "" {
			domain = machineDomain
		}
		if hostname == "" || domain == "" {
			entryError(k, http.StatusBadRequest,
				"settings.hostname and settings.domain (or machine_domain) are required in every hosts[] entry")
			return
		}
		name := hostname + "." + domain
		if !validMachineName(name) {
			entryError(k, http.StatusBadRequest, "Derived machine name "+name+" is not usable")
			return
		}
		serverID := machines.DocString(settings["server_id"], "")
		if prefix {
			if serverID == "" {
				entryError(k, http.StatusBadRequest,
					"server_id required when prefix_machine_names is enabled — every hosts[] entry needs its own settings.server_id")
				return
			}
			if !serverIDPattern.MatchString(serverID) {
				entryError(k, http.StatusBadRequest, "server_id must be numeric (1-8 digits)")
				return
			}
			if len(serverID) < 4 {
				serverID = strings.Repeat("0", 4-len(serverID)) + serverID
			}
			if seenIDs[serverID] {
				entryError(k, http.StatusConflict, "Server ID "+serverID+" appears twice in the document")
				return
			}
			seenIDs[serverID] = true
			if owner := dbIDs[serverID]; owner != "" {
				entryError(k, http.StatusConflict, "Server ID "+serverID+" is already in use by "+owner)
				return
			}
			name = serverID + "--" + name
		}
		nameKey := strings.ToLower(name)
		if seenNames[nameKey] {
			entryError(k, http.StatusConflict, "Machine name "+name+" appears twice in the document")
			return
		}
		seenNames[nameKey] = true

		// The single-host conflict trio, per entry, before anything queues.
		if _, gerr := s.machines.Get(r.Context(), name); gerr == nil {
			entryError(k, http.StatusConflict, "Machine "+name+" already exists in database")
			return
		} else if !errors.Is(gerr, machines.ErrNotFound) {
			slog.Error("check machine existence", "machine", name, "error", gerr)
			taskError(w, http.StatusInternalServerError, "Failed to create machines")
			return
		}
		if exe := machines.VBoxManagePath(r.Context()); exe != "" {
			if _, verr := vbox.ShowVMInfo(r.Context(), exe, name); verr == nil {
				entryError(k, http.StatusConflict, "Machine "+name+" already exists on the system")
				return
			}
		}
		taken, home, terr := s.workdirTaken(r.Context(), name)
		if terr != nil {
			taskError(w, http.StatusInternalServerError, "Failed to create machines")
			return
		}
		if taken {
			entryError(k, http.StatusConflict,
				"Another machine already uses the working directory "+home+" — pick a name that sanitizes differently")
			return
		}
		homeKey := strings.ToLower(home)
		if seenHomes[homeKey] {
			entryError(k, http.StatusConflict,
				"two hosts[] entries sanitize to the same working directory "+home)
			return
		}
		seenHomes[homeKey] = true

		// consoleport pre-flight per entry (converged, sync 2026-07-17): the
		// entry's RENDERED settings may carry consoleport (the 0.1.31 package
		// defaults it to server_id) — an out-of-range or non-numeric value
		// joins the atomic refusal with the entry prefix instead of dying
		// mid-chain as modifyvm's E_INVALIDARG. Absent stays absent.
		if value, ok := settings["consoleport"]; ok {
			if problem := machines.ConsolePortProblem(value); problem != "" {
				entryError(k, http.StatusBadRequest, problem)
				return
			}
		}
		// vcpus pre-flight per entry (converged, sync 2026-07-17 —
		// zoneweaver's proposal, ACKED): the entry's RENDERED settings must
		// carry a whole number >= 1 when vcpus is present (integral floats
		// like 2.0 pass); a bad value joins the atomic refusal with the entry
		// prefix. Absent stays absent (default 2).
		if value, ok := settings["vcpus"]; ok {
			if problem := machines.VCPUProblem(value); problem != "" {
				entryError(k, http.StatusBadRequest, problem)
				return
			}
		}
		// Typed disk spec per entry (Mark's word, sync 2026-07-17): the
		// RENDERED entry's disks + settings take the same frozen strings with
		// the 1-based entry prefix; the never-refuse rows join this machine's
		// warningsByMachine slot as disks rows.
		entryDisks := machines.MachineConfig(document).Section("disks")
		diskProblems, entryDiskWarnings := machines.ValidateDisks(entryDisks, settings)
		if len(diskProblems) > 0 {
			entryError(k, http.StatusBadRequest, diskProblems[0])
			return
		}

		// Auto-download is single-host only (M-Q1): every box the EFFECTIVE
		// boot type actually reads (template — the typed disk spec's gate)
		// must already be local — the refusal names the box AND the entry. A
		// box under a non-template type is unused (warned above), never
		// resolved.
		if box := machines.DocString(settings["box"], ""); box != "" &&
			machines.EffectiveBootType(entryDisks, settings) == machines.DiskTypeTemplate {
			org, boxName, boxOK := strings.Cut(box, "/")
			if !boxOK || org == "" || boxName == "" {
				entryError(k, http.StatusBadRequest, `settings.box must be "organization/box-name"`)
				return
			}
			_, ferr := s.machines.FindTemplate(r.Context(), org, boxName,
				machines.DocString(settings["box_version"], "latest"),
				machines.TemplateProviderFor(body.Hypervisor),
				machines.DocString(settings["box_arch"], "amd64"))
			if errors.Is(ferr, machines.ErrTemplateNotFound) {
				entryError(k, http.StatusBadRequest,
					"box "+box+" is not local — multi-host creates never auto-download; pull it first (POST /templates/pull)")
				return
			}
			if ferr != nil {
				slog.Error("resolve template for multi-host entry", "box", box, "error", ferr)
				taskError(w, http.StatusInternalServerError, "Failed to create machines")
				return
			}
		}

		// Per-entry pre-flight resource validation against ITS rendered
		// document: failures join the atomic refusal (entry + machine
		// annotated); warnings collect per machine name — the typed-disk
		// rows ride in front of them.
		resourceErrors, resourceWarnings := s.validateCreationResources(r.Context(), document)
		if len(resourceErrors) > 0 {
			for _, issue := range resourceErrors {
				issue["entry"] = k + 1
				issue["machine_name"] = name
			}
			insufficientResources(w, resourceErrors)
			return
		}
		entryWarnings := append(diskWarningRows(entryDiskWarnings), resourceWarnings...)
		if len(entryWarnings) > 0 {
			warningsByMachine[name] = entryWarnings
		}

		// This machine's spec: the SAME request spec with the entry's own
		// identity written back (the truth resolveMachineName's write-back
		// keeps for single-host rows) and its hosts[] index stamped so the
		// prepare child reads ITS OWN entry.
		specCopy := body.Spec
		specCopy.Settings = make(map[string]any, len(body.Settings)+3)
		for key, value := range body.Settings {
			specCopy.Settings[key] = value
		}
		specCopy.Settings["hostname"] = hostname
		if entryDomain := machines.DocString(settings["domain"], ""); entryDomain != "" {
			specCopy.Settings["domain"] = entryDomain
		}
		if machineDomain != "" {
			specCopy.Settings["machine_domain"] = machineDomain
		}
		if serverID != "" {
			specCopy.Settings["server_id"] = serverID
		}
		specCopy.HostIndex = k
		plans = append(plans, entryPlan{name: name, spec: &specCopy, document: document})
	}

	// Every entry passed — queue in hosts[] declaration order, chaining each
	// machine's first task on the previous machine's last. A mid-queue
	// failure cancels every parent already queued (the atomic promise held as
	// far as the queue allows) before the refusal answers.
	createdBy := auth.FromContext(r.Context()).Name
	queued := []string{}
	cancelAll := func() {
		for _, id := range queued {
			if _, cerr := s.tasks.Cancel(r.Context(), id); cerr != nil {
				slog.Warn("cancel half-built multi-host create", "task_id", id, "error", cerr)
			}
		}
	}
	machinesOut := make([]map[string]any, 0, len(plans))
	var dependsOn *string
	for k := range plans {
		plan := &plans[k]
		parentID, subTasks, _, lastTaskID, qerr := s.queueCreateOrchestration(r.Context(),
			plan.name, plan.spec, plan.document, body.StartAfterCreate, createdBy, dependsOn)
		if qerr != nil {
			cancelAll()
			entryError(k, http.StatusBadRequest, qerr.Error())
			return
		}
		queued = append(queued, parentID)
		last := lastTaskID
		dependsOn = &last
		machinesOut = append(machinesOut, map[string]any{
			"machine_name":   plan.name,
			"parent_task_id": parentID,
			"sub_tasks":      subTasks,
		})
	}

	slog.Info("multi-host machine creation queued", "count", len(plans),
		"provisioner", body.Provisioner.Name+"/"+body.Provisioner.Version, "by", createdBy)
	response := map[string]any{
		"success":    true,
		"multi_host": true,
		"count":      len(plans),
		"message": "Machine creation queued for " + strconv.Itoa(len(plans)) +
			" machines (multi-host document)",
		"machines": machinesOut,
	}
	if len(warningsByMachine) > 0 {
		response["resource_warnings"] = warningsByMachine
	}
	writeJSON(w, response)
}

// workdirTaken reports whether another machine row claims the working
// directory the name sanitizes to.
func (s *Server) workdirTaken(ctx context.Context, name string) (taken bool, home string, err error) {
	machinesRoot, err := s.cfg.MachinesDir()
	if err != nil {
		return false, "", err
	}
	home, err = safepath.Under(machinesRoot, provisioner.MachineDirName(name))
	if err != nil {
		return false, "", err
	}
	list, err := s.machines.List(ctx, &machines.ListFilter{})
	if err != nil {
		return false, "", err
	}
	for _, machine := range list {
		if machine.Home != nil && strings.EqualFold(*machine.Home, home) {
			return true, home, nil
		}
	}
	return false, home, nil
}

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
