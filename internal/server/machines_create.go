package server

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
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
// required (the name derives from them), role names must be usable, the
// safe-ID source must exist, sync_method must be valid.
func (s *Server) validateSpec(w http.ResponseWriter, spec *machines.Spec) bool {
	if (spec.Provisioner.Name == "") != (spec.Provisioner.Version == "") {
		taskError(w, http.StatusBadRequest,
			"provisioner needs both name and version — or neither: provisioning is optional")
		return false
	}
	if spec.HasProvisioner() {
		version, err := s.provisioners.GetVersion(spec.Provisioner.Name, spec.Provisioner.Version)
		if err != nil {
			if errors.Is(err, provisioner.ErrNotFound) || errors.Is(err, provisioner.ErrVersionNotFound) {
				taskError(w, http.StatusBadRequest,
					"provisioner "+spec.Provisioner.Name+"/"+spec.Provisioner.Version+" is not in the registry")
				return false
			}
			slog.Error("resolve provisioner for machine spec", "error", err)
			taskError(w, http.StatusInternalServerError, "Failed to resolve provisioner")
			return false
		}
		// Authoritative pre-render answer validation (Field DSL, design §3.1):
		// the ruled wire is a 422 whose body IS the {FIELD: message} map.
		problems, derr := provisioner.ValidateVersionAnswers(version, spec.Roles,
			spec.Properties, nil, false)
		if derr != nil {
			taskError(w, http.StatusBadRequest, derr.Error())
			return false
		}
		if len(problems) > 0 {
			writeJSONStatus(w, http.StatusUnprocessableEntity, problems)
			return false
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
		return false
	}
	for i := range spec.Roles {
		if !provisioner.ValidName(spec.Roles[i].Name) {
			taskError(w, http.StatusBadRequest, "role name "+spec.Roles[i].Name+" is not usable")
			return false
		}
	}
	if spec.SafeIDPath != "" {
		clean, err := safepath.CleanAbs(spec.SafeIDPath)
		if err != nil {
			taskError(w, http.StatusBadRequest, "safe_id_path is not a usable path")
			return false
		}
		if info, serr := os.Stat(clean); serr != nil || info.IsDir() {
			taskError(w, http.StatusBadRequest, "safe_id_path does not name a file on the agent host")
			return false
		}
		spec.SafeIDPath = clean
	}
	switch spec.SyncMethod {
	case "", machines.SyncRsync, machines.SyncSCP:
	default:
		taskError(w, http.StatusBadRequest, "sync_method must be rsync or scp")
		return false
	}
	return true
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
		Version:        version,
		Settings:       machines.EffectiveSettings(ctx, spec, s.cfg.Provisioning.DefaultSyncMethod, s.cfg.Provisioning.DefaultNetworkInterface),
		Networks:       spec.Networks,
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
	// Template resolution and auto-download engage only when a box is named.
	settings := machines.MachineConfig(document).Section("settings")
	box := machines.DocString(settings["box"], "")
	var org, boxName, boxVersion, boxArch string
	if box != "" {
		var boxOK bool
		org, boxName, boxOK = strings.Cut(box, "/")
		if !boxOK || org == "" || boxName == "" {
			return "", nil, false, "", errors.New(`settings.box must be "organization/box-name"`)
		}
		boxVersion = machines.DocString(settings["box_version"], "latest")
		boxArch = machines.DocString(settings["box_arch"], "amd64")

		_, terr := s.machines.FindTemplate(ctx, org, boxName, boxVersion, boxArch)
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
			Provider:     machines.TemplateProvider,
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
func (s *Server) handleCreateMachine(w http.ResponseWriter, r *http.Request) {
	var body createMachineRequest
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if !s.validateSpec(w, &body.Spec) {
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
	// reject BEFORE anything queues; warnings ride the success response.
	resourceErrors, resourceWarnings := s.validateCreationResources(r.Context(), document)
	if len(resourceErrors) > 0 {
		insufficientResources(w, resourceErrors)
		return
	}

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

		// Auto-download is single-host only (M-Q1): every named box must
		// already be local — the refusal names the box AND the entry.
		if box := machines.DocString(settings["box"], ""); box != "" {
			org, boxName, boxOK := strings.Cut(box, "/")
			if !boxOK || org == "" || boxName == "" {
				entryError(k, http.StatusBadRequest, `settings.box must be "organization/box-name"`)
				return
			}
			_, ferr := s.machines.FindTemplate(r.Context(), org, boxName,
				machines.DocString(settings["box_version"], "latest"),
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
		// annotated); warnings collect per machine name.
		resourceErrors, resourceWarnings := s.validateCreationResources(r.Context(), document)
		if len(resourceErrors) > 0 {
			for _, issue := range resourceErrors {
				issue["entry"] = k + 1
				issue["machine_name"] = name
			}
			insufficientResources(w, resourceErrors)
			return
		}
		if len(resourceWarnings) > 0 {
			warningsByMachine[name] = resourceWarnings
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
		taskError(w, http.StatusBadRequest, `source must be "template" (spec rebuild) or "current" (clonevm of today's disk state)`)
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
	provisionalCount := 0
	for _, entry := range spec.Networks {
		if network, ok := entry.(map[string]any); ok {
			if provisional, _ := network["provisional"].(bool); provisional {
				provisionalCount++
			}
		}
	}
	provisioningIPs, aerr := s.allocateProvisioningIPs(r.Context(), provisionalCount)
	if aerr != nil {
		slog.Error("allocate provisioning IPs", "error", aerr)
		taskError(w, http.StatusInternalServerError, "Failed to clone machine")
		return
	}
	stripCloneNetworks(spec.Networks, provisioningIPs)
	spec.StartAfterCreate = false

	if !s.validateSpec(w, spec) {
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

// stripCloneNetworks removes identity and addressing from cloned network
// entries so source and clone can never collide — the base's rule with its
// provisional exception (ZoneCloneController.buildCloneMetadata): provisional
// entries receive a FRESH address from the provisioning DHCP range instead of
// losing addressing (an exhausted range leaves it empty, the base's own
// behavior). mac always strips: the document's networks[] carry the adapter
// identity here.
func stripCloneNetworks(networks, provisioningIPs []any) {
	next := 0
	for _, entry := range networks {
		network, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		delete(network, "mac")
		if provisional, _ := network["provisional"].(bool); provisional {
			address := ""
			if next < len(provisioningIPs) {
				address, _ = provisioningIPs[next].(string)
				next++
			}
			network["address"] = address
			continue
		}
		for _, key := range []string{"address", "gateway", "netmask", "dns"} {
			delete(network, key)
		}
	}
}

// allocateProvisioningIPs is the base's batch allocator
// (ZoneCloneController.allocateProvisioningIPs): one pass over the stored
// configurations collects the provisional addresses in use, then count unused
// IPs come from the configured DHCP range (empty when the network is disabled
// or unconfigured — the base's warn-and-continue).
func (s *Server) allocateProvisioningIPs(ctx context.Context, count int) ([]any, error) {
	allocated := []any{}
	if count == 0 {
		return allocated, nil
	}
	network := s.cfg.Provisioning.Network
	if !network.Enabled || network.DHCPRangeStart == "" || network.DHCPRangeEnd == "" {
		slog.Warn("provisioning DHCP range not configured — clone provisional networks get no address")
		return allocated, nil
	}
	start := ipToLong(network.DHCPRangeStart)
	end := ipToLong(network.DHCPRangeEnd)
	if start == 0 || end == 0 {
		return allocated, nil
	}

	list, err := s.machines.List(ctx, &machines.ListFilter{})
	if err != nil {
		return nil, err
	}
	used := map[string]bool{}
	for _, machine := range list {
		config := machines.ParseConfiguration(machine)
		for _, entry := range config.List("networks") {
			network, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			if provisional, _ := network["provisional"].(bool); !provisional {
				continue
			}
			if address, _ := network["address"].(string); address != "" {
				used[address] = true
			}
		}
	}

	for ip := start; ip <= end && len(allocated) < count; ip++ {
		candidate := longToIP(ip)
		if !used[candidate] {
			allocated = append(allocated, candidate)
			used[candidate] = true
		}
	}
	return allocated, nil
}

// ipToLong/longToIP are the base's IPv4 <-> integer helpers (0 on non-IPv4).
func ipToLong(s string) uint32 {
	ip := net.ParseIP(s)
	if ip == nil {
		return 0
	}
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func longToIP(v uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, v)
	return ip.String()
}
