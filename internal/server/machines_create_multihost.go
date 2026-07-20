package server

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

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
