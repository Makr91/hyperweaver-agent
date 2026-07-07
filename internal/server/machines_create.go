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
// machine_prepare (render + materialize — the SHI registry layer in the
// provisioning-content slot) → machine_create_storage →
// machine_create_config → machine_create_finalize (+ optional start).
// PUT /machines/{name} is the modify mechanism (machines_modify.go) — create
// DROPS any provisioner config in its body beyond the package reference;
// provisioning config arrives via PUT's provisioner store or the render.

// serverIDPattern is the numeric server_id vocabulary.
var serverIDPattern = regexp.MustCompile(`^\d{1,8}$`)

// createMachineRequest is the POST /machines body: an optional explicit name
// plus the creation spec (the package reference + the document inputs the
// render consumes).
type createMachineRequest struct {
	Name string `json:"name"`
	machines.Spec
}

// validateSpec checks the creation spec: the provisioner version must exist,
// hostname and domain are required (the name derives from them), role names
// must be usable, the safe-ID source must exist, sync_method must be valid.
func (s *Server) validateSpec(w http.ResponseWriter, spec *machines.Spec) bool {
	if spec.Provisioner.Name == "" || spec.Provisioner.Version == "" {
		taskError(w, http.StatusBadRequest, "provisioner {name, version} is required")
		return false
	}
	if _, err := s.provisioners.GetVersion(spec.Provisioner.Name, spec.Provisioner.Version); err != nil {
		if errors.Is(err, provisioner.ErrNotFound) || errors.Is(err, provisioner.ErrVersionNotFound) {
			taskError(w, http.StatusBadRequest,
				"provisioner "+spec.Provisioner.Name+"/"+spec.Provisioner.Version+" is not in the registry")
			return false
		}
		slog.Error("resolve provisioner for machine spec", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to resolve provisioner")
		return false
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

// renderForResolution renders the package template once so the handler sees
// the EFFECTIVE settings (template defaults applied) — the box tuple the
// template registry resolves may come entirely from package defaults.
func (s *Server) renderForResolution(ctx context.Context, spec *machines.Spec) (map[string]any, error) {
	version, err := s.provisioners.GetVersion(spec.Provisioner.Name, spec.Provisioner.Version)
	if err != nil {
		return nil, err
	}
	rendered, err := provisioner.RenderHostsFile(&provisioner.GenerateInput{
		Version:            version,
		Settings:           machines.EffectiveSettings(ctx, spec, s.cfg.Provisioning.DefaultSyncMethod, s.cfg.Provisioning.DefaultNetworkInterface),
		Networks:           spec.Networks,
		Roles:              spec.Roles,
		UserProperties:     spec.Properties,
		AdvancedProperties: spec.AdvancedProperties,
		SecretsVars:        s.secrets.TemplateVars(),
	})
	if err != nil {
		return nil, err
	}
	return machines.ParseHostsDocument(rendered)
}

// queueCreateOrchestration creates the parent + chained children (the base's
// createZoneCreationSubTasks + handleAutoDownload): template_download first
// when the box is not local, then prepare → storage → config → finalize
// (every child carries the spec verbatim), then the optional start child.
func (s *Server) queueCreateOrchestration(ctx context.Context, name string, spec *machines.Spec,
	document map[string]any, startAfter bool, createdBy string,
) (parentID string, subTasks map[string]string, requiresDownload bool, err error) {
	settings := machines.MachineConfig(document).Section("settings")
	box := machines.DocString(settings["box"], "")
	org, boxName, boxOK := strings.Cut(box, "/")
	if !boxOK || org == "" || boxName == "" {
		return "", nil, false, errors.New(`settings.box must be "organization/box-name" (set it in the spec or the package defaults)`)
	}
	boxVersion := machines.DocString(settings["box_version"], "latest")
	boxArch := machines.DocString(settings["box_arch"], "amd64")

	_, terr := s.machines.FindTemplate(ctx, org, boxName, boxVersion, boxArch)
	switch {
	case terr == nil:
	case errors.Is(terr, machines.ErrTemplateNotFound):
		requiresDownload = true
		if boxVersion == "" || boxVersion == "latest" {
			return "", nil, false, errors.New("template " + box + " is not local and box_version is not specific — set settings.box_version to download it")
		}
	default:
		return "", nil, false, terr
	}

	specDoc, err := json.Marshal(map[string]any{"spec": spec})
	if err != nil {
		return "", nil, false, err
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
		return "", nil, false, err
	}
	cancelChain := func() {
		if _, cerr := s.tasks.Cancel(ctx, parent.ID); cerr != nil {
			slog.Warn("cancel half-built create orchestration", "task_id", parent.ID, "error", cerr)
		}
	}

	subTasks = map[string]string{}
	var previous *string
	if requiresDownload {
		source, serr := machines.FindTemplateSourceForURL(s.templateSources(),
			machines.DocString(settings["box_url"], ""))
		if serr != nil {
			cancelChain()
			return "", nil, false, serr
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
			return "", nil, false, merr
		}
		downloadStr := string(downloadMeta)
		download, derr := s.createChainTask(ctx, "system", machines.OpTemplateDownload,
			&downloadStr, nil, parent.ID, createdBy)
		if derr != nil {
			cancelChain()
			return "", nil, false, derr
		}
		subTasks["template_download"] = download.ID
		previous = &download.ID
	}

	for _, step := range []struct {
		key       string
		operation string
	}{
		{"prepare", machines.OpPrepare},
		{"storage", machines.OpCreateStorage},
		{"config", machines.OpCreateConfig},
		{"finalize", machines.OpCreateFinalize},
	} {
		child, cerr := s.createChainTask(ctx, name, step.operation, &metadata, previous, parent.ID, createdBy)
		if cerr != nil {
			cancelChain()
			return "", nil, false, cerr
		}
		subTasks[step.key] = child.ID
		previous = &child.ID
	}
	if startAfter {
		start, serr := s.createChainTask(ctx, name, machines.OpStart, nil, previous, parent.ID, createdBy)
		if serr != nil {
			cancelChain()
			return "", nil, false, serr
		}
		subTasks["start"] = start.ID
	}
	return parent.ID, subTasks, requiresDownload, nil
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

	document, err := s.renderForResolution(r.Context(), &body.Spec)
	if err != nil {
		taskError(w, http.StatusBadRequest, "Template render failed: "+err.Error())
		return
	}

	createdBy := auth.FromContext(r.Context()).Name
	parentID, subTasks, requiresDownload, err := s.queueCreateOrchestration(
		r.Context(), name, &body.Spec, document, body.StartAfterCreate, createdBy)
	if err != nil {
		taskError(w, http.StatusBadRequest, err.Error())
		return
	}

	slog.Info("machine creation queued", "machine", name,
		"provisioner", body.Provisioner.Name+"/"+body.Provisioner.Version,
		"requires_download", requiresDownload, "by", createdBy)
	message := "Machine creation queued"
	if requiresDownload {
		message = "Template download and machine creation queued"
	}
	writeJSON(w, map[string]any{
		"success":           true,
		"parent_task_id":    parentID,
		"machine_name":      name,
		"operation":         machines.OpCreateOrchestration,
		"status":            tasks.StatusPending,
		"message":           message,
		"requires_download": requiresDownload,
		"sub_tasks":         subTasks,
	})
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
			"Only machines created from a provisioner package can be cloned — this machine has no creation spec")
		return
	}
	var body struct {
		Name             string         `json:"name"`
		Settings         map[string]any `json:"settings"`
		Overrides        map[string]any `json:"overrides"`
		StartAfterCreate bool           `json:"start_after_create"`
	}
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
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

	document, err := s.renderForResolution(r.Context(), spec)
	if err != nil {
		taskError(w, http.StatusBadRequest, "Template render failed: "+err.Error())
		return
	}
	createdBy := auth.FromContext(r.Context()).Name
	parentID, subTasks, requiresDownload, err := s.queueCreateOrchestration(
		r.Context(), name, spec, document, body.StartAfterCreate, createdBy)
	if err != nil {
		taskError(w, http.StatusBadRequest, err.Error())
		return
	}
	slog.Info("machine clone queued", "source", source.Name, "clone", name, "by", createdBy)
	writeJSON(w, map[string]any{
		"success":           true,
		"parent_task_id":    parentID,
		"machine_name":      name,
		"source_machine":    source.Name,
		"operation":         machines.OpCreateOrchestration,
		"status":            tasks.StatusPending,
		"message":           "Machine clone creation queued",
		"requires_download": requiresDownload,
		"sub_tasks":         subTasks,
	})
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
