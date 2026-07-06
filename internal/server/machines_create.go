package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
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
)

// Machine creation and provisioning operations (Agent API v1 machines
// surface, completed by the provisioning engine — architecture §8): POST
// /machines records the Hosts.yml-shaped spec (no VM until first start,
// SHI's model), PUT /machines/{name} replaces it (materializes on the next
// start), and provision/sync run the vagrant operations through the queue.

// serverIDPattern is the numeric server_id vocabulary (/machines/ids
// constraints).
var serverIDPattern = regexp.MustCompile(`^\d{1,8}$`)

// createMachineRequest is the POST /machines body: the machine name plus
// the creation spec, stored verbatim.
type createMachineRequest struct {
	Name string `json:"name"`
	machines.Spec
}

// validateSpec checks the parts of a creation spec every write shares:
// the provisioner version must exist, role names must be usable as
// directories, and the safe-ID source (when named) must exist.
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
	if spec.Settings == nil {
		spec.Settings = map[string]any{}
	}
	return true
}

// resolveServerID normalizes the spec's server_id: the caller's value is
// validated against the numeric vocabulary and zero-padded to at least 4
// digits (zoneweaver's padStart(4) canonical form); absent means
// auto-assigned MAX+1 (design D-G).
func (s *Server) resolveServerID(ctx context.Context, spec *machines.Spec) (string, error) {
	serverID := ""
	switch v := spec.Settings["server_id"].(type) {
	case string:
		serverID = v
	case float64:
		// JSON numbers arrive as float64; whole values render digit-only,
		// fractional ones fail the numeric pattern below — honestly.
		serverID = strconv.FormatFloat(v, 'f', -1, 64)
	}
	if serverID == "" {
		next, err := s.machines.NextServerID(ctx, s.cfg.Machines.ServerIDStart)
		if err != nil {
			return "", err
		}
		serverID = next
	}
	if !serverIDPattern.MatchString(serverID) {
		return "", errors.New("settings.server_id must be numeric (1-8 digits)")
	}
	if len(serverID) < 4 {
		serverID = strings.Repeat("0", 4-len(serverID)) + serverID
	}
	spec.Settings["server_id"] = serverID
	return serverID, nil
}

// resolveMachineName settles the machine's name (zoneweaver's
// resolveZoneName on top of design D-G): an explicit name always wins —
// names are free-form, anything goes. Absent a name, it is DERIVED from the
// spec: `<server_id>--<hostname>.<domain>` when machines.prefix_machine_names
// is on (Mark's partition-id convention), plain `<hostname>.<domain>`
// otherwise — so hostname (and usually domain) become required exactly when
// the caller asks the agent to name the machine.
func (s *Server) resolveMachineName(explicit, serverID string, spec *machines.Spec) (string, error) {
	if explicit != "" {
		if !validMachineName(explicit) {
			return "", errors.New("invalid machine name")
		}
		return explicit, nil
	}

	hostname, _ := spec.Settings["hostname"].(string)
	if hostname == "" {
		return "", errors.New("name is required (or provide settings.hostname so the agent can derive one)")
	}
	base := hostname
	if domain, _ := spec.Settings["domain"].(string); domain != "" {
		base += "." + domain
	}
	if s.cfg.Machines.PrefixMachineNames {
		base = serverID + "--" + base
	}
	if !validMachineName(base) {
		return "", errors.New("derived machine name " + base + " is not usable — provide an explicit name")
	}
	return base, nil
}

// handleCreateMachine mirrors the Node agent's creation shape for this
// hypervisor: validate, assign the server_id, resolve the name (explicit or
// derived), claim a working directory, store the row (status configured —
// no VM until first start), and optionally chain the first start.
func (s *Server) handleCreateMachine(w http.ResponseWriter, r *http.Request) {
	var body createMachineRequest
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if !s.validateSpec(w, &body.Spec) {
		return
	}
	serverID, err := s.resolveServerID(r.Context(), &body.Spec)
	if err != nil {
		taskError(w, http.StatusBadRequest, err.Error())
		return
	}
	name, err := s.resolveMachineName(body.Name, serverID, &body.Spec)
	if err != nil {
		taskError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, gerr := s.machines.Get(r.Context(), name); gerr == nil {
		taskError(w, http.StatusConflict, "Machine already exists")
		return
	} else if !errors.Is(gerr, machines.ErrNotFound) {
		slog.Error("check machine existence", "machine", name, "error", gerr)
		taskError(w, http.StatusInternalServerError, "Failed to create machine")
		return
	}
	s.createMachineRow(w, r, name, serverID, &body.Spec, body.StartAfterCreate, nil)
}

// createMachineRow finishes a create or clone: claim a working directory,
// store the row (status configured — no VM until first start), and
// optionally queue the first start pipeline. extra entries merge into the
// 201 response (the clone's source_machine et al.).
func (s *Server) createMachineRow(w http.ResponseWriter, r *http.Request, name, serverID string,
	spec *machines.Spec, startAfter bool, extra map[string]any,
) {
	machinesRoot, err := s.cfg.MachinesDir()
	if err != nil {
		slog.Error("resolve machines dir", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to create machine")
		return
	}
	home, err := safepath.Under(machinesRoot, provisioner.MachineDirName(name))
	if err != nil {
		taskError(w, http.StatusBadRequest, "Machine name does not sanitize to a usable directory")
		return
	}
	if taken, terr := s.homeTaken(r.Context(), home); terr != nil {
		slog.Error("check machine home", "error", terr)
		taskError(w, http.StatusInternalServerError, "Failed to create machine")
		return
	} else if taken {
		taskError(w, http.StatusConflict,
			"Another machine already uses the working directory "+home+" — pick a name that sanitizes differently")
		return
	}

	raw, err := json.Marshal(spec)
	if err != nil {
		slog.Error("serialize machine spec", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to create machine")
		return
	}
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	machine, err := s.machines.Create(r.Context(), &machines.NewMachine{
		Name:     name,
		Host:     hostname,
		Home:     home,
		ServerID: serverID,
		Spec:     raw,
	})
	if err != nil {
		slog.Error("create machine", "machine", name, "error", err)
		if strings.Contains(err.Error(), "UNIQUE") {
			taskError(w, http.StatusConflict, "Machine name or server_id already in use")
			return
		}
		taskError(w, http.StatusInternalServerError, "Failed to create machine")
		return
	}
	createdBy := auth.FromContext(r.Context()).Name
	slog.Info("machine created", "machine", machine.Name,
		"provisioner", spec.Provisioner.Name+"/"+spec.Provisioner.Version,
		"by", createdBy)

	response := map[string]any{
		"success":      true,
		"machine":      machine,
		"machine_name": machine.Name,
		"message":      "Machine created successfully",
	}
	for key, value := range extra {
		response[key] = value
	}
	if startAfter {
		parent, terr := s.queueStartPipeline(r.Context(), machine.Name, createdBy)
		if terr != nil {
			slog.Error("queue first start", "machine", machine.Name, "error", terr)
		} else {
			response["task_id"] = parent.ID
			response["message"] = "Machine created; first start queued"
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if werr := json.NewEncoder(w).Encode(response); werr != nil {
		slog.Error("write create response", "error", werr)
	}
}

// handleCloneMachine clones a provisioner-managed machine — zoneweaver's
// clone contract on SHI's clone model (design §4 ruling: a metadata copy,
// fresh name and server_id, NO VM until first start — so no snapshots, no
// task orchestration, a synchronous registry insert). settings.hostname is
// required and domain defaults from the source (zoneweaver rule); overrides
// carries memory/vcpus; consoleport never survives a clone; cloned networks
// lose their MAC and addressing so source and clone can never collide
// (zoneweaver strips NIC identity the same way).
func (s *Server) handleCloneMachine(w http.ResponseWriter, r *http.Request) {
	source := s.findMachine(w, r)
	if source == nil {
		return
	}
	if len(source.Spec) == 0 {
		taskError(w, http.StatusBadRequest,
			"Only provisioner-managed machines can be cloned — this machine has no creation spec")
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
	// server_id is never inherited (fresh MAX+1) unless the caller names one.
	delete(spec.Settings, "server_id")
	// consoleport conflicts between source and clone (zoneweaver deletes it).
	delete(spec.Settings, "consoleport")
	for key, value := range body.Settings {
		spec.Settings[key] = value
	}
	for key, value := range body.Overrides {
		spec.Settings[key] = value
	}
	stripCloneNetworks(spec.Networks)
	spec.StartAfterCreate = false

	// Re-validate: the source's provisioner version or safe-ID file may be
	// gone by now — better a 400 here than a failed first start.
	if !s.validateSpec(w, spec) {
		return
	}
	serverID, err := s.resolveServerID(r.Context(), spec)
	if err != nil {
		taskError(w, http.StatusBadRequest, err.Error())
		return
	}
	name, err := s.resolveMachineName(body.Name, serverID, spec)
	if err != nil {
		taskError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, gerr := s.machines.Get(r.Context(), name); gerr == nil {
		taskError(w, http.StatusConflict, "Machine already exists")
		return
	} else if !errors.Is(gerr, machines.ErrNotFound) {
		slog.Error("check machine existence", "machine", name, "error", gerr)
		taskError(w, http.StatusInternalServerError, "Failed to clone machine")
		return
	}
	slog.Info("machine clone requested", "source", source.Name, "clone", name,
		"by", auth.FromContext(r.Context()).Name)
	s.createMachineRow(w, r, name, serverID, spec, body.StartAfterCreate, map[string]any{
		"source_machine": source.Name,
	})
}

// stripCloneNetworks removes identity and addressing from cloned network
// entries — MACs regenerate and addressing re-derives on the clone's first
// render, so source and clone never collide (zoneweaver's clone strips
// physical/mac_addr off NICs and address/gateway/dns/netmask off networks).
func stripCloneNetworks(networks []any) {
	for _, entry := range networks {
		network, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		for _, key := range []string{"mac", "address", "gateway", "netmask", "dns"} {
			delete(network, key)
		}
	}
}

// homeTaken reports whether another machine row already claims the working
// directory.
func (s *Server) homeTaken(ctx context.Context, home string) (bool, error) {
	list, err := s.machines.List(ctx, &machines.ListFilter{})
	if err != nil {
		return false, err
	}
	for _, machine := range list {
		if machine.Home != nil && strings.EqualFold(*machine.Home, home) {
			return true, nil
		}
	}
	return false, nil
}

// handleModifyMachine replaces a provisioner-managed machine's spec (PUT
// /machines/{name}); the change materializes on the next start —
// requires_restart in the response says exactly that.
func (s *Server) handleModifyMachine(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	if len(machine.Spec) == 0 {
		taskError(w, http.StatusBadRequest,
			"Only provisioner-managed machines can be modified — this machine has no creation spec")
		return
	}

	var spec machines.Spec
	if err := decodeBody(r, &spec); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if !s.validateSpec(w, &spec) {
		return
	}
	// An omitted (or emptied) server_id keeps the machine's own — modify must
	// never mint a fresh MAX+1 for an existing machine.
	if machine.ServerID != nil {
		switch v := spec.Settings["server_id"].(type) {
		case nil:
			spec.Settings["server_id"] = *machine.ServerID
		case string:
			if v == "" {
				spec.Settings["server_id"] = *machine.ServerID
			}
		}
	}
	serverID, err := s.resolveServerID(r.Context(), &spec)
	if err != nil {
		taskError(w, http.StatusBadRequest, err.Error())
		return
	}

	raw, err := json.Marshal(spec)
	if err != nil {
		slog.Error("serialize machine spec", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to modify machine")
		return
	}
	if serr := s.machines.SetSpec(r.Context(), machine.Name, raw, serverID); serr != nil {
		slog.Error("store machine spec", "machine", machine.Name, "error", serr)
		if strings.Contains(serr.Error(), "UNIQUE") {
			taskError(w, http.StatusConflict, "server_id already in use by another machine")
			return
		}
		taskError(w, http.StatusInternalServerError, "Failed to modify machine")
		return
	}
	slog.Info("machine spec updated", "machine", machine.Name,
		"by", auth.FromContext(r.Context()).Name)

	writeJSON(w, map[string]any{
		"success":          true,
		"machine_name":     machine.Name,
		"requires_restart": true,
		"message":          "Machine configuration updated — changes apply on the next start",
	})
}

// handleProvisionMachine queues a provision task (vagrant provision after a
// working-copy refresh).
func (s *Server) handleProvisionMachine(w http.ResponseWriter, r *http.Request) {
	s.queueVagrantOp(w, r, machines.OpProvision, "Provision")
}

// handleSyncMachine queues a sync task (vagrant rsync).
func (s *Server) handleSyncMachine(w http.ResponseWriter, r *http.Request) {
	s.queueVagrantOp(w, r, machines.OpSync, "Sync")
}

// queueVagrantOp is the shared provision/sync queueing flow: provisioned
// machines only, deduplicated, MEDIUM priority.
func (s *Server) queueVagrantOp(w http.ResponseWriter, r *http.Request, operation, label string) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	if !machine.Provisioned() {
		taskError(w, http.StatusBadRequest,
			"Machine is not provisioner-managed — nothing to "+strings.ToLower(label))
		return
	}

	if existing, err := s.dedupTask(r.Context(), machine.Name, operation); err != nil {
		slog.Error("check existing task", "machine", machine.Name, "operation", operation, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue "+strings.ToLower(label)+" task")
		return
	} else if existing != nil {
		operationResponse(w, existing.ID, machine.Name, operation, existing.Status,
			label+" task already queued")
		return
	}

	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: machine.Name,
		Operation:   operation,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   auth.FromContext(r.Context()).Name,
	})
	if err != nil {
		slog.Error("queue task", "machine", machine.Name, "operation", operation, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue "+strings.ToLower(label)+" task")
		return
	}
	operationResponse(w, task.ID, machine.Name, operation, tasks.StatusPending,
		label+" task queued successfully")
}
