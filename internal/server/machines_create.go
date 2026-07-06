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
var serverIDPattern = regexp.MustCompile(`^[0-9]{1,8}$`)

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
	for _, role := range spec.Roles {
		if !provisioner.ValidName(role.Name) {
			taskError(w, http.StatusBadRequest, "role name "+role.Name+" is not usable")
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
	if spec.Settings == nil {
		spec.Settings = map[string]any{}
	}
	return true
}

// resolveServerID normalizes the spec's server_id: the caller's value is
// validated against the numeric vocabulary; absent means auto-assigned
// MAX+1 (design D-G).
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
	spec.Settings["server_id"] = serverID
	return serverID, nil
}

// handleCreateMachine mirrors the Node agent's creation shape for this
// hypervisor: validate, assign the server_id, claim a working directory,
// store the row (status configured — no VM until first start), and
// optionally chain the first start.
func (s *Server) handleCreateMachine(w http.ResponseWriter, r *http.Request) {
	var body createMachineRequest
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if !validMachineName(body.Name) {
		taskError(w, http.StatusBadRequest, "Invalid machine name")
		return
	}
	if _, err := s.machines.Get(r.Context(), body.Name); err == nil {
		taskError(w, http.StatusConflict, "Machine already exists")
		return
	} else if !errors.Is(err, machines.ErrNotFound) {
		slog.Error("check machine existence", "machine", body.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to create machine")
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

	machinesRoot, err := s.cfg.MachinesDir()
	if err != nil {
		slog.Error("resolve machines dir", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to create machine")
		return
	}
	home, err := safepath.Under(machinesRoot, provisioner.MachineDirName(body.Name))
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

	spec, err := json.Marshal(body.Spec)
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
		Name:     body.Name,
		Host:     hostname,
		Home:     home,
		ServerID: serverID,
		Spec:     spec,
	})
	if err != nil {
		slog.Error("create machine", "machine", body.Name, "error", err)
		if strings.Contains(err.Error(), "UNIQUE") {
			taskError(w, http.StatusConflict, "Machine name or server_id already in use")
			return
		}
		taskError(w, http.StatusInternalServerError, "Failed to create machine")
		return
	}
	slog.Info("machine created", "machine", machine.Name,
		"provisioner", body.Provisioner.Name+"/"+body.Provisioner.Version,
		"by", auth.FromContext(r.Context()).Name)

	response := map[string]any{
		"success":      true,
		"machine":      machine,
		"machine_name": machine.Name,
		"message":      "Machine created successfully",
	}
	if body.StartAfterCreate {
		task, terr := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
			MachineName: machine.Name,
			Operation:   machines.OpStart,
			Priority:    tasks.PriorityMedium,
			CreatedBy:   auth.FromContext(r.Context()).Name,
		})
		if terr != nil {
			slog.Error("queue first start", "machine", machine.Name, "error", terr)
		} else {
			response["task_id"] = task.ID
			response["message"] = "Machine created; first start queued"
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if werr := json.NewEncoder(w).Encode(response); werr != nil {
		slog.Error("write create response", "error", werr)
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
	if _, err := s.resolveServerID(r.Context(), &spec); err != nil {
		taskError(w, http.StatusBadRequest, err.Error())
		return
	}

	raw, err := json.Marshal(spec)
	if err != nil {
		slog.Error("serialize machine spec", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to modify machine")
		return
	}
	if serr := s.machines.SetSpec(r.Context(), machine.Name, raw); serr != nil {
		slog.Error("store machine spec", "machine", machine.Name, "error", serr)
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
