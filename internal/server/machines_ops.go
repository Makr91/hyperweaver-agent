package server

// Verb-survey machine operations (Mark's go 2026-07-12): OVA/OVF import,
// movevm relocation, and the guest display resize hint.

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// applianceImportResponse is POST /machines/import's queued answer (202).
type applianceImportResponse struct {
	Success   bool   `json:"success"`
	TaskID    string `json:"task_id"`
	Path      string `json:"path"`
	Operation string `json:"operation"`
	Status    string `json:"status"`
	Message   string `json:"message"`
}

// handleImportMachine serves POST /machines/import — queue a machine_import
// task: VBoxManage import of an agent-host .ova/.ovf into the machines root;
// the reconciliation sweep lands the registry row afterwards.
//
//	@Summary		Import an OVA/OVF appliance
//	@Description	Minimum role: operator. Queues machine_import: VBoxManage import of an agent-host .ova/.ovf into the machines root (--vsys 0; name overrides the appliance's suggested machine name), followed by a reconciliation sweep that lands the registry row (auto_discovered, spec-less — like any machine built outside the agent). Export's pair.
//	@Tags			Machine Management
//	@Accept			json
//	@Produce		json
//	@Param			request	body	machines.ImportMetadata	true	"Appliance path and optional machine-name override"
//	@Success		202	{object}	applianceImportResponse	"Import task queued ({success, task_id, path, operation, status, message})"
//	@Failure		400	{object}	taskErrorBody	"Missing/invalid path, not .ova/.ovf, file absent, or invalid name"
//	@Failure		409	{object}	taskErrorBody	"A machine with that name already exists"
//	@Router			/machines/import [post]
func (s *Server) handleImportMachine(w http.ResponseWriter, r *http.Request) {
	var body machines.ImportMetadata
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.Path == "" {
		taskError(w, http.StatusBadRequest, "path is required (an .ova or .ovf on the agent host)")
		return
	}
	switch strings.ToLower(filepath.Ext(body.Path)) {
	case ".ova", ".ovf":
	default:
		taskError(w, http.StatusBadRequest, "path must name an .ova or .ovf file")
		return
	}
	if _, serr := os.Stat(filepath.Clean(filepath.FromSlash(body.Path))); serr != nil {
		taskError(w, http.StatusBadRequest, "Appliance file not found on the agent host: "+body.Path)
		return
	}
	taskMachine := "system"
	if body.Name != "" {
		if !validMachineName(body.Name) {
			taskError(w, http.StatusBadRequest, "Invalid machine name")
			return
		}
		if _, gerr := s.machines.Get(r.Context(), body.Name); gerr == nil {
			taskError(w, http.StatusConflict, "A machine named "+body.Name+" already exists")
			return
		} else if !errors.Is(gerr, machines.ErrNotFound) {
			taskError(w, http.StatusInternalServerError, "Failed to check machine name")
			return
		}
		taskMachine = body.Name
	}

	raw, err := json.Marshal(&body)
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to queue import task")
		return
	}
	metadata := string(raw)
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: taskMachine,
		Operation:   machines.OpImport,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   auth.FromContext(r.Context()).Name,
		Metadata:    &metadata,
	})
	if err != nil {
		slog.Error("queue import task", "path", body.Path, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue import task")
		return
	}
	writeJSONStatus(w, http.StatusAccepted, applianceImportResponse{
		Success:   true,
		TaskID:    task.ID,
		Path:      body.Path,
		Operation: machines.OpImport,
		Status:    tasks.StatusPending,
		Message:   "Appliance import task queued successfully",
	})
}

// queuedOperation is the queued-operation answer shape (operationResponse's
// wire, the QueuedOperation contract): a task id plus the machine, operation,
// status, and message.
type queuedOperation struct {
	Success     bool   `json:"success"`
	TaskID      string `json:"task_id,omitempty"`
	MachineName string `json:"machine_name"`
	Operation   string `json:"operation"`
	Status      string `json:"status"`
	Message     string `json:"message"`
}

// handleMoveMachine serves POST /machines/{machineName}/move — queue a
// machine_move task (VBoxManage movevm; powered-off machines only).
//
//	@Summary		Relocate a machine's VirtualBox files
//	@Description	Minimum role: operator. Queues machine_move (VBoxManage movevm --type basic): the .vbox, snapshots, and machine-stored media land under target_path. Powered-off machines only. The agent's working directory (provisioner documents, installers) does NOT move.
//	@Tags			Machine Management
//	@Accept			json
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Param			request	body	machines.MoveMetadata	true	"Destination directory"
//	@Success		200	{object}	queuedOperation	"Move task queued"
//	@Failure		400	{object}	taskErrorBody	"Missing target_path, or machine is not powered off"
//	@Failure		404	{object}	taskErrorBody	"Machine not found"
//	@Router			/machines/{machineName}/move [post]
func (s *Server) handleMoveMachine(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	var body machines.MoveMetadata
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.TargetPath == "" {
		taskError(w, http.StatusBadRequest, "target_path is required")
		return
	}
	switch liveMachineStatus(r.Context(), machine) {
	case machines.StatusStopped, machines.StatusAborted:
	default:
		taskError(w, http.StatusBadRequest, "Machine must be powered off to move its files")
		return
	}
	raw, err := json.Marshal(&body)
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to queue move task")
		return
	}
	metadata := string(raw)
	s.queueMachineOp(w, r, machine, machines.OpMove, tasks.PriorityMedium, &metadata,
		"Move task queued successfully")
}

// unattendedDetectResponse is GET /machines/unattended/detect's answer: the
// probed ISO path and VBoxManage's snake-cased detection fields.
type unattendedDetectResponse struct {
	Iso      string            `json:"iso"`
	Detected map[string]string `json:"detected"`
}

// handleUnattendedDetect serves GET /machines/unattended/detect?iso= —
// synchronous VBoxManage unattended detect: what an installer ISO contains
// and whether unattended installation supports it (the wizard's probe).
//
//	@Summary		Probe an installer ISO
//	@Description	Minimum role: viewer. Synchronous VBoxManage unattended detect — what the ISO contains and whether VirtualBox can install it unattended. iso is an agent-host path (cached ISOs carry theirs in GET /artifacts/iso's path field). detected keys are VBoxManage's own fields snake_cased (os_typeid, os_version, os_flavor, os_languages, os_hints, unattended_installation_supported).
//	@Tags			Machine Management
//	@Produce		json
//	@Param			iso	query	string	true	"Agent-host ISO path"
//	@Success		200	{object}	unattendedDetectResponse	"Detection result"
//	@Failure		400	{object}	taskErrorBody	"Missing iso, or file absent"
//	@Failure		500	{object}	taskErrorBody	"Detection failed"
//	@Failure		503	{object}	taskErrorBody	"VirtualBox is not installed"
//	@Router			/machines/unattended/detect [get]
func (s *Server) handleUnattendedDetect(w http.ResponseWriter, r *http.Request) {
	iso := r.URL.Query().Get("iso")
	if iso == "" {
		taskError(w, http.StatusBadRequest, "iso query parameter is required (an agent-host ISO path — cached ISOs carry theirs on GET /artifacts/iso)")
		return
	}
	if _, serr := os.Stat(filepath.Clean(filepath.FromSlash(iso))); serr != nil {
		taskError(w, http.StatusBadRequest, "ISO not found on the agent host: "+iso)
		return
	}
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}
	detected, err := vbox.UnattendedDetect(r.Context(), exe, iso)
	if err != nil {
		slog.Error("unattended detect", "iso", iso, "error", err)
		taskError(w, http.StatusInternalServerError, "Detection failed: "+err.Error())
		return
	}
	writeJSON(w, unattendedDetectResponse{Iso: iso, Detected: detected})
}

// unattendedInstallRequest is POST /machines/{machineName}/unattended's body:
// the UnattendedMetadata document with the created account flattened to
// top-level user/password (the handler's wire shape).
type unattendedInstallRequest struct {
	machines.UnattendedMetadata
	User     string `json:"user"`
	Password string `json:"password"`
}

// handleUnattendedInstall serves POST /machines/{machineName}/unattended —
// queue machine_unattended_install (VBoxManage's answer-file install onto an
// existing powered-off machine). The flat wire body maps onto the metadata
// document with the account nested (the provision chain's credentials shape).
//
//	@Summary		Start an unattended OS install
//	@Description	Minimum role: operator. Queues machine_unattended_install — VBoxManage's own answer-file machinery onto an EXISTING powered-off machine (create a diskless/scratch-disk machine first; probe the ISO via GET /machines/unattended/detect). The ISO comes as path (agent-host file) or iso (cached-ISO filename, cdroms[]'s vocabulary — resolved through the artifact registry). VirtualBox prepares the distro-appropriate unattended script and — with start (default true) — boots the machine headless straight into the installer; watch progress on the console or screenshot. user/password are the account the installer creates; image_index picks the Windows edition; install_additions slipstreams Guest Additions. The password rides task metadata (stored credentials are never redacted — Mark's visibility ruling).
//	@Tags			Machine Management
//	@Accept			json
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Param			request	body	unattendedInstallRequest	true	"Installer ISO, the account to create, and unattended options"
//	@Success		200	{object}	queuedOperation	"Unattended install task queued"
//	@Failure		400	{object}	taskErrorBody	"Missing ISO reference or credentials, or machine not powered off"
//	@Failure		404	{object}	taskErrorBody	"Machine not found"
//	@Router			/machines/{machineName}/unattended [post]
func (s *Server) handleUnattendedInstall(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	var body unattendedInstallRequest
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.Path == "" && body.Iso == "" {
		taskError(w, http.StatusBadRequest, "An installer ISO is required: path (agent-host file) or iso (cached-ISO filename)")
		return
	}
	if body.User == "" || body.Password == "" {
		taskError(w, http.StatusBadRequest, "user and password are required (the account the installer creates)")
		return
	}
	switch liveMachineStatus(r.Context(), machine) {
	case machines.StatusStopped, machines.StatusAborted:
	default:
		taskError(w, http.StatusBadRequest, "Unattended install needs a powered-off machine")
		return
	}
	meta := body.UnattendedMetadata
	meta.Account = machines.UnattendedAccount{User: body.User, Password: body.Password}
	raw, err := json.Marshal(&meta)
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to queue unattended install")
		return
	}
	metadata := string(raw)
	s.queueMachineOp(w, r, machine, machines.OpUnattended, tasks.PriorityMedium, &metadata,
		"Unattended install task queued successfully")
}

// displayHintRequest is POST /machines/{machineName}/display's body — the
// target video mode hint.
type displayHintRequest struct {
	Width   int `json:"width"`
	Height  int `json:"height"`
	Depth   int `json:"depth"`
	Display int `json:"display"`
}

// displayHintResponse is POST /machines/{machineName}/display's answer.
type displayHintResponse struct {
	Success     bool   `json:"success"`
	MachineName string `json:"machine_name"`
	Message     string `json:"message"`
}

// handleSetDisplay serves POST /machines/{machineName}/display — synchronous
// controlvm setvideomodehint (honored by guests running Guest Additions).
//
//	@Summary		Resize the guest display
//	@Description	Minimum role: operator. Synchronous VBoxManage controlvm setvideomodehint — asks the running guest to resize its display; honored by guests running Guest Additions (a guest without them ignores the hint, honestly).
//	@Tags			Machine Management
//	@Accept			json
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Param			request	body	displayHintRequest	true	"Target resolution and optional depth/display"
//	@Success		200	{object}	displayHintResponse	"Hint sent ({success, machine_name, message})"
//	@Failure		400	{object}	taskErrorBody	"Missing width/height, or machine is not running"
//	@Failure		404	{object}	taskErrorBody	"Machine not found"
//	@Failure		503	{object}	taskErrorBody	"VirtualBox is not installed"
//	@Router			/machines/{machineName}/display [post]
func (s *Server) handleSetDisplay(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	var body displayHintRequest
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.Width < 1 || body.Height < 1 {
		taskError(w, http.StatusBadRequest, "width and height are required")
		return
	}
	if body.Depth == 0 {
		body.Depth = 32
	}
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}
	if liveMachineStatus(r.Context(), machine) != machines.StatusRunning {
		taskError(w, http.StatusBadRequest, "Can only resize a running machine's display")
		return
	}
	if err := vbox.SetVideoModeHint(r.Context(), exe, machine.VBoxTarget(),
		body.Width, body.Height, body.Depth, body.Display); err != nil {
		slog.Error("set video mode hint", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to set the display hint")
		return
	}
	writeJSON(w, displayHintResponse{
		Success:     true,
		MachineName: machine.Name,
		Message:     "Display resize hint sent (guests honor it via Guest Additions)",
	})
}
