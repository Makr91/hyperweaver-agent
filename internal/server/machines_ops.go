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

// handleImportMachine serves POST /machines/import — queue a machine_import
// task: VBoxManage import of an agent-host .ova/.ovf into the machines root;
// the reconciliation sweep lands the registry row afterwards.
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
	writeJSONStatus(w, http.StatusAccepted, map[string]any{
		"success":   true,
		"task_id":   task.ID,
		"path":      body.Path,
		"operation": machines.OpImport,
		"status":    tasks.StatusPending,
		"message":   "Appliance import task queued successfully",
	})
}

// handleMoveMachine serves POST /machines/{machineName}/move — queue a
// machine_move task (VBoxManage movevm; powered-off machines only).
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

// handleUnattendedDetect serves GET /machines/unattended/detect?iso= —
// synchronous VBoxManage unattended detect: what an installer ISO contains
// and whether unattended installation supports it (the wizard's probe).
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
	writeJSON(w, map[string]any{"iso": iso, "detected": detected})
}

// handleUnattendedInstall serves POST /machines/{machineName}/unattended —
// queue machine_unattended_install (VBoxManage's answer-file install onto an
// existing powered-off machine). The flat wire body maps onto the metadata
// document with the account nested (the provision chain's credentials shape).
func (s *Server) handleUnattendedInstall(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	var body struct {
		machines.UnattendedMetadata
		User     string `json:"user"`
		Password string `json:"password"`
	}
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

// handleSetDisplay serves POST /machines/{machineName}/display — synchronous
// controlvm setvideomodehint (honored by guests running Guest Additions).
func (s *Server) handleSetDisplay(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	var body struct {
		Width   int `json:"width"`
		Height  int `json:"height"`
		Depth   int `json:"depth"`
		Display int `json:"display"`
	}
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
	writeJSON(w, map[string]any{
		"success":      true,
		"machine_name": machine.Name,
		"message":      "Display resize hint sent (guests honor it via Guest Additions)",
	})
}
