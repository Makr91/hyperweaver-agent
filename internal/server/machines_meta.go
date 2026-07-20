package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// Machine notes and tags endpoints (Agent API v1 machines surface). These are
// registry-only metadata operations — no tasks are queued.

type machineNotesResponse struct {
	MachineName string  `json:"machine_name"`
	Notes       *string `json:"notes"`
}

// handleGetMachineNotes / handleUpdateMachineNotes mirror the Node agent's
// notes endpoints (registry-only, no task).
//
//	@Summary		Machine notes
//	@Description	Minimum role: viewer.
//	@Tags			Machine Management
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{object}	machineNotesResponse	"Notes"
//	@Failure		404	"Machine not found"
//	@Router			/machines/{machineName}/notes [get]
func (s *Server) handleGetMachineNotes(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	writeJSON(w, machineNotesResponse{
		MachineName: machine.Name,
		Notes:       machine.Notes,
	})
}

type machineNotesRequest struct {
	Notes *string `json:"notes"`
}

// @Summary		Update machine notes
// @Description	Minimum role: operator. Registry-only, no task.
// @Tags			Machine Management
// @Accept			json
// @Param			machineName	path	string	true	"Machine name"
// @Param			request	body	machineNotesRequest	true	"Notes to set"
// @Success		200	"Notes updated"
// @Failure		404	"Machine not found"
// @Router			/machines/{machineName}/notes [put]
func (s *Server) handleUpdateMachineNotes(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	raw := map[string]json.RawMessage{}
	if err := decodeBody(r, &raw); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	rawNotes, present := raw["notes"]
	if !present {
		taskError(w, http.StatusBadRequest, "notes field is required")
		return
	}
	var body machineNotesRequest
	if string(rawNotes) != "null" {
		if err := json.Unmarshal(rawNotes, &body.Notes); err != nil {
			taskError(w, http.StatusBadRequest, "notes must be a string or null")
			return
		}
	}
	if body.Notes != nil && *body.Notes == "" {
		body.Notes = nil
	}

	if err := s.machines.SetNotes(r.Context(), machine.Name, body.Notes); err != nil {
		slog.Error("update machine notes", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to update machine notes")
		return
	}
	writeJSON(w, map[string]any{
		"success":      true,
		"machine_name": machine.Name,
		"notes":        body.Notes,
	})
}

type machineTagsResponse struct {
	MachineName string   `json:"machine_name"`
	Tags        []string `json:"tags"`
}

// handleGetMachineTags / handleUpdateMachineTags mirror the Node agent's tags
// endpoints.
//
//	@Summary		Machine tags
//	@Description	Minimum role: viewer.
//	@Tags			Machine Management
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{object}	machineTagsResponse	"Tags"
//	@Failure		404	"Machine not found"
//	@Router			/machines/{machineName}/tags [get]
func (s *Server) handleGetMachineTags(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	tags := []string{}
	if machine.Tags != nil {
		if err := json.Unmarshal(machine.Tags, &tags); err != nil {
			slog.Error("decode machine tags", "machine", machine.Name, "error", err)
			taskError(w, http.StatusInternalServerError, "Failed to retrieve machine tags")
			return
		}
	}
	writeJSON(w, machineTagsResponse{
		MachineName: machine.Name,
		Tags:        tags,
	})
}

type machineTagsRequest struct {
	Tags []string `json:"tags"`
}

// @Summary		Update machine tags
// @Description	Minimum role: operator. Registry-only, no task.
// @Tags			Machine Management
// @Accept			json
// @Param			machineName	path	string	true	"Machine name"
// @Param			request	body	machineTagsRequest	true	"Tags to set"
// @Success		200	"Tags updated"
// @Failure		404	"Machine not found"
// @Router			/machines/{machineName}/tags [put]
func (s *Server) handleUpdateMachineTags(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	raw := map[string]json.RawMessage{}
	if err := decodeBody(r, &raw); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	rawTags, present := raw["tags"]
	if !present {
		taskError(w, http.StatusBadRequest, "tags field is required")
		return
	}

	var body machineTagsRequest
	if string(rawTags) != "null" {
		if err := json.Unmarshal(rawTags, &body.Tags); err != nil {
			taskError(w, http.StatusBadRequest, "tags must be an array or null")
			return
		}
	}
	var stored json.RawMessage
	if len(body.Tags) > 0 {
		encoded, err := json.Marshal(body.Tags)
		if err != nil {
			slog.Error("serialize machine tags", "error", err)
			taskError(w, http.StatusInternalServerError, "Failed to update machine tags")
			return
		}
		stored = encoded
	}

	if err := s.machines.SetTags(r.Context(), machine.Name, stored); err != nil {
		slog.Error("update machine tags", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to update machine tags")
		return
	}
	response := stored
	if response == nil {
		response = json.RawMessage("[]")
	}
	writeJSON(w, map[string]any{
		"success":      true,
		"machine_name": machine.Name,
		"tags":         response,
	})
}
