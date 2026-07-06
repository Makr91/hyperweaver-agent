package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// Machine notes and tags endpoints (Agent API v1 machines surface). These are
// registry-only metadata operations — no tasks are queued.

// handleGetMachineNotes / handleUpdateMachineNotes mirror the Node agent's
// notes endpoints (registry-only, no task).
func (s *Server) handleGetMachineNotes(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	writeJSON(w, map[string]any{
		"machine_name": machine.Name,
		"notes":        machine.Notes,
	})
}

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
	var notes *string
	if string(rawNotes) != "null" {
		if err := json.Unmarshal(rawNotes, &notes); err != nil {
			taskError(w, http.StatusBadRequest, "notes must be a string or null")
			return
		}
	}
	if notes != nil && *notes == "" {
		notes = nil
	}

	if err := s.machines.SetNotes(r.Context(), machine.Name, notes); err != nil {
		slog.Error("update machine notes", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to update machine notes")
		return
	}
	writeJSON(w, map[string]any{
		"success":      true,
		"machine_name": machine.Name,
		"notes":        notes,
	})
}

// handleGetMachineTags / handleUpdateMachineTags mirror the Node agent's tags
// endpoints.
func (s *Server) handleGetMachineTags(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	tags := machine.Tags
	if tags == nil {
		tags = json.RawMessage("[]")
	}
	writeJSON(w, map[string]any{
		"machine_name": machine.Name,
		"tags":         tags,
	})
}

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

	var tags []string
	if string(rawTags) != "null" {
		if err := json.Unmarshal(rawTags, &tags); err != nil {
			taskError(w, http.StatusBadRequest, "tags must be an array or null")
			return
		}
	}
	var stored json.RawMessage
	if len(tags) > 0 {
		encoded, err := json.Marshal(tags)
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
