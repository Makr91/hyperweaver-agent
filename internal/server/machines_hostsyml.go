package server

import (
	"log/slog"
	"net/http"

	"github.com/Makr91/hyperweaver-agent/internal/machines"
)

// GET/PUT /machines/{machineName}/hosts-yml — the raw-YAML document editor
// surface (frozen cross-agent contract, sync 2026-07-19): the stored document
// sections as YAML text, editable verbatim with key order preserved; the
// converged document pre-flights still answer 400.

func (s *Server) handleGetHostsYAML(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	yamlText, err := machines.DocumentYAML(machine)
	if err != nil {
		slog.Error("serialize hosts-yml", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to serialize the stored document")
		return
	}
	writeJSON(w, map[string]any{
		"machine_name": machine.Name,
		"yaml":         yamlText,
	})
}

func (s *Server) handlePutHostsYAML(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	var body struct {
		YAML string `json:"yaml"`
	}
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.YAML == "" {
		taskError(w, http.StatusBadRequest, "yaml is required")
		return
	}
	result, err := s.machines.StoreDocumentYAML(r.Context(), machine, body.YAML)
	if err != nil {
		slog.Error("store hosts-yml", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to store the document")
		return
	}
	if result.Problem != "" {
		response := map[string]any{"error": result.Problem}
		if result.Line > 0 {
			response["line"] = result.Line
			response["column"] = result.Column
		}
		writeJSONStatus(w, http.StatusBadRequest, response)
		return
	}
	writeJSON(w, map[string]any{"warnings": result.Warnings})
}
