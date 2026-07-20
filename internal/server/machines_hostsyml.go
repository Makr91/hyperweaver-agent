package server

import (
	"log/slog"
	"net/http"

	"github.com/Makr91/hyperweaver-agent/internal/machines"
)

type hostsYAMLResponse struct {
	MachineName string `json:"machine_name"`
	// The stored document sections as YAML text
	YAML string `json:"yaml"`
}

// GET/PUT /machines/{machineName}/hosts-yml — the raw-YAML document editor
// surface (frozen cross-agent contract, sync 2026-07-19): the stored document
// sections as YAML text, editable verbatim with key order preserved; the
// converged document pre-flights still answer 400.
//
//	@Summary		The stored document as YAML
//	@Description	Minimum role: viewer. The raw-YAML document surface (the FROZEN cross-agent contract, sync 2026-07-19 — identical route and shapes on both agents): the machine's stored document sections serialized as YAML text, key order preserved. SCOPE: exactly the six document sections — settings, zones, networks, disks, provisioner, metadata; agent bookkeeping (provisioner_state, pending_changes, guest_info, snapshots, host_hooks_confirmed) and the live hypervisor view never appear. On packaged machines this is the STORED document — the pipeline and extra_vars run from it; the working copy's Hosts.yml FILE regenerates from the package render at each provision (a manual vagrant run reads the render).
//	@Tags			Machine Management
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{object}	hostsYAMLResponse	"The document as YAML"
//	@Failure		404	"Machine not found"
//	@Failure		500	"Serialization failure"
//	@Router			/machines/{machineName}/hosts-yml [get]
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
	writeJSON(w, hostsYAMLResponse{
		MachineName: machine.Name,
		YAML:        yamlText,
	})
}

type hostsYAMLRequest struct {
	// The whole document as raw YAML — the six sections, nothing else
	YAML string `json:"yaml"`
}

type hostsYAMLStoreResponse struct {
	// Non-blocking advisories, shown verbatim
	Warnings []string `json:"warnings"`
}

type hostsYAMLProblem struct {
	// Parse errors only
	Column *int   `json:"column,omitempty"`
	Error  string `json:"error"`
	// Parse errors only
	Line *int `json:"line,omitempty"`
}

// @Summary		Replace the stored document from raw YAML
// @Description	Minimum role: operator. The raw-YAML edit half (the FROZEN cross-agent contract, sync 2026-07-19 — the emergency hatch: missing vars, extra roles, hand edits between create-without-start and provision). Body {yaml}. Refusals, nothing stored: unparseable YAML → 400 {error, line, column} (numeric, editor-jumpable); impossible section shapes (root/settings/zones/disks/provisioner/metadata not mappings, networks not a list) → 400 {error}; the converged document pre-flights still gate — consoleport 1025-65535, vcpus whole ≥ 1, the typed-disk frozen strings — the YAML door bypasses NOTHING; a bookkeeping key named in the YAML (provisioner_state, pending_changes, guest_info, snapshots, host_hooks_confirmed) or any unknown top-level key → 400 {error} (it would silently die at the next discovery merge — loud beats silent loss). Otherwise the document stores VERBATIM with KEY ORDER PRESERVED (comments die; the document is the program — provisioning: method keys execute in document order): the six sections replace wholesale, a section ABSENT from the YAML is REMOVED, bookkeeping and the live view survive untouched. 200 {warnings: []} — non-blocking string advisories (bhyve-vocabulary disk keys, no control IP, ...). Unknown keys INSIDE sections ride verbatim.
// @Tags			Machine Management
// @Accept			json
// @Produce		json
// @Param			machineName	path	string	true	"Machine name"
// @Param			request	body	hostsYAMLRequest	true	"The document as raw YAML"
// @Success		200	{object}	hostsYAMLStoreResponse	"Document stored"
// @Failure		400	{object}	hostsYAMLProblem	"Refused, nothing stored — parse error ({error, line, column}), impossible shape, converged pre-flight, bookkeeping/unknown top-level key ({error})"
// @Failure		404	"Machine not found"
// @Router			/machines/{machineName}/hosts-yml [put]
func (s *Server) handlePutHostsYAML(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	var body hostsYAMLRequest
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
		problem := hostsYAMLProblem{Error: result.Problem}
		if result.Line > 0 {
			problem.Line = &result.Line
			problem.Column = &result.Column
		}
		writeJSONStatus(w, http.StatusBadRequest, problem)
		return
	}
	writeJSON(w, hostsYAMLStoreResponse{Warnings: result.Warnings})
}
