package server

import (
	"encoding/json"
	"net/http"

	"github.com/goccy/go-yaml"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
)

type previewMachineResponse struct {
	YAML     string            `json:"yaml"`
	Hosts    []json.RawMessage `json:"hosts"`
	Warnings []string          `json:"warnings"`
}

// @Summary		Preview a machine's document
// @Description	Minimum role: operator. Takes the body of POST /api/machines, runs its validation and answers its 400s and its 422 map, then answers the Hosts.yml the create would store without writing or queueing anything: yaml is the package's rendered Hosts.template.yml and hosts its hosts[] entries parsed with their key order kept; a provisioner-less body answers the document the create would build from the spec as one hosts[] entry. warnings carries the typed-disk warnings the create's resource_warnings would.
// @Tags			Machine Management
// @Accept			json
// @Produce		json
// @Param			request	body		createMachineRequest	true	"The body of POST /api/machines"
// @Success		200	{object}	previewMachineResponse	"The document"
// @Failure		400	"Invalid spec or template render failure, as POST /api/machines refuses"
// @Failure		422	{object}	map[string]string	"Form answers fail the package's Field DSL — the body IS the {FIELD: message} map"
// @Router			/api/machines/preview [post]
func (s *Server) handlePreviewMachine(w http.ResponseWriter, r *http.Request) {
	var body createMachineRequest
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	specOK, diskWarnings := s.validateSpec(w, &body.Spec)
	if !specOK {
		return
	}
	warnings := diskWarnings
	if warnings == nil {
		warnings = []string{}
	}
	if body.HasProvisioner() {
		rendered, err := s.renderHosts(r.Context(), &body.Spec, s.personsOfKeyName(auth.FromContext(r.Context()).Name))
		if err != nil {
			taskError(w, http.StatusBadRequest, "Template render failed: "+err.Error())
			return
		}
		hosts, err := machines.ParseHostsDocumentsOrdered(rendered)
		if err != nil {
			taskError(w, http.StatusBadRequest, "Template render failed: "+err.Error())
			return
		}
		writeJSON(w, previewMachineResponse{YAML: string(rendered), Hosts: hosts, Warnings: warnings})
		return
	}
	document := machines.SpecDocument(r.Context(), &body.Spec,
		s.cfg.Provisioning.DefaultSyncMethod, s.cfg.Provisioning.DefaultNetworkInterface)
	rendered, err := yaml.Marshal(map[string]any{"hosts": []any{document}})
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to render the document")
		return
	}
	raw, err := json.Marshal(document)
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to render the document")
		return
	}
	writeJSON(w, previewMachineResponse{YAML: string(rendered), Hosts: []json.RawMessage{raw}, Warnings: warnings})
}
