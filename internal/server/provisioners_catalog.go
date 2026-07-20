package server

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/provisioner"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// catalogSourceList converts the configured catalogs into the provisioner
// package's source shape.
func (s *Server) catalogSourceList() []provisioner.CatalogSource {
	sources := make([]provisioner.CatalogSource, 0, len(s.cfg.CatalogSources.Sources))
	for _, source := range s.cfg.CatalogSources.Sources {
		sources = append(sources, provisioner.CatalogSource{
			Name:    source.Name,
			URL:     source.URL,
			Enabled: source.Enabled,
			Default: source.Default,
			CAFile:  source.CAFile,
		})
	}
	return sources
}

// catalogSourceRow is one entry of GET /provisioning/catalog/sources.
type catalogSourceRow struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Default bool   `json:"default"`
}

// listCatalogSourcesResponse is GET /provisioning/catalog/sources's answer.
type listCatalogSourcesResponse struct {
	Enabled bool               `json:"enabled"`
	Sources []catalogSourceRow `json:"sources"`
}

// handleListCatalogSources lists the enabled catalog definitions (the
// templates/sources shape — never the CA file path).
//
//	@Summary		List configured provisioner catalogs
//	@Description	Minimum role: viewer. The enabled catalog_sources definitions (name, url, default) — the HACS model's registries; fork the catalog repo and add your own as another source. CA bundles are never returned.
//	@Tags			Provisioning
//	@Produce		json
//	@Success		200	{object}	listCatalogSourcesResponse	"Enabled catalogs"
//	@Router			/provisioning/catalog/sources [get]
func (s *Server) handleListCatalogSources(w http.ResponseWriter, _ *http.Request) {
	sources := []catalogSourceRow{}
	for _, source := range s.catalogSourceList() {
		if !source.Enabled {
			continue
		}
		sources = append(sources, catalogSourceRow{
			Name:    source.Name,
			URL:     source.URL,
			Default: source.Default,
		})
	}
	// enabled = zoneweaver's converged field (its provisioning.catalog_sources
	// carries a subsystem gate); this agent has no catalog kill-switch, so the
	// honest constant is true.
	writeJSON(w, listCatalogSourcesResponse{Enabled: true, Sources: sources})
}

// handleGetCatalog fetches one catalog's document live (?source= names a
// configured catalog; empty = the default) — parsed, format_version-gated,
// relayed with the source name.
//
//	@Summary		Browse a provisioner catalog
//	@Description	Minimum role: viewer. Fetches the source's catalog.json LIVE (?source= names a configured catalog; empty = the default), validates format_version 1, and relays the parsed document: {name, format_version, updated, provisioners: [{name, repo, description, versions: [{version, artifacts: [{url, checksum_type, checksum}]}]}]} — versions semver-DESC, artifact URLs OPAQUE (release tags carry slashes; never parse or construct them). Versions may disappear between fetches when an author deletes a release.
//	@Tags			Provisioning
//	@Produce		json
//	@Param			source	query	string	false	"A configured catalog source; empty = the default"
//	@Success		200	{object}	provisioner.CatalogDocument	"The catalog document — the parsed catalog.json IS the response (no envelope; the resolved source rides /provisioning/catalog/sources)"
//	@Failure		404	"No such (or no default) enabled catalog source"
//	@Failure		502	"Catalog unreachable, unparseable, or wrong format_version"
//	@Router			/provisioning/catalog [get]
func (s *Server) handleGetCatalog(w http.ResponseWriter, r *http.Request) {
	source, err := provisioner.FindCatalogSource(s.catalogSourceList(), r.URL.Query().Get("source"))
	if err != nil {
		taskError(w, http.StatusNotFound, err.Error())
		return
	}
	document, err := provisioner.FetchCatalog(r.Context(), source)
	if err != nil {
		slog.Error("fetch provisioner catalog", "source", source.Name, "error", err)
		taskError(w, http.StatusBadGateway, err.Error())
		return
	}
	// Parsed relay, the shared wire (UI's 2026-07-17 flag — the wrap was a
	// bug on BOTH agents once): the catalog document IS the response; the
	// resolved source rides /provisioning/catalog/sources, never an envelope.
	writeJSON(w, document)
}

// handleCatalogInstall queues provisioner_catalog_install: download the
// named family/version's VERSIONED asset, verify its sha256, import.
//
//	@Summary		Install a provisioner from a catalog
//	@Description	Minimum role: operator. Queues provisioner_catalog_install: the executor fetches the catalog FRESH (a stale pin would 404 anyway; published checksums never change), downloads the named version's immutable VERSIONED asset, verifies its sha256 DURING the stream (mismatch = loud failure, nothing imported), then runs the ordinary import path — DSL lint gate, non-clobber, role-specs + schema.json derivation all included. While the archive downloads, the TASK carries real byte progress (the converged wire, sync 2026-07-17): progress_info is exactly {status: "downloading", received_bytes, total_bytes|null} and progress_percent maps the bytes into 0→90 (this op had no intermediate percents; the sha256 verify + import ride after the window and completion lands 100) — throttled to one update per 1s or 1% of total (whichever first), final update always emitted; an unknown Content-Length parks the percent at 0 while received_bytes streams. Serialized with imports (one registry write at a time).
//	@Tags			Provisioning
//	@Accept			json
//	@Produce		json
//	@Param			request	body	provisioner.CatalogInstallMetadata	true	"Catalog install request: name + version (source_name optional; empty = the default catalog)"
//	@Success		202	"Catalog install task queued"
//	@Failure		400	"Missing/unusable name or version"
//	@Failure		404	"No such (or no default) enabled catalog source"
//	@Router			/provisioning/catalog/install [post]
func (s *Server) handleCatalogInstall(w http.ResponseWriter, r *http.Request) {
	var body provisioner.CatalogInstallMetadata
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if !provisioner.ValidName(body.Name) || !provisioner.ValidName(body.Version) {
		taskError(w, http.StatusBadRequest, "name and version are required (registry-legal names)")
		return
	}
	source, err := provisioner.FindCatalogSource(s.catalogSourceList(), body.SourceName)
	if err != nil {
		taskError(w, http.StatusNotFound, err.Error())
		return
	}
	// Already-present pre-check (zoneweaver's converged wire): versions are
	// immutable — an install of an existing version answers 409 up front
	// instead of queueing a task doomed to the import's non-clobber refusal.
	if _, verr := s.provisioners.GetVersion(body.Name, body.Version); verr == nil {
		taskError(w, http.StatusConflict,
			body.Name+"/"+body.Version+" is already in the registry — versions are immutable")
		return
	}

	raw, err := json.Marshal(&body)
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to queue catalog install")
		return
	}
	metadata := string(raw)
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: "system",
		Operation:   provisioner.OpCatalogInstall,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   auth.FromContext(r.Context()).Name,
		Metadata:    &metadata,
	})
	if err != nil {
		slog.Error("queue catalog install", "name", body.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue catalog install")
		return
	}
	// The converged 202 body (zoneweaver's shipped shape): name/version/source
	// ride alongside the task identity.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	if werr := json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"task_id": task.ID,
		"name":    body.Name,
		"version": body.Version,
		"source":  source.Name,
		"status":  tasks.StatusPending,
		"message": "Catalog install task queued for " + body.Name + "/" + body.Version,
	}); werr != nil {
		slog.Error("write catalog install response", "error", werr)
	}
}
