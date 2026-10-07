package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/config"
	"github.com/Makr91/hyperweaver-agent/internal/problem"
	"github.com/Makr91/hyperweaver-agent/internal/provisioner"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// catalogSourceList converts the configured catalogs, as the engine holds
// them now, into the provisioner package's source shape.
func (s *Server) catalogSourceList() []provisioner.CatalogSource {
	configured := s.cfg.LiveCatalogSources()
	ids := make([]string, 0, len(configured))
	for id := range configured {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	sources := make([]provisioner.CatalogSource, 0, len(ids))
	for _, id := range ids {
		source := configured[id]
		sources = append(sources, provisioner.CatalogSource{
			ID:      id,
			Name:    source.DisplayName,
			URL:     source.URL,
			Enabled: source.Enabled,
			Default: source.Default,
			Auth:    source.Auth,
			CAFile:  source.CAFile,
		})
	}
	return sources
}

// catalogFailure answers a catalog read that failed: 401 authentication when the source needs a signed-in account, 502 otherwise.
func catalogFailure(w http.ResponseWriter, source *provisioner.CatalogSource, err error) {
	if errors.Is(err, provisioner.ErrCatalogAuth) {
		problem.Detail(w, http.StatusUnauthorized, err.Error())
		return
	}
	slog.Error("fetch provisioner catalog", "source", source.Name, "error", err)
	taskError(w, http.StatusBadGateway, err.Error())
}

// catalogSourceRow is one entry of GET /api/provisioning/catalog/sources.
type catalogSourceRow struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Default bool   `json:"default"`
}

// listCatalogSourcesResponse is GET /api/provisioning/catalog/sources's answer.
type listCatalogSourcesResponse struct {
	Enabled bool               `json:"enabled"`
	Sources []catalogSourceRow `json:"sources"`
}

// handleListCatalogSources lists the enabled catalog definitions (the
// templates/sources shape — never the CA file path).
//
//	@Summary		List configured provisioner catalogs
//	@Description	Minimum role: viewer. The enabled catalog_sources definitions (id, name, url, default) — the HACS model's registries; fork the catalog repo and add your own as another source. The id is what source_name and ?source= name. CA bundles are never returned.
//	@Tags			Provisioning
//	@Produce		json
//	@Success		200	{object}	listCatalogSourcesResponse	"Enabled catalogs"
//	@Router			/api/provisioning/catalog/sources [get]
func (s *Server) handleListCatalogSources(w http.ResponseWriter, _ *http.Request) {
	sources := []catalogSourceRow{}
	for _, source := range s.catalogSourceList() {
		if !source.Enabled {
			continue
		}
		sources = append(sources, catalogSourceRow{
			ID:      source.ID,
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
// configured catalog; empty = the default), format_version-gated, relayed
// verbatim.
//
//	@Summary		Browse a provisioner catalog
//	@Description	Minimum role: viewer. Fetches the source's catalog.json LIVE (?source= names a configured catalog; empty = the default), validates format_version 1, and relays the document verbatim with every member the catalog publishes: {name, format_version, updated, provisioners: [{name, repo, description, versions: [{version, released_at, artifacts: [{url, checksum_type, checksum}]}]}]} — versions semver-DESC, artifact URLs OPAQUE (release tags carry slashes; never parse or construct them). Versions may disappear between fetches when an author deletes a release. An oidc source is read under the bound account's access token; with none held, or the catalog refusing it, the answer is 401 with the authentication problem type.
//	@Tags			Provisioning
//	@Produce		json
//	@Param			source	query	string	false	"A configured catalog source's id; empty = the default"
//	@Success		200	{object}	provisioner.CatalogDocument	"The catalog document — catalog.json IS the response (no envelope; the resolved source rides /api/provisioning/catalog/sources)"
//	@Failure		401	{object}	problem.Body	"The source needs a signed-in account"
//	@Failure		404	{object}	problem.Body	"No such (or no default) enabled catalog source"
//	@Failure		502	{object}	problem.Body	"Catalog unreachable, unparseable, or wrong format_version"
//	@Router			/api/provisioning/catalog [get]
func (s *Server) handleGetCatalog(w http.ResponseWriter, r *http.Request) {
	source, err := provisioner.FindCatalogSource(s.catalogSourceList(), r.URL.Query().Get("source"))
	if err != nil {
		taskError(w, http.StatusNotFound, err.Error())
		return
	}
	document, _, err := provisioner.FetchCatalogVerbatim(r.Context(), source)
	if err != nil {
		catalogFailure(w, source, err)
		return
	}
	writeJSON(w, document)
}

// @Summary		A provisioner catalog's health document
// @Description	Minimum role: viewer. Fetches the source's health.json LIVE, the URL beside the catalog's (catalog.json becoming health.json, /catalog becoming /health), and relays it verbatim: {name, format_version, updated, provisioners: {<family>: {repo, tier, presentation, rules, failed_rules, health}}}. 404 while the source publishes none. An oidc source is read under the bound account's access token; with none held, or the catalog refusing it, the answer is 401 with the authentication problem type.
// @Tags			Provisioning
// @Produce		json
// @Param			source	query	string	false	"A configured catalog source's id; empty = the default"
// @Success		200	{object}	map[string]interface{}	"The health document verbatim"
// @Failure		401	{object}	problem.Body	"The source needs a signed-in account"
// @Failure		404	{object}	problem.Body	"No such (or no default) enabled catalog source, or the source publishes no health document"
// @Failure		502	{object}	problem.Body	"Catalog unreachable or the document is not JSON"
// @Router			/api/provisioning/catalog/health [get]
func (s *Server) handleCatalogHealth(w http.ResponseWriter, r *http.Request) {
	source, err := provisioner.FindCatalogSource(s.catalogSourceList(), r.URL.Query().Get("source"))
	if err != nil {
		taskError(w, http.StatusNotFound, err.Error())
		return
	}
	document, err := provisioner.FetchCatalogHealth(r.Context(), source)
	if errors.Is(err, provisioner.ErrCatalogHealthMissing) {
		taskError(w, http.StatusNotFound, err.Error())
		return
	}
	if err != nil {
		catalogFailure(w, source, err)
		return
	}
	writeJSON(w, document)
}

type createCatalogSourceRequest struct {
	DisplayName string `json:"display_name"`
	// The catalog document's URL, fetched as given
	URL string `json:"url"`
	// none or oidc; absent means none
	Auth string `json:"auth"`
}

type createCatalogSourceResponse struct {
	Success bool             `json:"success"`
	Source  catalogSourceRow `json:"source"`
}

func (s *Server) catalogSourceID(displayName string) string {
	id := strings.Trim(storagePathSlug.ReplaceAllString(strings.ToLower(displayName), "_"), "_")
	if id == "" || !config.ValidStoragePathID(id) {
		id = "catalog"
	}
	configured := s.cfg.LiveCatalogSources()
	candidate := id
	for n := 2; ; n++ {
		if _, taken := configured[candidate]; !taken {
			return candidate
		}
		candidate = id + "_" + strconv.Itoa(n)
	}
}

// @Summary		Add a provisioner catalog source
// @Description	Minimum role: operator. Adds a catalog to catalog_sources.sources in the storage configuration file, keyed by an id derived from display_name, enabled and not the default; auth is none or oidc, oidc sending the bound account's access token as Bearer on the catalog read and its downloads. It takes effect at once, no restart: the sources list, the catalog read and the next catalog install read it.
// @Tags			Provisioning
// @Accept			json
// @Produce		json
// @Param			body	body		createCatalogSourceRequest	true	"The new source"
// @Success		201		{object}	createCatalogSourceResponse	"Source added: {success, source: {id, name, url, default}}"
// @Failure		400		{object}	problem.Body	"Unreadable body"
// @Failure		409		{object}	problem.Body	"A source of that url is already present (unique at /url); source carries it"
// @Failure		422		{object}	problem.Body	"display_name or url missing (required); url not an http(s) URL (format uri at /url); auth outside none, oidc (enum at /auth)"
// @Router			/api/provisioning/catalog/sources [post]
func (s *Server) handleCreateCatalogSource(w http.ResponseWriter, r *http.Request) {
	var body createCatalogSourceRequest
	if err := decodeBody(r, &body); err != nil {
		problem.BadRequest(w)
		return
	}
	failures := []problem.Error{}
	if body.DisplayName == "" {
		failures = append(failures, problem.Required("/display_name"))
	}
	switch parsed, err := url.Parse(body.URL); {
	case body.URL == "":
		failures = append(failures, problem.Required("/url"))
	case err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http"):
		failures = append(failures, problem.Rule("/url", "format", map[string]any{"format": "uri"}))
	}
	if body.Auth == "" {
		body.Auth = provisioner.CatalogAuthNone
	}
	if body.Auth != provisioner.CatalogAuthNone && body.Auth != provisioner.CatalogAuthOIDC {
		failures = append(failures, problem.Enum("/auth", provisioner.CatalogAuthNone, provisioner.CatalogAuthOIDC))
	}
	if len(failures) > 0 {
		problem.Invalid(w, failures...)
		return
	}
	for _, existing := range s.catalogSourceList() {
		if existing.URL == body.URL {
			problem.Send(w, http.StatusConflict, "conflict", "", "A catalog source with this url is already present",
				[]problem.Error{problem.Unique("/url", "catalog_sources")},
				map[string]any{"source": catalogSourceRow{
					ID: existing.ID, Name: existing.Name, URL: existing.URL, Default: existing.Default,
				}})
			return
		}
	}

	id := s.catalogSourceID(body.DisplayName)
	previous := s.cfg.CatalogSources.Sources
	sources := make(map[string]config.CatalogSourceConfig, len(previous)+1)
	for key, entry := range s.cfg.LiveCatalogSources() {
		sources[key] = entry
	}
	sources[id] = config.CatalogSourceConfig{
		DisplayName: body.DisplayName,
		URL:         body.URL,
		Enabled:     true,
		Auth:        body.Auth,
	}
	s.cfg.CatalogSources.Sources = sources
	if err := s.cfg.MergeAndSave(map[string]any{"catalog_sources": s.cfg.CatalogSources}); err != nil {
		s.cfg.CatalogSources.Sources = previous
		slog.Error("save catalog source", "id", id, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to save the catalog source")
		return
	}
	slog.Info("catalog source added", "id", id, "url", body.URL, "auth", body.Auth,
		"by", auth.FromContext(r.Context()).Name)
	writeJSONStatus(w, http.StatusCreated, createCatalogSourceResponse{
		Success: true,
		Source:  catalogSourceRow{ID: id, Name: body.DisplayName, URL: body.URL, Default: false},
	})
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
//	@Router			/api/provisioning/catalog/install [post]
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
		"source":  source.ID,
		"status":  tasks.StatusPending,
		"message": "Catalog install task queued for " + body.Name + "/" + body.Version,
	}); werr != nil {
		slog.Error("write catalog install response", "error", werr)
	}
}
