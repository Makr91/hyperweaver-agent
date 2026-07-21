package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"runtime"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/version"
)

// The remote-template discovery surface — zoneweaver's
// TemplateSourceController mirrored (the base ALREADY served this; the Go
// agent was the one missing it): GET /templates/sources lists the configured
// registries, GET /templates/remote/{sourceName} serves the registry's
// /api/discover catalog, and GET /templates/remote/{sourceName}/{org}/{boxName}
// the Vagrant-compatible /{org}/{box} metadata document — BOTH filtered to
// THIS host's provider set (virtualbox; utm when the capability probe
// passes) AND the host's architecture
// (Mark's directive 2026-07-09: a zones-only or foreign-arch box in the
// picker is a guaranteed 404 at download time). An
// x-registry-token request header overrides the source's configured token
// (the base's user-token rule); the configured auth_token never leaves the
// agent.

// templateSourceSummary is one enabled registry in the sources list —
// credentials (auth_token) withheld.
type templateSourceSummary struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
	Default bool   `json:"default"`
}

// templateSourcesResponse is GET /templates/sources' answer.
type templateSourcesResponse struct {
	Sources []templateSourceSummary `json:"sources"`
}

// handleListTemplateSources mirrors GET /templates/sources: the enabled
// registries, credentials withheld.
//
//	@Summary		List configured template sources
//	@Description	Minimum role: viewer. The enabled Vagrant/BoxVault-compatible registries (name, url, default) — credentials are never returned. The base's GET /templates/sources.
//	@Tags			Machine Management
//	@Produce		json
//	@Success		200	{object}	templateSourcesResponse	"Enabled sources"
//	@Router			/templates/sources [get]
func (s *Server) handleListTemplateSources(w http.ResponseWriter, _ *http.Request) {
	sources := []templateSourceSummary{}
	for _, source := range s.cfg.TemplateSources.Sources {
		if !source.Enabled {
			continue
		}
		sources = append(sources, templateSourceSummary{
			Name:    source.Name,
			URL:     source.URL,
			Enabled: source.Enabled,
			Default: source.Default,
		})
	}
	writeJSON(w, templateSourcesResponse{Sources: sources})
}

// findRegistrySource resolves an enabled source by name (the base's
// findSourceConfig).
func (s *Server) findRegistrySource(name string) *machines.TemplateSource {
	for _, source := range s.templateSources() {
		if source.Enabled && source.Name == name {
			return &source
		}
	}
	return nil
}

// registryJSON fetches one registry path (Bearer = headerToken when the
// request carried x-registry-token, else the source's API key) and decodes
// the JSON answer. vagrantUA selects Vagrant's user agent — ONLY the
// /{org}/{box} metadata path wants it, where BoxVault's vagrantHandler
// middleware rewrites Vagrant-UA URLs onto its metadata API. A Vagrant UA
// anywhere else is a 404 factory: the middleware parses any two-segment
// Vagrant-UA path as {org}/{box} (runtime-found on Mark's BoxVault,
// 2026-07-09 — /api/discover became box "discover" in org "api"). A non-200
// upstream answer returns (nil, status, nil).
func registryJSON(ctx context.Context, source *machines.TemplateSource,
	headerToken, path string, vagrantUA bool,
) (decoded any, status int, err error) {
	// ONE registry transport: the shared client (ca_file honored) and the
	// source's API key; an x-registry-token header still overrides.
	client := machines.RegistryHTTPClient(source)
	token := headerToken
	if token == "" {
		token = machines.RegistryToken(source)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(source.URL, "/")+path, http.NoBody)
	if err != nil {
		return nil, 0, err
	}
	userAgent := "Hyperweaver/" + version.Version
	if vagrantUA {
		userAgent = "Vagrant/2.2.19 Hyperweaver/" + version.Version
	}
	request.Header.Set("User-Agent", userAgent)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK {
		return nil, response.StatusCode, nil
	}
	if derr := json.NewDecoder(io.LimitReader(response.Body, 64<<20)).Decode(&decoded); derr != nil {
		return nil, response.StatusCode, derr
	}
	return decoded, http.StatusOK, nil
}

// agentProviders is the registry-provider set THIS host can consume:
// virtualbox always, utm when the capability probe passes (the same probe
// /status advertises on).
func agentProviders(ctx context.Context) map[string]bool {
	providers := map[string]bool{machines.TemplateProvider: true}
	if utmHypervisorAvailable(ctx) {
		providers[machines.TemplateProviderUTM] = true
	}
	return providers
}

// compatibleVersions keeps only the versions this agent can actually
// download — a provider in the host's set AND the host's own architecture
// (runtime.GOARCH matches BoxVault's names: amd64, arm64; a VirtualBox-arm
// future needs zero changes here) — pruning foreign providers and
// architectures from the survivors. Mark's directive 2026-07-09: the
// catalog must never offer a template this hypervisor cannot consume — a
// zones-only box in the picker was a guaranteed 404 at download time.
// Discover's shape: versions[].providers[].architectures[].name.
func compatibleVersions(versions []any, providerSet map[string]bool) []any {
	kept := make([]any, 0, len(versions))
	for _, raw := range versions {
		ver, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		providers, _ := ver["providers"].([]any)
		matching := make([]any, 0, len(providers))
		for _, praw := range providers {
			provider, pok := praw.(map[string]any)
			if !pok {
				continue
			}
			if name, _ := provider["name"].(string); !providerSet[strings.ToLower(name)] {
				continue
			}
			architectures, _ := provider["architectures"].([]any)
			usable := make([]any, 0, len(architectures))
			for _, araw := range architectures {
				arch, aok := araw.(map[string]any)
				if !aok {
					continue
				}
				if archName, _ := arch["name"].(string); strings.EqualFold(archName, runtime.GOARCH) {
					usable = append(usable, arch)
				}
			}
			if len(usable) > 0 {
				provider["architectures"] = usable
				matching = append(matching, provider)
			}
		}
		if len(matching) > 0 {
			ver["providers"] = matching
			kept = append(kept, ver)
		}
	}
	return kept
}

// compatibleMetadataVersions is compatibleVersions for the Vagrant metadata
// document's FLATTENED shape (findone.js formatVagrantResponse): one
// providers[] entry per provider×architecture pair — {name, architecture}.
func compatibleMetadataVersions(versions []any, providerSet map[string]bool) []any {
	kept := make([]any, 0, len(versions))
	for _, raw := range versions {
		ver, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		providers, _ := ver["providers"].([]any)
		matching := make([]any, 0, len(providers))
		for _, praw := range providers {
			provider, pok := praw.(map[string]any)
			if !pok {
				continue
			}
			name, _ := provider["name"].(string)
			architecture, _ := provider["architecture"].(string)
			if providerSet[strings.ToLower(name)] &&
				strings.EqualFold(architecture, runtime.GOARCH) {
				matching = append(matching, provider)
			}
		}
		if len(matching) > 0 {
			ver["providers"] = matching
			kept = append(kept, ver)
		}
	}
	return kept
}

// handleRemoteTemplates mirrors GET /templates/remote/{sourceName}: the
// registry's discovery catalog — the wizard's box dropdown feed. ONE
// discover call (BoxVault answers public boxes plus the API key's own
// organization's — BoxVault-side change 2026-07-09; the agent-side
// multi-endpoint aggregation died with it), filtered to what THIS agent can
// consume (compatibleVersions); boxes left with no versions are dropped.
// Plain UA — see registryJSON.
//
//	@Summary		List a source's remote box catalog
//	@Description	Minimum role: viewer. The registry's discovery catalog — the machine wizard's box-picker feed. ONE /api/discover call: public boxes for everyone, and when the source carries an API key (a BoxVault service-account token, sent as Bearer) the registry additionally answers the key's own organization's boxes. Sources WITHOUT their own auth_token fall back to the logged-in user's OIDC access token when one is held (the Direct-mode device login) — org-private BoxVault boxes then appear per the user's own claims. FILTERED to what this agent can consume: only versions carrying a provider in the host's set (virtualbox always; utm too on a UTM-capable macOS agent) in the host's architecture survive (foreign providers/architectures are pruned; boxes left with no versions are dropped) — a zone/docker/aws-only or foreign-arch box never reaches the picker. An x-registry-token request header overrides the source's configured key (never returned). The base's GET /templates/remote/{sourceName}.
//	@Tags			Machine Management
//	@Produce		json
//	@Param			sourceName	path	string	true	"The configured template source"
//	@Success		200	{object}	map[string]interface{}	"The registry's catalog document, relayed verbatim"
//	@Failure		404	"Source not found or disabled"
//	@Failure		502	"Remote source unreachable or answered an error"
//	@Router			/templates/remote/{sourceName} [get]
func (s *Server) handleRemoteTemplates(w http.ResponseWriter, r *http.Request) {
	source := s.findRegistrySource(r.PathValue("sourceName"))
	if source == nil {
		taskError(w, http.StatusNotFound, "Template source not found or disabled")
		return
	}
	decoded, status, err := registryJSON(r.Context(), source,
		r.Header.Get("x-registry-token"), "/api/discover", false)
	if err != nil {
		slog.Error("registry discover failed", "source", source.Name, "error", err)
		taskError(w, http.StatusBadGateway,
			"Failed to retrieve data from remote source: "+err.Error())
		return
	}
	if status != http.StatusOK {
		taskError(w, http.StatusBadGateway,
			fmt.Sprintf("Remote source answered HTTP %d", status))
		return
	}
	providerSet := agentProviders(r.Context())
	list, _ := decoded.([]any)
	catalog := make([]any, 0, len(list))
	for _, raw := range list {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		versions, _ := entry["versions"].([]any)
		usable := compatibleVersions(versions, providerSet)
		if len(usable) == 0 {
			continue
		}
		entry["versions"] = usable
		catalog = append(catalog, entry)
	}
	writeJSON(w, catalog)
}

// handleRemoteTemplateDetails mirrors GET
// /templates/remote/{sourceName}/{org}/{boxName}: the Vagrant-compatible
// metadata document for one box (versions + providers + download URLs),
// filtered to what THIS agent can consume — a box that exists upstream but
// carries nothing downloadable here answers 404, same as absent.
//
//	@Summary		Get one remote box's metadata
//	@Description	Minimum role: viewer. The registry's Vagrant-compatible /{org}/{box} metadata document: versions with providers and download URLs, FILTERED to what this agent can consume (the host's provider set — virtualbox always, utm on a UTM-capable macOS agent — in the host architecture). A box that exists upstream but carries nothing downloadable here answers 404, same as absent. The base's GET /templates/remote/{sourceName}/{org}/{boxName}.
//	@Tags			Machine Management
//	@Produce		json
//	@Param			sourceName	path	string	true	"The configured template source"
//	@Param			org			path	string	true	"The box's organization"
//	@Param			boxName		path	string	true	"The box name"
//	@Success		200	{object}	map[string]interface{}	"The box's metadata document, relayed verbatim"
//	@Failure		404	"Source disabled, or box not on the remote"
//	@Failure		502	"Remote source unreachable or answered an error"
//	@Router			/templates/remote/{sourceName}/{org}/{boxName} [get]
func (s *Server) handleRemoteTemplateDetails(w http.ResponseWriter, r *http.Request) {
	source := s.findRegistrySource(r.PathValue("sourceName"))
	if source == nil {
		taskError(w, http.StatusNotFound, "Template source not found or disabled")
		return
	}
	org := url.PathEscape(r.PathValue("org"))
	boxName := url.PathEscape(r.PathValue("boxName"))
	decoded, status, err := registryJSON(r.Context(), source,
		r.Header.Get("x-registry-token"), "/"+org+"/"+boxName, true)
	if err != nil {
		slog.Error("registry metadata failed", "source", source.Name,
			"box", org+"/"+boxName, "error", err)
		taskError(w, http.StatusBadGateway,
			"Failed to retrieve data from remote source: "+err.Error())
		return
	}
	if status == http.StatusNotFound {
		taskError(w, http.StatusNotFound, "Template not found on remote source")
		return
	}
	if status != http.StatusOK {
		taskError(w, http.StatusBadGateway,
			fmt.Sprintf("Remote source answered HTTP %d", status))
		return
	}
	document, ok := decoded.(map[string]any)
	if !ok {
		taskError(w, http.StatusBadGateway, "Remote source answered an unexpected document")
		return
	}
	versions, _ := document["versions"].([]any)
	usable := compatibleMetadataVersions(versions, agentProviders(r.Context()))
	if len(usable) == 0 {
		taskError(w, http.StatusNotFound, "Template not found on remote source")
		return
	}
	document["versions"] = usable
	writeJSON(w, document)
}
