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
// THIS hypervisor's provider (virtualbox) AND the host's architecture
// (Mark's directive 2026-07-09: a zones-only or foreign-arch box in the
// picker is a guaranteed 404 at download time). An
// x-registry-token request header overrides the source's configured token
// (the base's user-token rule); the configured auth_token never leaves the
// agent.

// handleListTemplateSources mirrors GET /templates/sources: the enabled
// registries, credentials withheld.
func (s *Server) handleListTemplateSources(w http.ResponseWriter, _ *http.Request) {
	sources := []map[string]any{}
	for _, source := range s.cfg.TemplateSources.Sources {
		if !source.Enabled {
			continue
		}
		sources = append(sources, map[string]any{
			"name":    source.Name,
			"url":     source.URL,
			"enabled": source.Enabled,
			"default": source.Default,
		})
	}
	writeJSON(w, map[string]any{"sources": sources})
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

// compatibleVersions keeps only the versions this agent can actually
// download — provider virtualbox AND the host's own architecture
// (runtime.GOARCH matches BoxVault's names: amd64, arm64; a VirtualBox-arm
// future needs zero changes here) — pruning foreign providers and
// architectures from the survivors. Mark's directive 2026-07-09: the
// catalog must never offer a template this hypervisor cannot consume — a
// zones-only box in the picker was a guaranteed 404 at download time.
// Discover's shape: versions[].providers[].architectures[].name.
func compatibleVersions(versions []any) []any {
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
			if name, _ := provider["name"].(string); !strings.EqualFold(name, machines.TemplateProvider) {
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
func compatibleMetadataVersions(versions []any) []any {
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
			if strings.EqualFold(name, machines.TemplateProvider) &&
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
	list, _ := decoded.([]any)
	catalog := make([]any, 0, len(list))
	for _, raw := range list {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		versions, _ := entry["versions"].([]any)
		usable := compatibleVersions(versions)
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
	usable := compatibleMetadataVersions(versions)
	if len(usable) == 0 {
		taskError(w, http.StatusNotFound, "Template not found on remote source")
		return
	}
	document["versions"] = usable
	writeJSON(w, document)
}
