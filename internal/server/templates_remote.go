package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/version"
)

// The remote-template discovery surface — zoneweaver's
// TemplateSourceController mirrored (the base ALREADY served this; the Go
// agent was the one missing it): GET /templates/sources lists the configured
// registries, GET /templates/remote/{sourceName} proxies the registry's
// /api/discover catalog, and GET /templates/remote/{sourceName}/{org}/{boxName}
// proxies the Vagrant-compatible /{org}/{box} metadata document. An
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

// proxyRegistry forwards one GET to the registry and relays the JSON answer
// (the base's createRegistryClient semantics: Vagrant user agent — BoxVault's
// service accounts expect it — Bearer token, x-access-token only for
// JWT-shaped tokens; upstream failure answers 502 with detail, upstream 404
// stays a 404).
func (s *Server) proxyRegistry(w http.ResponseWriter, r *http.Request,
	source *machines.TemplateSource, path, notFound string,
) {
	// ONE registry transport: the shared client (ca_file honored) and token
	// ladder (signin JWT etc.); an x-registry-token header still overrides.
	client := machines.RegistryHTTPClient(source)
	token := r.Header.Get("x-registry-token")
	if token == "" {
		token = machines.RegistryToken(r.Context(), client, source)
	}
	request, err := http.NewRequestWithContext(r.Context(), http.MethodGet,
		source.URL+path, http.NoBody)
	if err != nil {
		taskError(w, http.StatusBadGateway, "Failed to reach template source")
		return
	}
	request.Header.Set("User-Agent", "Vagrant/2.2.19 Hyperweaver/"+version.Version)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
		if strings.Count(token, ".") == 2 {
			request.Header.Set("x-access-token", token)
		}
	}

	response, err := client.Do(request)
	if err != nil {
		slog.Error("registry request failed", "source", source.Name, "path", path, "error", err)
		taskError(w, http.StatusBadGateway, "Failed to retrieve data from remote source: "+err.Error())
		return
	}
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode == http.StatusNotFound && notFound != "" {
		taskError(w, http.StatusNotFound, notFound)
		return
	}
	if response.StatusCode != http.StatusOK {
		taskError(w, http.StatusBadGateway,
			"Remote source answered "+response.Status)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, cerr := io.Copy(w, io.LimitReader(response.Body, 64<<20)); cerr != nil {
		slog.Warn("relay registry response", "source", source.Name, "error", cerr)
	}
}

// handleRemoteTemplates mirrors GET /templates/remote/{sourceName}: the
// registry's whole discovery catalog (BoxVault's /api/discover — every
// public box with its versions/providers/architectures), the wizard's box
// dropdown feed.
func (s *Server) handleRemoteTemplates(w http.ResponseWriter, r *http.Request) {
	source := s.findRegistrySource(r.PathValue("sourceName"))
	if source == nil {
		taskError(w, http.StatusNotFound, "Template source not found or disabled")
		return
	}
	s.proxyRegistry(w, r, source, "/api/discover", "")
}

// handleRemoteTemplateDetails mirrors GET
// /templates/remote/{sourceName}/{org}/{boxName}: the Vagrant-compatible
// metadata document for one box (versions + providers + download URLs).
func (s *Server) handleRemoteTemplateDetails(w http.ResponseWriter, r *http.Request) {
	source := s.findRegistrySource(r.PathValue("sourceName"))
	if source == nil {
		taskError(w, http.StatusNotFound, "Template source not found or disabled")
		return
	}
	org := url.PathEscape(r.PathValue("org"))
	boxName := url.PathEscape(r.PathValue("boxName"))
	s.proxyRegistry(w, r, source, "/"+org+"/"+boxName,
		"Template not found on remote source")
}
