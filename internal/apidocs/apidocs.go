// Package apidocs serves the interactive Agent API documentation: a
// hand-authored OpenAPI document covering the surface this agent actually
// implements, rendered by a vendored Swagger UI at /api-docs — the same page
// (URL shape, dark theme, public spec route) the Node zoneweaver-agent
// serves. The spec's info.version is the frozen Agent API contract line
// (architecture D1); info.x-app-version is stamped with the running build at
// serve time, and the document grows as endpoints are implemented.
package apidocs

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"

	"github.com/Makr91/hyperweaver-agent/internal/version"
)

//go:embed openapi.json
var specJSON []byte

//go:embed assets
var assets embed.FS

// The real swagger-ui-dist bundle is over a megabyte; anything smaller is
// the committed placeholder, worth a loud startup warning.
const vendoredMinBytes = 10_000

// Mount registers the documentation routes: the public OpenAPI document at
// /api-docs/swagger.json (also fetched server-side by the Hyperweaver Server
// to render this agent's API in aggregated mode) and the Swagger UI page at
// /api-docs/.
func Mount(mux *http.ServeMux) error {
	var spec map[string]any
	if err := json.Unmarshal(specJSON, &spec); err != nil {
		return fmt.Errorf("parse embedded openapi.json: %w", err)
	}

	sub, err := fs.Sub(assets, "assets")
	if err != nil {
		return err
	}
	if info, serr := fs.Stat(sub, "swagger-ui-bundle.js"); serr != nil || info.Size() < vendoredMinBytes {
		slog.Warn("swagger-ui assets are placeholders — /api-docs will not render;" +
			" vendor swagger-ui-dist into internal/apidocs/assets")
	}

	mux.HandleFunc("GET /api-docs/swagger.json", func(w http.ResponseWriter, r *http.Request) {
		writeSpec(w, r, spec)
	})
	mux.Handle("GET /api-docs/", http.StripPrefix("/api-docs/", http.FileServerFS(sub)))
	mux.Handle("GET /api-docs", http.RedirectHandler("/api-docs/", http.StatusFound))
	return nil
}

// writeSpec renders the spec with its two request-time fields: a servers
// block targeting whoever served the page (so "Try it out" hits the right
// host — the Node agent's withDynamicServers), and the running application
// version. The contract version in info.version stays frozen.
func writeSpec(w http.ResponseWriter, r *http.Request, spec map[string]any) {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	doc := make(map[string]any, len(spec)+1)
	for k, v := range spec {
		doc[k] = v
	}
	// Two entries, exactly like the Node agent: the auto-detected current
	// server plus a templated one whose variables render swagger-ui's
	// protocol/host selector.
	doc["servers"] = []map[string]any{
		{"url": scheme + "://" + r.Host, "description": "Current server (auto-detected)"},
		{
			"url":         "{protocol}://{host}",
			"description": "Custom server",
			"variables": map[string]any{
				"protocol": map[string]any{
					"enum":        []string{"http", "https"},
					"default":     scheme,
					"description": "The protocol used to access the server",
				},
				"host": map[string]any{
					"default":     r.Host,
					"description": "The hostname and port of the server",
				},
			},
		},
	}
	if info, ok := spec["info"].(map[string]any); ok {
		stamped := make(map[string]any, len(info)+1)
		for k, v := range info {
			stamped[k] = v
		}
		stamped["x-app-version"] = version.Version
		doc["info"] = stamped
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(doc); err != nil {
		slog.Error("write swagger.json response", "error", err)
	}
}
