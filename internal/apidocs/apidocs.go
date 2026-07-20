// Package apidocs serves the interactive Agent API documentation: the
// hand-maintained OpenAPI fragment (openapi.json — info/tags/components/
// security and every not-yet-migrated path) merged with the swag-generated
// document (gen/ — swag v2 annotations above handlers, regenerated at build
// time via go:generate), rendered by a vendored Swagger UI at /api-docs — the
// same page (URL shape, dark theme, public spec route) the Node
// zoneweaver-agent serves. The spec's info.version is the frozen Agent API
// contract line (architecture D1); info.x-app-version is stamped with the
// running build at serve time. The merged document stays OpenAPI 3.0: 3.1-only
// constructs in the generated half are rejected loudly and the fragment serves
// alone rather than serving a dirty document.
package apidocs

//go:generate swag init --v3.1 --dir ../../ --generalInfo main.go --output gen --outputTypes json --parseDependency --parseInternal

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/version"
)

//go:embed openapi.json
var specJSON []byte

//go:embed gen
var genFS embed.FS

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
	mergeGenerated(spec)
	stampPublicPaths(spec)

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

// mergeGenerated folds every embedded generated document into the fragment.
// A generated file that fails to parse or fold degrades loudly to the
// fragment alone — a doc-generation mistake never bricks the agent and never
// serves a dirty document.
func mergeGenerated(spec map[string]any) {
	entries, err := genFS.ReadDir("gen")
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, rerr := genFS.ReadFile("gen/" + entry.Name())
		if rerr != nil {
			slog.Error("read generated OpenAPI", "file", entry.Name(), "error", rerr)
			continue
		}
		var gen map[string]any
		if uerr := json.Unmarshal(raw, &gen); uerr != nil {
			slog.Error("parse generated OpenAPI — serving the fragment alone",
				"file", entry.Name(), "error", uerr)
			continue
		}
		if len(gen) == 0 {
			continue
		}
		if ferr := foldGenerated(spec, gen); ferr != nil {
			slog.Error("generated OpenAPI rejected — serving the fragment alone",
				"file", entry.Name(), "error", ferr)
		}
	}
}

// foldGenerated adopts the generated document's paths and component schemas
// into the fragment. THE FRAGMENT WINS every collision (a shadowed generated
// path means its fragment copy was not deleted yet — the migration switch is
// exactly that deletion), and the fragment alone owns info/tags/security/
// servers. Validation runs before any mutation.
func foldGenerated(spec, gen map[string]any) error {
	if _, ok := gen["swagger"]; ok {
		return errors.New("generated document is Swagger 2.0 — regenerate with swag v2 and --v3.1")
	}
	genPaths, _ := gen["paths"].(map[string]any)
	genSchemas := schemaMap(gen)
	if err := rejectOAS31(genPaths, false); err != nil {
		return err
	}
	if err := rejectOAS31(genSchemas, false); err != nil {
		return err
	}

	specPaths, ok := spec["paths"].(map[string]any)
	if !ok {
		return errors.New("fragment has no paths object")
	}
	for path, item := range genPaths {
		if _, exists := specPaths[path]; exists {
			slog.Warn("generated path shadowed by the fragment — delete it from openapi.json to finish its migration",
				"path", path)
			continue
		}
		specPaths[path] = item
	}
	if len(genSchemas) > 0 {
		specSchemas := schemaMap(spec)
		if specSchemas == nil {
			return errors.New("fragment has no components.schemas object")
		}
		for name, schema := range genSchemas {
			if _, exists := specSchemas[name]; exists {
				slog.Warn("generated schema shadowed by the fragment", "schema", name)
				continue
			}
			specSchemas[name] = schema
		}
	}
	return nil
}

func schemaMap(doc map[string]any) map[string]any {
	components, _ := doc["components"].(map[string]any)
	schemas, _ := components["schemas"].(map[string]any)
	return schemas
}

// stampPublicPaths applies the fragment's x-public-paths list: every listed
// path's operations get an EMPTY security array (public — overriding the
// document's global security). swag annotations cannot express "no security"
// (omitting @Security inherits the global schemes), so the fragment names the
// public surface and the merge stamps it — idempotent over fragment paths
// that already carry it. The extension key never reaches the served document.
func stampPublicPaths(spec map[string]any) {
	list, _ := spec["x-public-paths"].([]any)
	delete(spec, "x-public-paths")
	paths, _ := spec["paths"].(map[string]any)
	if len(list) == 0 || paths == nil {
		return
	}
	for _, entry := range list {
		path, _ := entry.(string)
		item, _ := paths[path].(map[string]any)
		for _, operation := range item {
			if op, ok := operation.(map[string]any); ok {
				op["security"] = []any{}
			}
		}
	}
}

// oas31Keys are JSON-Schema keywords legal in OpenAPI 3.1 but not in the 3.0
// dialect this document is published as.
var oas31Keys = []string{
	"const", "prefixItems", "$schema", "unevaluatedProperties",
	"contentMediaType", "contentEncoding", "patternProperties",
}

// rejectOAS31 walks a generated subtree and refuses 3.1-only vocabulary —
// the merged document is published as OpenAPI 3.0.0 and must stay
// byte-compatible for every consumer. Keys inside a properties map are data
// (property names), never keywords.
func rejectOAS31(node any, insideProperties bool) error {
	switch value := node.(type) {
	case map[string]any:
		for key, child := range value {
			if !insideProperties {
				if key == "type" {
					if _, isArray := child.([]any); isArray {
						return errors.New("a type array is OpenAPI 3.1 vocabulary — the merged document stays 3.0 (use nullable)")
					}
				}
				for _, banned := range oas31Keys {
					if key == banned {
						return errors.New(banned + " is OpenAPI 3.1 vocabulary — the merged document stays 3.0")
					}
				}
			}
			if err := rejectOAS31(child, key == "properties"); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range value {
			if err := rejectOAS31(child, false); err != nil {
				return err
			}
		}
	}
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
