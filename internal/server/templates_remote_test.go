package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/Makr91/hyperweaver-agent/internal/machines"
)

func registryStub(t *testing.T) (registry *httptest.Server, authorization *string) {
	t.Helper()
	seen := new(string)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(server.Close)
	return server, seen
}

func TestRegistryJSONCredentialLadder(t *testing.T) {
	t.Cleanup(func() { machines.SetOIDCTokenSource(nil) })
	registry, seen := registryStub(t)
	source := &machines.TemplateSource{ID: "boxvault", URL: registry.URL, Enabled: true, AuthToken: "server-wide-key"}
	machines.SetOIDCTokenSource(func() string { return "bound-token" })

	if _, status, err := registryJSON(context.Background(), source, "forwarded-person-token", "/api/discover", false); err != nil || status != http.StatusOK {
		t.Fatalf("header read: status %d, err %v", status, err)
	}
	if *seen != "Bearer forwarded-person-token" {
		t.Fatalf("x-registry-token must win: got %q", *seen)
	}

	if _, _, err := registryJSON(context.Background(), source, "", "/api/discover", false); err != nil {
		t.Fatal(err)
	}
	if *seen != "Bearer bound-token" {
		t.Fatalf("bound token must beat the source's key: got %q", *seen)
	}

	machines.SetOIDCTokenSource(func() string { return "" })
	if _, _, err := registryJSON(context.Background(), source, "", "/api/discover", false); err != nil {
		t.Fatal(err)
	}
	if *seen != "Bearer server-wide-key" {
		t.Fatalf("the source's key is the last resort: got %q", *seen)
	}
}

func provider(name, arch string) map[string]any {
	return map[string]any{"name": name, "architectures": []any{map[string]any{"name": arch}}}
}

func TestCompatibleVersionsPrunesProvidersAndArchitectures(t *testing.T) {
	versions := []any{
		map[string]any{"version": "1.0.0", "providers": []any{
			provider("virtualbox", runtime.GOARCH),
			provider("zone", runtime.GOARCH),
			provider("virtualbox", "foreign"),
		}},
		map[string]any{"version": "0.9.0", "providers": []any{provider("bhyve", runtime.GOARCH)}},
	}
	kept := compatibleVersions(versions, map[string]bool{machines.TemplateProvider: true})
	if len(kept) != 1 {
		t.Fatalf("kept %d versions, want the one with a usable provider", len(kept))
	}
	providers, _ := kept[0].(map[string]any)["providers"].([]any)
	if len(providers) != 1 {
		t.Fatalf("kept %d providers, want virtualbox alone", len(providers))
	}
	architectures, _ := providers[0].(map[string]any)["architectures"].([]any)
	if len(architectures) != 1 || architectures[0].(map[string]any)["name"] != runtime.GOARCH {
		t.Fatalf("kept architectures %v, want the host's alone", architectures)
	}
}

func TestCompatibleMetadataVersionsPrunesProvidersAndArchitectures(t *testing.T) {
	versions := []any{
		map[string]any{"version": "1.0.0", "providers": []any{
			map[string]any{"name": "virtualbox", "architecture": runtime.GOARCH},
			map[string]any{"name": "virtualbox", "architecture": "foreign"},
			map[string]any{"name": "zone", "architecture": runtime.GOARCH},
		}},
		map[string]any{"version": "0.9.0", "providers": []any{map[string]any{"name": "zone", "architecture": runtime.GOARCH}}},
	}
	kept := compatibleMetadataVersions(versions, map[string]bool{machines.TemplateProvider: true})
	if len(kept) != 1 {
		t.Fatalf("kept %d versions, want one", len(kept))
	}
	providers, _ := kept[0].(map[string]any)["providers"].([]any)
	if len(providers) != 1 || providers[0].(map[string]any)["architecture"] != runtime.GOARCH {
		t.Fatalf("kept providers %v, want virtualbox on the host's architecture alone", providers)
	}
}
