package machines

import "testing"

func TestRegistryTokenLadder(t *testing.T) {
	t.Cleanup(func() { SetOIDCTokenSource(nil) })
	source := &TemplateSource{ID: "boxvault", URL: "https://boxvault.example.com", Enabled: true, AuthToken: "server-wide-key"}

	SetOIDCTokenSource(func() string { return "bound-token" })
	if got := registryToken(source); got != "bound-token" {
		t.Fatalf("bound token held: got %q, want the bound token", got)
	}

	SetOIDCTokenSource(func() string { return "" })
	if got := registryToken(source); got != "server-wide-key" {
		t.Fatalf("no bound token: got %q, want the source's key", got)
	}

	SetOIDCTokenSource(nil)
	if got := registryToken(source); got != "server-wide-key" {
		t.Fatalf("no token source: got %q, want the source's key", got)
	}

	if got := registryToken(&TemplateSource{ID: "public", URL: "https://public.example.com", Enabled: true}); got != "" {
		t.Fatalf("no credential anywhere: got %q, want none", got)
	}
}
