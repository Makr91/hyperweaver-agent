package machines

import "testing"

func TestRegistryTokenLadder(t *testing.T) {
	t.Cleanup(func() { SetOIDCTokenSource(nil) })
	source := &TemplateSource{ID: "boxvault", URL: "https://boxvault.example.com", Enabled: true, AuthToken: "server-wide-key"}

	SetOIDCTokenSource(func(createdBy string) string {
		if createdBy == "alice@example.com" {
			return "alice-token"
		}
		return "bound-token"
	})
	if got := registryToken(source, "alice@example.com"); got != "alice-token" {
		t.Fatalf("the key's own account first: got %q", got)
	}
	if got := registryToken(source, "Tray-Login"); got != "bound-token" {
		t.Fatalf("a plain key reads as the bound account: got %q", got)
	}
	if got := registryToken(source, ""); got != "bound-token" {
		t.Fatalf("no key named: got %q, want the bound token", got)
	}

	SetOIDCTokenSource(func(string) string { return "" })
	if got := registryToken(source, "alice@example.com"); got != "server-wide-key" {
		t.Fatalf("no federated token: got %q, want the source's key", got)
	}

	SetOIDCTokenSource(nil)
	if got := registryToken(source, ""); got != "server-wide-key" {
		t.Fatalf("no token source: got %q, want the source's key", got)
	}

	if got := registryToken(&TemplateSource{ID: "public", URL: "https://public.example.com", Enabled: true}, ""); got != "" {
		t.Fatalf("no credential anywhere: got %q, want none", got)
	}
}
