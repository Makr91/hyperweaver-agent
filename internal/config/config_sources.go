// Package config loads and provides the agent's YAML configuration.
package config

// TemplateSourceConfig is one configured box registry
// (Vagrant/BoxVault-compatible download API).
type TemplateSourceConfig struct {
	Name    string `yaml:"name"    json:"name"`
	URL     string `yaml:"url"     json:"url"`
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Default bool   `yaml:"default" json:"default"`
	// AuthToken is the registry API key — a BoxVault service-account token,
	// sent raw as Bearer on every call (vagrant's own model; Mark's ruling
	// 2026-07-09: "API keys, PERIOD"). The ONLY credential: the base's
	// username/JWT signin ladder is deliberately dead.
	AuthToken string `yaml:"auth_token" json:"auth_token"`
	// CAFile adds a PEM CA bundle to the trust store for this registry —
	// the self-signed-registry answer. Verification always stays on (the
	// base's verify_ssl:false is deliberately not ported).
	CAFile string `yaml:"ca_file" json:"ca_file"`
}

// TemplateSourcesConfig controls the box-template registry (the base's
// template_sources block): where downloaded box disk images live and which
// registries serve them.
type TemplateSourcesConfig struct {
	// LocalStoragePath is the template storage root
	// (<root>/<org>/<box>/<version>/). Empty selects templates under the
	// data root.
	LocalStoragePath string `yaml:"local_storage_path" json:"local_storage_path"`
	// Sources are the configured registries; the entry flagged default
	// serves requests that name no source (names are display-only).
	Sources []TemplateSourceConfig `yaml:"sources" json:"sources"`
}

// CatalogSourceConfig is one configured provisioner catalog (design §7 —
// the HACS model; the second door is a forked catalog repo added here).
type CatalogSourceConfig struct {
	Name    string `yaml:"name"    json:"name"`
	URL     string `yaml:"url"     json:"url"`
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Default bool   `yaml:"default" json:"default"`
	// CAFile adds a PEM CA bundle to the trust store for this catalog —
	// self-hosted forks behind private CAs. Verification always stays on.
	CAFile string `yaml:"ca_file" json:"ca_file"`
}

// CatalogSourcesConfig controls the provisioner catalog client (mirrors the
// template-sources pattern).
type CatalogSourcesConfig struct {
	Sources []CatalogSourceConfig `yaml:"sources" json:"sources"`
}
