// Package config loads and provides the agent's YAML configuration.
package config

// ServerConfig controls the HTTP and HTTPS listeners.
type ServerConfig struct {
	BindAddress string `yaml:"bind_address" json:"bind_address"`
	Port        int    `yaml:"port"         json:"port"`
	// HTTPSPort is the TLS listener's port (the Node agent's
	// server.https_port); bound only when ssl.enabled.
	HTTPSPort int `yaml:"https_port" json:"https_port"`
}

// SSLConfig controls the agent's HTTPS listener (the Node agent's ssl block,
// lib/SSLManager.js semantics: certificate problems never stop the agent —
// HTTPS is skipped with an error in the log and HTTP keeps serving).
type SSLConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// ForceSecure (default true) makes the plain-HTTP port serve ONLY 308
	// redirects once the TLS listener is up — SSL enabled means ALL traffic
	// rides TLS. false is the escape valve (a runtime serving-mode toggle,
	// cors.allow_all's species): the HTTP port keeps serving the full app
	// alongside HTTPS for clients that cannot chase redirects.
	ForceSecure bool `yaml:"force_secure" json:"force_secure"`
	// GenerateSSL creates the server certificate at the paths below when
	// none exists (the Node agent's generateSSLCertificatesIfNeeded, done
	// with crypto/x509 instead of shelling out to openssl). When an
	// operator-provided CA pair exists at the CA paths, the generated server
	// certificate is signed by that CA (Mark's model: ship a CA — wildcard
	// capable — and everything chains to it); otherwise it is self-signed.
	GenerateSSL bool `yaml:"generate_ssl" json:"generate_ssl"`
	// KeyPath/CertPath locate the server private key and certificate. Empty
	// selects <config dir>/ssl/server.key and <config dir>/ssl/server.crt.
	KeyPath  string `yaml:"key_path"  json:"key_path"`
	CertPath string `yaml:"cert_path" json:"cert_path"`
	// CACertPath/CAKeyPath locate the operator-provided CA used to sign the
	// generated server certificate. Empty selects <config dir>/ssl/ca.crt
	// and <config dir>/ssl/ca.key. Absent files mean self-signed generation.
	CACertPath string `yaml:"ca_cert_path" json:"ca_cert_path"`
	CAKeyPath  string `yaml:"ca_key_path"  json:"ca_key_path"`
}

// CORSConfig controls Cross-Origin Resource Sharing (the Node agent's cors
// block): this is an API-key-authenticated backend in a many-to-many mesh —
// the key, not the browser Origin, is the access boundary, so allow_all
// defaults to true. allow_all: false falls back to the explicit whitelist.
type CORSConfig struct {
	AllowAll  bool     `yaml:"allow_all" json:"allow_all"`
	Whitelist []string `yaml:"whitelist" json:"whitelist"`
}

// StatsConfig controls the /stats endpoint (the Node agent's stats block).
type StatsConfig struct {
	// PublicAccess serves GET /stats without an API key.
	PublicAccess bool `yaml:"public_access" json:"public_access"`
}

// APIKeysConfig controls API-key authentication (Agent API v1 local tier).
// Field names and defaults mirror the Node agent's api_keys block.
type APIKeysConfig struct {
	BootstrapEnabled           bool `yaml:"bootstrap_enabled"             json:"bootstrap_enabled"`
	BootstrapAutoDisable       bool `yaml:"bootstrap_auto_disable"        json:"bootstrap_auto_disable"`
	BootstrapRequireClaimToken bool `yaml:"bootstrap_require_claim_token" json:"bootstrap_require_claim_token"`
	HashRounds                 int  `yaml:"hash_rounds"                   json:"hash_rounds"`
	KeyLength                  int  `yaml:"key_length"                    json:"key_length"`
}

// UpdatesConfig controls update checking (SHI/Node-agent versioninfo model).
type UpdatesConfig struct {
	// VersionInfoURL points at a JSON document {version, releaseUrl,
	// releaseDate, changelog}; empty disables update checking.
	VersionInfoURL string `yaml:"versioninfo_url" json:"versioninfo_url"`
}

// APIDocsConfig controls the interactive Agent API documentation (Swagger UI
// at /api-docs), mirroring the Node agent's api_docs block.
type APIDocsConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}
