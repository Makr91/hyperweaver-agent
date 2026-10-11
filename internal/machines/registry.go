package machines

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Registry auth + transport — vagrant's own model (Mark's ruling 2026-07-09:
// "API keys, PERIOD"): ONE raw service-account token per source, sent as
// Bearer on every call. BoxVault accepts it everywhere (its verifyToken falls
// back to the service_account table); the base's username/JWT signin ladder
// is deliberately dead — a JWT expires and impersonates the key's owner.
// Shared by download, publish, and the catalog proxy.

// registryUserAgent satisfies BoxVault's service-account expectations (the
// base's exact convention, this agent's name).
const registryUserAgent = "Vagrant/2.2.19 Hyperweaver/1.0.0"

// registryHTTPClient builds the per-source client. Self-signed registries are
// handled PROPERLY: the source's ca_file joins the trust store — verification
// always stays ON (no InsecureSkipVerify; the base's verify_ssl:false knob is
// deliberately not ported — trusting the registry's actual CA is the fix, not
// disabling TLS).
func registryHTTPClient(source *TemplateSource) *http.Client {
	client := &http.Client{}
	if source.CAFile == "" {
		return client
	}
	pem, err := os.ReadFile(filepath.Clean(source.CAFile))
	if err != nil {
		mlog().Error("registry ca_file unreadable — system trust store only",
			"source", source.Name, "ca_file", source.CAFile, "error", err)
		return client
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		mlog().Error("registry ca_file carries no usable PEM certificates",
			"source", source.Name, "ca_file", source.CAFile)
		return client
	}
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}
	return client
}

// setRegistryAuth stamps the auth headers: Bearer with the source's API key.
func setRegistryAuth(request *http.Request, token string) {
	request.Header.Set("User-Agent", registryUserAgent)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
}

var oidcTokenSource func(createdBy string) string

// SetOIDCTokenSource wires the federated access token a read runs under, the
// one of the key named createdBy, else the bound account's, as the first
// registry credential; the source's auth_token is the fallback.
func SetOIDCTokenSource(source func(createdBy string) string) {
	oidcTokenSource = source
}

// registryToken resolves the source's credential for the key named
// createdBy: that key's own account's access token, else the bound
// account's, while one is held, else the source's configured API key
// (BoxVault service-account token), else none.
func registryToken(source *TemplateSource, createdBy string) string {
	if oidcTokenSource != nil {
		if token := oidcTokenSource(createdBy); token != "" {
			return token
		}
	}
	return source.AuthToken
}

// registryPost sends one JSON document and reports the status code.
// Conflict-class answers (400/409 — duplicate box/version/provider/arch) are
// SUCCESS for the ensure-structure calls (the base's ignoreConflict).
func registryPost(ctx context.Context, client *http.Client, token, url string, document map[string]any) (int, error) {
	return registrySend(ctx, client, token, http.MethodPost, url, document)
}

// registrySend is registryPost's method-generic core (the release step PUTs).
func registrySend(ctx context.Context, client *http.Client, token, method, url string, document map[string]any) (int, error) {
	body, err := json.Marshal(document)
	if err != nil {
		return 0, err
	}
	request, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	setRegistryAuth(request, token)

	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	return response.StatusCode, nil
}

// conflictOK folds the base's ignoreConflict rule over a status code.
func conflictOK(status int) bool {
	return status == http.StatusOK || status == http.StatusCreated ||
		status == http.StatusBadRequest || status == http.StatusConflict
}

// registryUploadTimeout bounds one chunk request (the base's
// upload.timeout_seconds default 7200).
const registryUploadTimeout = 2 * time.Hour

// RegistryHTTPClient exposes the per-source client (ca_file honored) for the
// server's catalog proxy — ONE registry-transport implementation.
func RegistryHTTPClient(source *TemplateSource) *http.Client {
	return registryHTTPClient(source)
}

// RegistryToken exposes the source's credential for the key named createdBy, that key's account's token, else the bound account's, before the source's API key, for the server's catalog proxy.
func RegistryToken(source *TemplateSource, createdBy string) string {
	return registryToken(source, createdBy)
}

// RegistryFetch sends one GET to the enabled source sourceID names at path, Bearer the credential of the key named createdBy under the registry ladder; the caller closes the body.
func RegistryFetch(ctx context.Context, sources []TemplateSource, sourceID, createdBy, path string) (*http.Response, error) {
	source, err := findTemplateSource(sources, sourceID)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(source.URL, "/")+path, http.NoBody)
	if err != nil {
		return nil, err
	}
	setRegistryAuth(request, registryToken(source, createdBy))
	request.Header.Set("Accept", "application/json")
	return registryHTTPClient(source).Do(request)
}
