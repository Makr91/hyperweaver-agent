package machines

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Registry auth + transport — the base's TemplateRegistryUtils ported: a
// per-source HTTP client honoring verify_ssl, and the BoxVault token ladder
// (explicit JWT auth_token → JWT-shaped api_key → username+api_key signin →
// raw token fallback). Shared by download and publish.

// registryUserAgent satisfies BoxVault's service-account expectations (the
// base's exact convention, this agent's name).
const registryUserAgent = "Vagrant/2.2.19 Hyperweaver/1.0.0"

// isJWT reports the three-dot-part JWT shape the base sniffs for.
func isJWT(token string) bool {
	return strings.Count(token, ".") == 2 && !strings.Contains(token, " ")
}

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

// setRegistryAuth stamps the auth headers the base's client sends: Bearer
// always, x-access-token additionally when the token is a JWT (BoxVault's API
// endpoints read that header).
func setRegistryAuth(request *http.Request, token string) {
	request.Header.Set("User-Agent", registryUserAgent)
	if token == "" {
		return
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if isJWT(token) {
		request.Header.Set("x-access-token", token)
	}
}

// registryToken resolves the source's effective token (getRegistryToken's
// ladder): a JWT auth_token or api_key is used directly; username+api_key
// signs in for a JWT; failures fall back to the raw token.
func registryToken(ctx context.Context, client *http.Client, source *TemplateSource) string {
	if source.AuthToken != "" && isJWT(source.AuthToken) {
		return source.AuthToken
	}
	if source.APIKey != "" && isJWT(source.APIKey) {
		return source.APIKey
	}
	if source.Username != "" && source.APIKey != "" {
		if token, err := registrySignin(ctx, client, source); err == nil && token != "" {
			return token
		} else if err != nil {
			mlog().Warn("registry signin failed, falling back to raw token",
				"source", source.Name, "error", err)
		}
	}
	if source.AuthToken != "" {
		return source.AuthToken
	}
	return source.APIKey
}

// registrySignin exchanges username+api_key for a JWT (POST /api/auth/signin,
// BoxVault's flow).
func registrySignin(ctx context.Context, client *http.Client, source *TemplateSource) (string, error) {
	body, err := json.Marshal(map[string]any{
		"username":     source.Username,
		"password":     source.APIKey,
		"stayLoggedIn": true,
	})
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		source.URL+"/api/auth/signin", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", registryUserAgent)

	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("signin: HTTP %s", response.Status)
	}
	var parsed struct {
		AccessToken string `json:"accessToken"`
	}
	if derr := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&parsed); derr != nil {
		return "", derr
	}
	return parsed.AccessToken, nil
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

// RegistryToken exposes the token ladder for the server's catalog proxy.
func RegistryToken(ctx context.Context, client *http.Client, source *TemplateSource) string {
	return registryToken(ctx, client, source)
}
