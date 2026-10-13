package provisioner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// catalogMetadataLimit bounds one protected resource metadata read.
const catalogMetadataLimit = 1 << 20

// protectedResourcePath is the well-known suffix of RFC 9728 protected resource metadata.
const protectedResourcePath = "/.well-known/oauth-protected-resource"

var (
	oidcIssuer      string
	oidcTokenSource func(ctx context.Context, createdBy, resource string) (string, error)
	oidcTokenForget func(createdBy, resource string)
)

// SetOIDCTokenSource wires the identity provider's issuer, the function answering an access token for a resource identifier from the account of the key named createdBy, else the bound account's, and the function dropping that token after the resource refused it.
func SetOIDCTokenSource(issuer string, source func(ctx context.Context, createdBy, resource string) (string, error), forget func(createdBy, resource string)) {
	oidcIssuer = issuer
	oidcTokenSource = source
	oidcTokenForget = forget
}

// ErrCatalogAuth is answered when the identity provider refused to mint the catalog's token or the catalog refused the one sent.
var ErrCatalogAuth = errors.New("the catalog requires a signed-in account")

type protectedResource struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
}

var catalogResources = struct {
	mu       sync.Mutex
	byOrigin map[string]string
}{byOrigin: map[string]string{}}

func catalogOrigin(catalogURL string) (string, error) {
	parsed, err := url.Parse(catalogURL)
	if err != nil || parsed.Host == "" {
		return "", fmt.Errorf("catalog url %q names no host", catalogURL)
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

func sameIssuer(a, b string) bool {
	return strings.TrimRight(a, "/") == strings.TrimRight(b, "/")
}

// catalogResource answers the catalog's resource identifier from its RFC 9728 metadata at its origin, read once per origin and again after a refusal, or the empty string for a catalog that publishes none, names another resource or does not name this agent's issuer; an error only when the metadata could not be fetched.
func catalogResource(ctx context.Context, source *CatalogSource) (string, error) {
	origin, err := catalogOrigin(source.URL)
	if err != nil {
		return "", err
	}
	catalogResources.mu.Lock()
	resource, known := catalogResources.byOrigin[origin]
	catalogResources.mu.Unlock()
	if known {
		return resource, nil
	}
	client, err := catalogClient(source, catalogFetchTimeout)
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+protectedResourcePath, http.NoBody)
	if err != nil {
		return "", err
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("read catalog %s resource metadata: %w", source.Name, err)
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK {
		slog.Debug("catalog publishes no protected resource metadata; reading anonymously", "source", source.Name, "status", response.StatusCode)
		return "", nil
	}
	metadata := protectedResource{}
	if derr := json.NewDecoder(io.LimitReader(response.Body, catalogMetadataLimit)).Decode(&metadata); derr != nil {
		return "", fmt.Errorf("parse catalog %s resource metadata: %w", source.Name, derr)
	}
	if metadata.Resource != origin || !namesIssuer(metadata.AuthorizationServers) {
		slog.Debug("catalog metadata is not for this agent's issuer; reading anonymously", "source", source.Name, "resource", metadata.Resource, "authorization_servers", metadata.AuthorizationServers)
		return "", nil
	}
	catalogResources.mu.Lock()
	catalogResources.byOrigin[origin] = metadata.Resource
	catalogResources.mu.Unlock()
	return metadata.Resource, nil
}

func namesIssuer(servers []string) bool {
	for _, server := range servers {
		if sameIssuer(server, oidcIssuer) {
			return true
		}
	}
	return false
}

// forgetCatalogCredentials drops the resource identifier read for the source's origin and the token kept for it, after the catalog refused a read.
func forgetCatalogCredentials(source *CatalogSource, createdBy string) {
	origin, err := catalogOrigin(source.URL)
	if err != nil {
		return
	}
	catalogResources.mu.Lock()
	resource, known := catalogResources.byOrigin[origin]
	delete(catalogResources.byOrigin, origin)
	catalogResources.mu.Unlock()
	if known && oidcTokenForget != nil {
		oidcTokenForget(createdBy, resource)
	}
}

// catalogRequest builds one GET against the source, Bearer a token minted for the catalog's resource identifier from the key createdBy's account, else the bound account's, whenever one is held and the catalog's metadata names this agent's issuer; otherwise the read goes out anonymous.
func catalogRequest(ctx context.Context, source *CatalogSource, target, createdBy string) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		return nil, err
	}
	if oidcTokenSource == nil {
		return request, nil
	}
	resource, rerr := catalogResource(ctx, source)
	if rerr != nil {
		return nil, rerr
	}
	if resource == "" {
		return request, nil
	}
	token, terr := oidcTokenSource(ctx, createdBy, resource)
	if terr != nil {
		return nil, fmt.Errorf("%w: %s", ErrCatalogAuth, terr.Error())
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	return request, nil
}

func catalogRefused(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden
}

// catalogRefusal answers the error for a catalog that refused the token: 403 names a missing membership, 401 a token the catalog does not take.
func catalogRefusal(source *CatalogSource, status int) error {
	if status == http.StatusForbidden {
		return fmt.Errorf("%w: the signed-in account is not a member of the organization catalog %s serves", ErrCatalogAuth, source.Name)
	}
	return fmt.Errorf("%w: catalog %s refused the token (HTTP %d)", ErrCatalogAuth, source.Name, status)
}
