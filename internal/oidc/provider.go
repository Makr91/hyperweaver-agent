package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var httpClient = &http.Client{Timeout: 15 * time.Second}

const (
	cacheFreshFor      = 15 * time.Minute
	unknownKidCooldown = 5 * time.Minute
)

type provider struct {
	mu               sync.Mutex
	issuer           string
	ctx              context.Context
	endpointsCache   *providerEndpoints
	endpointsFetched time.Time
	jwksCache        *jwksDocument
	jwksFetched      time.Time
	unknownKids      map[string]time.Time
}

func (p *provider) endpoints(ctx context.Context) (*providerEndpoints, error) {
	p.mu.Lock()
	cached := p.endpointsCache
	fresh := time.Since(p.endpointsFetched) < cacheFreshFor
	p.mu.Unlock()
	if cached != nil && fresh {
		return cached, nil
	}
	fetched, err := discover(ctx, p.issuer)
	if err != nil {
		if cached != nil {
			return cached, nil
		}
		return nil, err
	}
	p.mu.Lock()
	p.endpointsCache = fetched
	p.endpointsFetched = time.Now()
	p.mu.Unlock()
	return fetched, nil
}

func (p *provider) jwks(force bool) (*jwksDocument, error) {
	p.mu.Lock()
	cached := p.jwksCache
	fresh := time.Since(p.jwksFetched) < cacheFreshFor
	p.mu.Unlock()
	if cached != nil && fresh && !force {
		return cached, nil
	}
	endpoints, err := p.endpoints(p.ctx)
	if err != nil {
		return nil, err
	}
	return p.refreshJWKS(endpoints.JWKSURI)
}

func (p *provider) refreshJWKS(uri string) (*jwksDocument, error) {
	fetched, err := fetchJWKS(p.ctx, uri)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.jwksCache = fetched
	p.jwksFetched = time.Now()
	p.mu.Unlock()
	return fetched, nil
}

func (p *provider) kidRefetchAllowed(kid string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for known, seen := range p.unknownKids {
		if now.Sub(seen) > unknownKidCooldown {
			delete(p.unknownKids, known)
		}
	}
	if _, cooling := p.unknownKids[kid]; cooling {
		return false
	}
	p.unknownKids[kid] = now
	return true
}

type providerEndpoints struct {
	Issuer              string `json:"issuer"`
	Authorization       string `json:"authorization_endpoint"`
	DeviceAuthorization string `json:"device_authorization_endpoint"`
	Token               string `json:"token_endpoint"`
	JWKSURI             string `json:"jwks_uri"`
}

func discover(ctx context.Context, issuer string) (*providerEndpoints, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(issuer, "/")+"/.well-known/openid-configuration", http.NoBody)
	if err != nil {
		return nil, err
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery answered HTTP %d", response.StatusCode)
	}
	endpoints := &providerEndpoints{}
	if derr := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(endpoints); derr != nil {
		return nil, fmt.Errorf("discovery document unreadable: %w", derr)
	}
	if endpoints.DeviceAuthorization == "" {
		return nil, fmt.Errorf("issuer %s does not advertise a device_authorization_endpoint", issuer)
	}
	if endpoints.Token == "" || endpoints.JWKSURI == "" {
		return nil, fmt.Errorf("issuer %s discovery document is missing token_endpoint or jwks_uri", issuer)
	}
	return endpoints, nil
}

// DeviceAuthorization is the issuer's answer to a device authorization request.
type DeviceAuthorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

func startDeviceAuthorization(ctx context.Context, endpoints *providerEndpoints, clientID, scope string) (*DeviceAuthorization, error) {
	form := url.Values{
		"client_id": {clientID},
		"scope":     {scope},
	}
	body, status, err := postForm(ctx, endpoints.DeviceAuthorization, form)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("device authorization answered HTTP %d: %s", status, strings.TrimSpace(string(body)))
	}
	authorization := &DeviceAuthorization{}
	if uerr := json.Unmarshal(body, authorization); uerr != nil {
		return nil, fmt.Errorf("device authorization endpoint %s answered a non-JSON body: %w", endpoints.DeviceAuthorization, uerr)
	}
	if authorization.DeviceCode == "" || authorization.UserCode == "" {
		return nil, fmt.Errorf("device authorization answer carries no device_code")
	}
	if authorization.Interval < 1 {
		authorization.Interval = 5
	}
	if authorization.ExpiresIn < 1 {
		authorization.ExpiresIn = 600
	}
	return authorization, nil
}

type tokenAnswer struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
}

func pollToken(ctx context.Context, endpoints *providerEndpoints, clientID, deviceCode string) (*tokenAnswer, error) {
	form := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {clientID},
	}
	return tokenCall(ctx, endpoints.Token, form)
}

func refreshTokens(ctx context.Context, endpoints *providerEndpoints, clientID, refreshToken string) (*tokenAnswer, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	}
	return tokenCall(ctx, endpoints.Token, form)
}

func exchangeCode(ctx context.Context, endpoints *providerEndpoints, clientID, code, redirectURI, verifier string) (*tokenAnswer, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	}
	return tokenCall(ctx, endpoints.Token, form)
}

func tokenCall(ctx context.Context, endpoint string, form url.Values) (*tokenAnswer, error) {
	body, status, err := postForm(ctx, endpoint, form)
	if err != nil {
		return nil, err
	}
	answer := &tokenAnswer{}
	if uerr := json.Unmarshal(body, answer); uerr != nil {
		return nil, fmt.Errorf("token endpoint answered HTTP %d with an unreadable body", status)
	}
	return answer, nil
}

func postForm(ctx context.Context, endpoint string, form url.Values) (body []byte, status int, err error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	body, err = io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, response.StatusCode, err
	}
	return body, response.StatusCode, nil
}

type jwksDocument struct {
	Keys []jwksKey `json:"keys"`
}

type jwksKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func fetchJWKS(ctx context.Context, uri string) (*jwksDocument, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, http.NoBody)
	if err != nil {
		return nil, err
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks fetch answered HTTP %d", response.StatusCode)
	}
	document := &jwksDocument{}
	if derr := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(document); derr != nil {
		return nil, fmt.Errorf("jwks document unreadable: %w", derr)
	}
	return document, nil
}
