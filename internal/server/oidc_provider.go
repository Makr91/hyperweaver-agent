package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var oidcHTTPClient = &http.Client{Timeout: 15 * time.Second}

type oidcProviderEndpoints struct {
	Issuer              string `json:"issuer"`
	DeviceAuthorization string `json:"device_authorization_endpoint"`
	Token               string `json:"token_endpoint"`
	JWKSURI             string `json:"jwks_uri"`
}

func oidcDiscover(ctx context.Context, issuer string) (*oidcProviderEndpoints, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(issuer, "/")+"/.well-known/openid-configuration", http.NoBody)
	if err != nil {
		return nil, err
	}
	response, err := oidcHTTPClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery answered HTTP %d", response.StatusCode)
	}
	endpoints := &oidcProviderEndpoints{}
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

type oidcDeviceAuthorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

func oidcStartDeviceAuthorization(ctx context.Context, endpoints *oidcProviderEndpoints, clientID, scope string) (*oidcDeviceAuthorization, error) {
	form := url.Values{
		"client_id": {clientID},
		"scope":     {scope},
	}
	body, status, err := oidcPostForm(ctx, endpoints.DeviceAuthorization, form)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("device authorization answered HTTP %d: %s", status, strings.TrimSpace(string(body)))
	}
	authorization := &oidcDeviceAuthorization{}
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

type oidcTokenAnswer struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
}

func oidcPollToken(ctx context.Context, endpoints *oidcProviderEndpoints, clientID, deviceCode string) (*oidcTokenAnswer, error) {
	form := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {clientID},
	}
	return oidcTokenCall(ctx, endpoints.Token, form)
}

func oidcRefreshTokens(ctx context.Context, endpoints *oidcProviderEndpoints, clientID, refreshToken string) (*oidcTokenAnswer, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	}
	return oidcTokenCall(ctx, endpoints.Token, form)
}

func oidcTokenCall(ctx context.Context, endpoint string, form url.Values) (*oidcTokenAnswer, error) {
	body, status, err := oidcPostForm(ctx, endpoint, form)
	if err != nil {
		return nil, err
	}
	answer := &oidcTokenAnswer{}
	if uerr := json.Unmarshal(body, answer); uerr != nil {
		return nil, fmt.Errorf("token endpoint answered HTTP %d with an unreadable body", status)
	}
	return answer, nil
}

func oidcPostForm(ctx context.Context, endpoint string, form url.Values) (body []byte, status int, err error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := oidcHTTPClient.Do(request)
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

type oidcJWKSDocument struct {
	Keys []oidcJWKSKey `json:"keys"`
}

type oidcJWKSKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func oidcFetchJWKS(ctx context.Context, uri string) (*oidcJWKSDocument, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, http.NoBody)
	if err != nil {
		return nil, err
	}
	response, err := oidcHTTPClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks fetch answered HTTP %d", response.StatusCode)
	}
	document := &oidcJWKSDocument{}
	if derr := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(document); derr != nil {
		return nil, fmt.Errorf("jwks document unreadable: %w", derr)
	}
	return document, nil
}
