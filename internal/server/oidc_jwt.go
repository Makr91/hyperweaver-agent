package server

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

type oidcIdentityClaims struct {
	Subject string
	Email   string
}

var errOIDCUnknownKey = errors.New("no matching RSA key in the issuer's JWKS")

func oidcValidateToken(raw string, jwks *oidcJWKSDocument, issuer, audience string) (*oidcIdentityClaims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("id_token is not a three-part JWT")
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("id_token header undecodable: %w", err)
	}
	header := struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}{}
	if uerr := json.Unmarshal(headerRaw, &header); uerr != nil {
		return nil, fmt.Errorf("id_token header unreadable: %w", uerr)
	}
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("token algorithm %q is not RS256", header.Alg)
	}
	publicKey, err := jwks.rsaKey(header.Kid)
	if err != nil {
		return nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("id_token signature undecodable: %w", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if verr := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); verr != nil {
		return nil, errors.New("id_token signature verification failed")
	}

	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("id_token payload undecodable: %w", err)
	}
	payload := struct {
		Issuer   string          `json:"iss"`
		Subject  string          `json:"sub"`
		Audience json.RawMessage `json:"aud"`
		Expiry   int64           `json:"exp"`
		Email    string          `json:"email"`
	}{}
	if uerr := json.Unmarshal(payloadRaw, &payload); uerr != nil {
		return nil, fmt.Errorf("id_token payload unreadable: %w", uerr)
	}
	if strings.TrimRight(payload.Issuer, "/") != strings.TrimRight(issuer, "/") {
		return nil, fmt.Errorf("token issuer %q does not match the configured issuer", payload.Issuer)
	}
	if !oidcAudienceContains(payload.Audience, audience) {
		return nil, fmt.Errorf("token audience does not include %q", audience)
	}
	if payload.Expiry <= time.Now().Unix() {
		return nil, errors.New("token is expired")
	}
	if payload.Subject == "" {
		return nil, errors.New("token carries no subject")
	}
	return &oidcIdentityClaims{Subject: payload.Subject, Email: payload.Email}, nil
}

func oidcAudienceContains(raw json.RawMessage, audience string) bool {
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return single == audience
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, entry := range many {
			if entry == audience {
				return true
			}
		}
	}
	return false
}

func (d *oidcJWKSDocument) rsaKey(kid string) (*rsa.PublicKey, error) {
	for i := range d.Keys {
		key := &d.Keys[i]
		if key.Kty != "RSA" {
			continue
		}
		if kid != "" && key.Kid != kid {
			continue
		}
		modulus, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			return nil, fmt.Errorf("jwks key %s modulus undecodable: %w", key.Kid, err)
		}
		exponentRaw, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			return nil, fmt.Errorf("jwks key %s exponent undecodable: %w", key.Kid, err)
		}
		exponent := 0
		for _, b := range exponentRaw {
			exponent = exponent<<8 | int(b)
		}
		if exponent < 3 {
			return nil, fmt.Errorf("jwks key %s exponent is unusable", key.Kid)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: exponent}, nil
	}
	return nil, fmt.Errorf("kid %q: %w", kid, errOIDCUnknownKey)
}
