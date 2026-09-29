package oidc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/dpop"
	"github.com/Makr91/hyperweaver-agent/internal/logging"
)

type validator struct {
	provider *provider
	binding  *binding
	clientID string
	baseURL  string
	proofs   *dpop.Seen
}

func tokenKid(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ""
	}
	header := struct {
		Kid string `json:"kid"`
	}{}
	if json.Unmarshal(raw, &header) != nil {
		return ""
	}
	return header.Kid
}

func (v *validator) authenticate(r *http.Request, scheme auth.Scheme, token string) (*auth.Identity, error) {
	jwks, err := v.provider.jwks(false)
	if err != nil {
		slog.Warn("oidc token auth: jwks unavailable", "error", err)
		return nil, errors.New("the identity provider's keys are unavailable")
	}
	claims, err := validateToken(token, jwks, v.provider.issuer, v.clientID)
	if errors.Is(err, errUnknownKey) && v.provider.kidRefetchAllowed(tokenKid(token)) {
		if jwks, err = v.provider.jwks(true); err == nil {
			claims, err = validateToken(token, jwks, v.provider.issuer, v.clientID)
		}
	}
	if err != nil {
		logging.Category("auth").Warn("oidc token rejected", "error", err)
		return nil, errors.New("invalid token")
	}
	switch {
	case scheme == auth.SchemeBearer && claims.BoundJKT != "":
		logging.Category("auth").Warn("key-bound token presented as Bearer")
		return nil, errors.New("a key-bound token must be presented with the DPoP scheme")
	case scheme == auth.SchemeDPoP && claims.BoundJKT == "":
		return nil, errors.New("the token is not key-bound")
	case scheme == auth.SchemeDPoP:
		proofs := r.Header.Values("DPoP")
		if len(proofs) != 1 {
			return nil, errors.New("exactly one DPoP proof header is required")
		}
		htu := v.baseURL + r.URL.Path
		if perr := dpop.Verify(proofs[0], r.Method, htu, token, claims.BoundJKT, time.Now(), v.proofs); perr != nil {
			logging.Category("auth").Warn("dpop proof rejected", "error", perr)
			return nil, errors.New("the DPoP proof was refused: " + perr.Error())
		}
	}
	if !v.binding.allowed(claims) {
		logging.Category("auth").Warn("oidc token refused — not the bound account and not in oidc.allowed_users",
			"subject", claims.Subject, "email", claims.Email)
		return nil, errors.New("the account is not bound to this agent")
	}
	name := claims.Email
	if name == "" {
		name = claims.Subject
	}
	return &auth.Identity{Name: name, Description: "OIDC " + string(scheme) + " token", Role: "admin"}, nil
}
