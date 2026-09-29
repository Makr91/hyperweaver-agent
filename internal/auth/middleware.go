package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/keys"
	"github.com/Makr91/hyperweaver-agent/internal/logging"
	"github.com/Makr91/hyperweaver-agent/internal/problem"
)

// alog is this package's category logger (the Node agent's auth logger:
// logging.categories.auth overrides its level).
func alog() *slog.Logger {
	return logging.Category("auth")
}

// Role hierarchy for the direct-mode authorization model (Agent API v1).
// Unknown roles compare as 0 and only pass checks requiring nothing.
var roleLevels = map[string]int{"viewer": 1, "operator": 2, "admin": 3}

// Admin-only surfaces for MUTATING requests (reads stay viewer-accessible).
var adminWritePrefixes = []string{
	"/api/server",
	"/api/system/host",
	"/api/system/users",
	"/api/system/groups",
	"/api/system/roles",
	"/api/database",
	// Applying an agent update replaces the binary and exits the process.
	"/api/app",
}

// Surfaces that are admin-only regardless of method: key management, the
// configuration files (which can expose credentials), the global secrets
// store, and the host terminal (a shell as the agent's own user is full host
// access — even listing sessions stays admin). GET /api/config/ticket is
// public and never passes through this middleware.
var adminAlwaysPrefixes = []string{"/api/api-keys", "/api/config", "/api/secrets", "/api/term"}

func underPrefix(path string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

// RequiredRole is the central method+path policy (Agent API v1), ported
// verbatim from the Node agent's middleware/VerifyApiKey.js.
func RequiredRole(method, path string) string {
	if path == "/api/api-keys/info" {
		return "viewer"
	}
	if underPrefix(path, adminAlwaysPrefixes) {
		return "admin"
	}
	if path == "/api/ws-ticket" || underPrefix(path, []string{"/api/filesystem"}) {
		return "operator"
	}
	if method == http.MethodGet || method == http.MethodHead {
		return "viewer"
	}
	if underPrefix(path, adminWritePrefixes) {
		return "admin"
	}
	return "operator"
}

type contextKey struct{}

// Identity is the authenticated key attached to the request context.
type Identity struct {
	ID          int64
	Name        string
	Description string
	Role        string
}

// FromContext returns the authenticated identity, or nil on unauthenticated
// requests (public routes).
func FromContext(ctx context.Context) *Identity {
	id, _ := ctx.Value(contextKey{}).(*Identity)
	return id
}

// Scheme names how a credential arrived.
type Scheme string

// The schemes a request may carry.
const (
	SchemeAPIKey Scheme = "apikey"
	SchemeBearer Scheme = "Bearer"
	SchemeDPoP   Scheme = "DPoP"
)

// ErrAmbiguous is two Authorization headers on one request (RFC 9449 §7.2).
var ErrAmbiguous = errors.New("multiple Authorization headers")

// ErrScheme is an Authorization scheme the agent does not read.
var ErrScheme = errors.New("unsupported Authorization scheme")

// Credential reads the request's credential: X-API-Key, else Authorization as Bearer or DPoP.
func Credential(r *http.Request) (Scheme, string, error) {
	if key := r.Header.Get("X-API-Key"); key != "" {
		return SchemeAPIKey, key, nil
	}
	values := r.Header.Values("Authorization")
	if len(values) > 1 {
		return "", "", ErrAmbiguous
	}
	if len(values) == 0 {
		return "", "", nil
	}
	name, token, found := strings.Cut(values[0], " ")
	token = strings.TrimSpace(token)
	if !found || token == "" {
		return "", "", ErrScheme
	}
	switch {
	case strings.EqualFold(name, string(SchemeBearer)):
		return SchemeBearer, token, nil
	case strings.EqualFold(name, string(SchemeDPoP)):
		return SchemeDPoP, token, nil
	}
	return "", "", ErrScheme
}

// Challenge is the WWW-Authenticate value a 401 carries: bare schemes with no credential, the failed scheme's error otherwise.
func Challenge(scheme Scheme, code string) string {
	if code == "" {
		return `Bearer, DPoP algs="ES256"`
	}
	if scheme == SchemeDPoP {
		return `DPoP error="` + code + `", algs="ES256"`
	}
	return `Bearer error="` + code + `", DPoP algs="ES256"`
}

// Unauthorized answers 401 with the challenge header and a problem body.
func Unauthorized(w http.ResponseWriter, scheme Scheme, code, detail string) {
	w.Header().Set("WWW-Authenticate", Challenge(scheme, code))
	problem.Detail(w, http.StatusUnauthorized, detail)
}

// WriteMsg writes a problem body of the status's registry type with msg as its detail.
func WriteMsg(w http.ResponseWriter, status int, msg string) {
	problem.Detail(w, status, msg)
}

// TokenValidator authenticates an identity-provider token under its scheme; nil identity with the refusal's reason.
type TokenValidator func(r *http.Request, scheme Scheme, token string) (*Identity, error)

// Middleware validates the credential and enforces the role policy, mirroring
// the Node agent's verifyApiKey: 401 missing credential, 403 invalid, 403
// insufficient role. API keys (hw_-prefixed) authenticate against the key
// store; a JWT-shaped credential goes to the TokenValidator instead (the
// OIDC resource-server door — nil validator disables it). On success the
// identity is attached to the context.
func Middleware(store *keys.Store, tokens TokenValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scheme, credential, cerr := Credential(r)
			switch {
			case errors.Is(cerr, ErrAmbiguous):
				problem.Detail(w, http.StatusBadRequest, "Multiple methods used to include an access token")
				return
			case errors.Is(cerr, ErrScheme):
				Unauthorized(w, "", "", "Authorization scheme must be Bearer or DPoP")
				return
			case credential == "":
				Unauthorized(w, "", "",
					"API key required - provide either X-API-Key header or Authorization: Bearer header")
				return
			}

			var identity *Identity
			isJWT := strings.Count(credential, ".") == 2 && !strings.HasPrefix(credential, "hw_")
			switch {
			case scheme == SchemeDPoP && !isJWT:
				Unauthorized(w, SchemeDPoP, "invalid_token", "An API key is never key-bound; send it as Bearer or X-API-Key")
				return
			case tokens != nil && isJWT:
				var terr error
				identity, terr = tokens(r, scheme, credential)
				if identity == nil {
					code := "invalid_token"
					if terr != nil && strings.Contains(terr.Error(), "DPoP proof") {
						code = "invalid_dpop_proof"
					}
					detail := "Invalid bearer token"
					if terr != nil {
						detail = terr.Error()
					}
					Unauthorized(w, scheme, code, detail)
					return
				}
			default:
				match, err := store.Verify(credential)
				if err != nil {
					alog().Error("api key validation failed", "error", err, "path", r.URL.Path)
					WriteMsg(w, http.StatusInternalServerError, "API key validation failed")
					return
				}
				if match == nil {
					WriteMsg(w, http.StatusForbidden, "Invalid API key")
					return
				}
				identity = &Identity{
					ID:          match.ID,
					Name:        match.Name,
					Description: match.Description,
					Role:        match.Role,
				}
			}

			needed := RequiredRole(r.Method, r.URL.Path)
			if roleLevels[identity.Role] < roleLevels[needed] {
				alog().Warn("credential role insufficient for request",
					"entity_name", identity.Name,
					"role", identity.Role,
					"required_role", needed,
					"request_path", r.URL.Path,
					"request_method", r.Method,
				)
				WriteMsg(w, http.StatusForbidden,
					"Insufficient role: this operation requires '"+needed+"' (key role: '"+identity.Role+"')")
				return
			}

			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, identity)))
		})
	}
}
