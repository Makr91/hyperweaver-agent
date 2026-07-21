package auth

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/keys"
	"github.com/Makr91/hyperweaver-agent/internal/logging"
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
	"/server",
	"/system/host",
	"/system/users",
	"/system/groups",
	"/system/roles",
	"/database",
	// Applying an agent update replaces the binary and exits the process.
	"/app",
}

// Surfaces that are admin-only regardless of method: key management, agent
// settings (which can expose credentials), the global secrets store, and the
// host terminal (a shell as the agent's own user is full host access — even
// listing sessions stays admin).
var adminAlwaysPrefixes = []string{"/api-keys", "/settings", "/secrets", "/term"}

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
	if path == "/api-keys/info" {
		return "viewer"
	}
	if underPrefix(path, adminAlwaysPrefixes) {
		return "admin"
	}
	if path == "/ws-ticket" || underPrefix(path, []string{"/filesystem"}) {
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

// ExtractKey pulls the API key from X-API-Key or Authorization: Bearer.
func ExtractKey(r *http.Request) string {
	if key := r.Header.Get("X-API-Key"); key != "" {
		return key
	}
	parts := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

// ErrorMsg is the agent's auth-layer error envelope (the spec's Error
// component).
type ErrorMsg struct {
	// Error message
	Msg string `json:"msg"`
}

// WriteMsg writes the agent's error shape: {"msg": "..."} — the field the
// Hyperweaver UI surfaces.
func WriteMsg(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(ErrorMsg{Msg: msg}); err != nil {
		slog.Error("write error response", "error", err)
	}
}

// BearerValidator authenticates a non-API-key bearer credential (an OIDC
// access token); nil = rejected.
type BearerValidator func(token string) *Identity

// Middleware validates the credential and enforces the role policy, mirroring
// the Node agent's verifyApiKey: 401 missing credential, 403 invalid, 403
// insufficient role. API keys (hw_-prefixed) authenticate against the key
// store; a JWT-shaped bearer credential goes to the BearerValidator instead
// (the OIDC resource-server door — nil validator disables it). On success the
// identity is attached to the context.
func Middleware(store *keys.Store, bearer BearerValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			credential := ExtractKey(r)
			if credential == "" {
				WriteMsg(w, http.StatusUnauthorized,
					"API key required - provide either X-API-Key header or Authorization: Bearer header")
				return
			}

			var identity *Identity
			if bearer != nil && strings.Count(credential, ".") == 2 &&
				!strings.HasPrefix(credential, "hw_") {
				identity = bearer(credential)
				if identity == nil {
					WriteMsg(w, http.StatusForbidden, "Invalid bearer token")
					return
				}
			} else {
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
