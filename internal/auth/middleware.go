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
}

// Surfaces that are admin-only regardless of method: key management and agent
// settings (which can expose credentials).
var adminAlwaysPrefixes = []string{"/api-keys", "/settings"}

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

// WriteMsg writes the agent's error shape: {"msg": "..."} — the field the
// Hyperweaver UI surfaces.
func WriteMsg(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]string{"msg": msg}); err != nil {
		slog.Error("write error response", "error", err)
	}
}

// Middleware validates the API key and enforces the role policy, mirroring
// the Node agent's verifyApiKey: 401 missing key, 403 invalid key, 403
// insufficient role. On success the identity is attached to the context.
func Middleware(store *keys.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiKey := ExtractKey(r)
			if apiKey == "" {
				WriteMsg(w, http.StatusUnauthorized,
					"API key required - provide either X-API-Key header or Authorization: Bearer header")
				return
			}

			match, err := store.Verify(apiKey)
			if err != nil {
				alog().Error("api key validation failed", "error", err, "path", r.URL.Path)
				WriteMsg(w, http.StatusInternalServerError, "API key validation failed")
				return
			}
			if match == nil {
				WriteMsg(w, http.StatusForbidden, "Invalid API key")
				return
			}

			needed := RequiredRole(r.Method, r.URL.Path)
			if roleLevels[match.Role] < roleLevels[needed] {
				alog().Warn("api key role insufficient for request",
					"entity_name", match.Name,
					"role", match.Role,
					"required_role", needed,
					"request_path", r.URL.Path,
					"request_method", r.Method,
				)
				WriteMsg(w, http.StatusForbidden,
					"Insufficient role: this operation requires '"+needed+"' (key role: '"+match.Role+"')")
				return
			}

			identity := &Identity{
				ID:          match.ID,
				Name:        match.Name,
				Description: match.Description,
				Role:        match.Role,
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, identity)))
		})
	}
}
