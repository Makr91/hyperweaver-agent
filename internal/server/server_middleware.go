package server

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/config"
	"github.com/Makr91/hyperweaver-agent/internal/logging"
)

// corsMiddleware implements the Node agent's CORS policy (its index.js
// corsOptions): an API-key-authenticated backend in a many-to-many mesh
// gates on the key, not the browser Origin — allow_all (default true)
// answers any Origin, allow_all: false falls back to the whitelist.
// Disallowed origins are declined by omitting the CORS headers, never by
// failing the request. Credentialed responses echo the Origin (a wildcard is
// invalid with credentials).
func corsMiddleware(cfg *config.CORSConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			// Not a cross-origin browser request.
			next.ServeHTTP(w, r)
			return
		}

		allowed := cfg.AllowAll
		if !allowed {
			for _, entry := range cfg.Whitelist {
				if entry == origin {
					allowed = true
					break
				}
			}
		}

		headers := w.Header()
		if allowed {
			headers.Set("Access-Control-Allow-Origin", origin)
			headers.Set("Access-Control-Allow-Credentials", "true")
			headers.Add("Vary", "Origin")
		} else {
			logging.Category("api_requests").Warn("CORS: origin not allowed", "origin", origin)
		}

		// Preflight: answered here (204) — the mux has no OPTIONS routes.
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			if allowed {
				headers.Set("Access-Control-Allow-Methods", "GET,HEAD,PUT,PATCH,POST,DELETE")
				if requestHeaders := r.Header.Get("Access-Control-Request-Headers"); requestHeaders != "" {
					headers.Set("Access-Control-Allow-Headers", requestHeaders)
					headers.Add("Vary", "Access-Control-Request-Headers")
				}
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// requestLog logs each request at debug level under the api_requests
// category (the Node agent's api-requests logger).
func requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		logging.Category("api_requests").Debug("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

// recoverer converts handler panics into 500s instead of killing the process.
func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("handler panic", "panic", rec, "path", r.URL.Path)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
