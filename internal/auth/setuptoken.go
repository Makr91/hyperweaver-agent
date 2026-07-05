// Package auth implements the agent's authentication surface: the setup
// (claim) token for first-key bootstrap and the API-key middleware enforcing
// the Agent API v1 direct-mode role model.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// setup.token holds 32 random bytes as hex, written 0600 beside the config.
const tokenHexLength = 64

// GetOrGenerateSetupToken reads the existing setup token, or generates and
// persists a new one. Idempotent: a valid existing token is reused (e.g. one
// seeded by a package). Returns "" when the token cannot be written.
func GetOrGenerateSetupToken(path string) string {
	clean, err := safepath.CleanAbs(path)
	if err != nil {
		slog.Error("setup token path invalid", "error", err)
		return ""
	}

	if existing := ReadSetupToken(clean); len(existing) == tokenHexLength {
		return existing
	}

	raw := make([]byte, 32)
	if _, rerr := rand.Read(raw); rerr != nil {
		slog.Error("generate setup token", "error", rerr)
		return ""
	}
	token := hex.EncodeToString(raw)
	if werr := os.WriteFile(clean, []byte(token), 0o600); werr != nil {
		slog.Error("write setup token", "error", werr, "path", clean)
		return ""
	}
	return token
}

// ReadSetupToken reads the current token without generating one; "" when the
// file is absent or unreadable.
func ReadSetupToken(path string) string {
	clean, err := safepath.CleanAbs(path)
	if err != nil {
		return ""
	}
	raw, err := os.ReadFile(filepath.Clean(clean))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// VerifySetupToken constant-time-compares a supplied token against the stored
// one. False unless a stored token exists and matches exactly.
func VerifySetupToken(path, supplied string) bool {
	stored := ReadSetupToken(path)
	if stored == "" || len(supplied) != len(stored) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(supplied), []byte(stored)) == 1
}
