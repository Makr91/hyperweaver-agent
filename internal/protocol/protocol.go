// Package protocol implements the agent's hwa:// custom URL scheme: parsing
// and validating incoming protocol invocations, and the single-instance
// handoff that forwards an invocation from a freshly spawned process to the
// agent already running for this user.
//
// The handoff is authenticated by a per-boot secret file (0600, beside the
// config): a web page cannot read local files, so possession of the secret
// proves the caller is a local process running as the same user — the same
// trust a physical tray click carries. Incoming URIs are untrusted input and
// are validated against a small closed action vocabulary.
package protocol

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// Scheme is the agent's registered custom URL scheme (architecture item 5:
// our own scheme, deliberately not SwitchBoard's swb://).
const Scheme = "hwa"

// ActionOpen is the only action in the vocabulary today: behave exactly like
// the tray "Open" click (mint a one-time token, open the signed-in UI).
const ActionOpen = "open"

// ErrRejected reports that a running agent answered the handoff and refused
// it (bad or stale secret) — not that no agent was reachable.
var ErrRejected = errors.New("running agent rejected the protocol handoff")

// The secret file holds 32 random bytes as hex, rewritten on every boot.
const secretHexLength = 64

// forwardTimeout bounds the whole handoff attempt; the target is loopback.
const forwardTimeout = 3 * time.Second

// URIFromArgs returns the first hwa:// URI among the positional command-line
// arguments — how the OS hands an invocation to a newly spawned process on
// Windows (registry command "%1") and Linux (.desktop Exec %u).
func URIFromArgs(args []string) (string, bool) {
	for _, arg := range args {
		if strings.HasPrefix(strings.ToLower(arg), Scheme+"://") {
			return arg, true
		}
	}
	return "", false
}

// ParseAction validates an incoming protocol URI (untrusted input) against
// the closed action vocabulary and returns the action.
func ParseAction(uri string) (string, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("invalid protocol URI: %w", err)
	}
	if !strings.EqualFold(parsed.Scheme, Scheme) {
		return "", fmt.Errorf("unsupported scheme %q", parsed.Scheme)
	}
	action := strings.ToLower(parsed.Host)
	if action != ActionOpen {
		return "", fmt.Errorf("unsupported protocol action %q", parsed.Host)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", fmt.Errorf("unsupported protocol path %q", parsed.Path)
	}
	return action, nil
}

// WriteSecret generates and persists a fresh handoff secret, replacing any
// previous one — called once per agent boot so a secret never outlives the
// process that minted it.
func WriteSecret(path string) error {
	clean, err := safepath.CleanAbs(path)
	if err != nil {
		return err
	}
	raw := make([]byte, 32)
	if _, rerr := rand.Read(raw); rerr != nil {
		return rerr
	}
	return os.WriteFile(clean, []byte(hex.EncodeToString(raw)), 0o600)
}

// ReadSecret reads the running agent's current handoff secret. The error
// distinguishes the caller's cases: fs.ErrNotExist means no agent has booted
// for this user (cold start is appropriate); a permission error means an
// agent runs as a different user (its secret is 0600).
func ReadSecret(path string) (string, error) {
	clean, err := safepath.CleanAbs(path)
	if err != nil {
		return "", err
	}
	raw, err := os.ReadFile(filepath.Clean(clean))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

// VerifySecret constant-time-compares a supplied secret against the stored
// one. False unless a stored secret exists and matches exactly.
func VerifySecret(path, supplied string) bool {
	stored, err := ReadSecret(path)
	if err != nil || len(stored) != secretHexLength || len(supplied) != len(stored) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(supplied), []byte(stored)) == 1
}

// Forward delivers an action to the agent already running at baseURL,
// authenticated by the handoff secret. A transport-level failure (nothing
// listening) is returned as-is; an HTTP rejection wraps ErrRejected so the
// caller can tell "no agent" from "an agent said no".
func Forward(ctx context.Context, baseURL, action, secret string) error {
	reqCtx, cancel := context.WithTimeout(ctx, forwardTimeout)
	defer cancel()

	body, err := json.Marshal(map[string]string{"secret": secret})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost,
		baseURL+"/protocol/"+action, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s", ErrRejected, resp.Status)
	}
	return nil
}
