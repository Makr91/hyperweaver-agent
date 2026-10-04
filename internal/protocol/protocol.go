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
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

var schemes = []string{"hwa", "hyperweaver-agent", "com.startcloud.hyperweaver-agent"}

func knownScheme(name string) bool {
	for _, scheme := range schemes {
		if strings.EqualFold(name, scheme) {
			return true
		}
	}
	return false
}

// ActionOpen is the only action in the vocabulary today: behave exactly like
// the tray "Open" click (mint a one-time token, open the signed-in UI).
const ActionOpen = "open"

// ActionHandoff is the restart handoff: the successor asks the running agent to release the port and databases.
const ActionHandoff = "handoff"

// ErrRejected reports that a running agent answered the handoff and refused
// it (bad or stale secret) — not that no agent was reachable.
var ErrRejected = errors.New("running agent rejected the protocol handoff")

// The secret file holds 32 random bytes as hex, rewritten on every boot.
const secretHexLength = 64

const maxQueryLength = 2048

var queryKeys = map[string]bool{
	"create":              true,
	"box":                 true,
	"box_version":         true,
	"box_arch":            true,
	"box_url":             true,
	"provisioner":         true,
	"provisioner_version": true,
	"provisioner_url":     true,
}

// forwardTimeout bounds the whole handoff attempt; the target is loopback.
const forwardTimeout = 3 * time.Second

// URIFromArgs returns the first hwa:// URI among the positional command-line
// arguments — how the OS hands an invocation to a newly spawned process on
// Windows (registry command "%1") and Linux (.desktop Exec %u).
func URIFromArgs(args []string) (string, bool) {
	for _, arg := range args {
		lowered := strings.ToLower(arg)
		for _, scheme := range schemes {
			if strings.HasPrefix(lowered, scheme+"://") {
				return arg, true
			}
		}
	}
	return "", false
}

// ParseAction validates an incoming protocol URI (untrusted input) against
// the closed action vocabulary and returns the action and its raw query.
func ParseAction(uri string) (action, query string, err error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return "", "", fmt.Errorf("invalid protocol URI: %w", err)
	}
	if !knownScheme(parsed.Scheme) {
		return "", "", fmt.Errorf("unsupported scheme %q", parsed.Scheme)
	}
	if parsed.User != nil || parsed.Port() != "" || parsed.Fragment != "" {
		return "", "", errors.New("protocol URI carries userinfo, a port or a fragment")
	}
	action = strings.ToLower(parsed.Hostname())
	if action != ActionOpen {
		return "", "", fmt.Errorf("unsupported protocol action %q", parsed.Host)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", "", fmt.Errorf("unsupported protocol path %q", parsed.Path)
	}
	if verr := ValidateQuery(parsed.RawQuery); verr != nil {
		return "", "", verr
	}
	return action, parsed.RawQuery, nil
}

// ValidateQuery refuses a query longer than 2048 bytes, one with a key outside the deploy vocabulary, or one whose create is not machine.
func ValidateQuery(raw string) error {
	if raw == "" {
		return nil
	}
	if len(raw) > maxQueryLength {
		return errors.New("protocol query too long")
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return fmt.Errorf("invalid protocol query: %w", err)
	}
	for key, entries := range values {
		if !queryKeys[key] {
			return fmt.Errorf("unsupported protocol query key %q", key)
		}
		if len(entries) != 1 {
			return fmt.Errorf("protocol query key %q given more than once", key)
		}
	}
	if values.Has("create") && values.Get("create") != "machine" {
		return fmt.Errorf("unsupported protocol create %q", values.Get("create"))
	}
	return nil
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
	return safepath.WriteFile(clean, []byte(hex.EncodeToString(raw)), 0o600)
}

// ReadSecret reads the running agent's current handoff secret. The error
// distinguishes the caller's cases: fs.ErrNotExist means no agent has booted
// for this user (cold start is appropriate); a permission error means an
// agent runs as a different user (its secret is 0600).
func ReadSecret(path string) (string, error) {
	raw, err := safepath.ReadFile(path)
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
// authenticated by the handoff secret. client is the loopback self-client
// (it trusts the running agent's own certificate when TLS is on). A
// transport-level failure (nothing listening) is returned as-is; an HTTP
// rejection wraps ErrRejected so the caller can tell "no agent" from "an
// agent said no".
func Forward(ctx context.Context, client *http.Client, baseURL, action, secret, query string) error {
	reqCtx, cancel := context.WithTimeout(ctx, forwardTimeout)
	defer cancel()
	return post(reqCtx, client, baseURL, action, secret, query)
}

// AwaitRelease asks the running agent to hand over its port and databases and returns once it has, with no deadline; ErrRejected means no restart is pending there.
func AwaitRelease(ctx context.Context, client *http.Client, baseURL, secret string) error {
	return post(ctx, client, baseURL, ActionHandoff, secret, "")
}

func post(ctx context.Context, client *http.Client, baseURL, action, secret, query string) error {
	payload := map[string]string{"secret": secret}
	if query != "" {
		payload["query"] = query
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		baseURL+"/api/protocol/"+action, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
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
