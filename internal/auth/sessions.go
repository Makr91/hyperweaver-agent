package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// SessionCookie is the browser session's cookie name.
const SessionCookie = "__Host-hwa_session"

type sessionEntry struct {
	KeyID     int64     `json:"key_id"`
	CreatedAt time.Time `json:"created_at"`
}

// Sessions maps browser session handles to the API keys they stand for, kept by digest in a 0600 file beside the configuration so a restart keeps every open tab signed in.
type Sessions struct {
	mu      sync.Mutex
	path    string
	entries map[string]sessionEntry
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func randomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// OpenSessions loads the session file at path, an absent file being no sessions.
func OpenSessions(path string) (*Sessions, error) {
	clean, err := safepath.CleanAbs(path)
	if err != nil {
		return nil, err
	}
	s := &Sessions{path: clean, entries: map[string]sessionEntry{}}
	raw, err := safepath.ReadFile(clean)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read session store %s: %w", clean, err)
	}
	if uerr := json.Unmarshal(raw, &s.entries); uerr != nil {
		return nil, fmt.Errorf("parse session store %s: %w", clean, uerr)
	}
	return s, nil
}

func (s *Sessions) persistLocked() error {
	raw, err := json.MarshalIndent(s.entries, "", "  ")
	if err != nil {
		return err
	}
	if merr := os.MkdirAll(filepath.Dir(s.path), 0o700); merr != nil {
		return merr
	}
	return safepath.WriteFile(s.path, raw, 0o600)
}

// Create opens a session for a key, dropping every session whose key alive no longer knows, and answers the handle.
func (s *Sessions) Create(keyID int64, alive func(id int64) bool) (string, error) {
	handle, err := randomToken()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, entry := range s.entries {
		if !alive(entry.KeyID) {
			delete(s.entries, key)
		}
	}
	s.entries[digest(handle)] = sessionEntry{KeyID: keyID, CreatedAt: time.Now().UTC()}
	if perr := s.persistLocked(); perr != nil {
		return "", perr
	}
	return handle, nil
}

// Key answers the key a session handle stands for.
func (s *Sessions) Key(handle string) (int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[digest(handle)]
	return entry.KeyID, ok
}

// End forgets a session handle.
func (s *Sessions) End(handle string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := digest(handle)
	if _, ok := s.entries[key]; !ok {
		return nil
	}
	delete(s.entries, key)
	return s.persistLocked()
}

// SetSessionCookie writes the session cookie on an answer.
func SetSessionCookie(w http.ResponseWriter, handle string) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: handle, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

// ClearSessionCookie expires the session cookie.
func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}
