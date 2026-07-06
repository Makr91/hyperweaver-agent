// Package keys implements the agent's API-key store: bcrypt-hashed keys with
// the Agent API v1 direct-mode role model (admin | operator | viewer). Keys
// persist as a JSON file beside the config (SQLite can take over when later
// milestones need a database); the wire behavior mirrors the Node agent's
// entities table.
package keys

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// ValidRoles is the Agent API v1 role vocabulary.
var ValidRoles = []string{"admin", "operator", "viewer"}

// ErrNotFound is returned when no key has the requested id.
var ErrNotFound = errors.New("api key not found")

// ErrLastAdmin is returned when deleting/revoking would remove the last
// active admin key (lockout guard).
var ErrLastAdmin = errors.New("last active admin key")

// bcrypt only reads the first 72 bytes of input. The Node agent's bcrypt
// silently truncates there; Go's errors instead — so both hashing and
// verification explicitly truncate to stay hash-compatible with keys and
// hashes produced by the Node agent.
const bcryptMaxLen = 72

// Key is one API-key entity. JSON field names match the Node agent's
// entities columns so API payloads serialize identically.
type Key struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	APIKeyHash  string    `json:"api_key_hash"`
	Description string    `json:"description"`
	Role        string    `json:"role"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsed    time.Time `json:"last_used"`
}

// Store is a mutex-guarded, file-backed key store.
type Store struct {
	mu   sync.Mutex
	path string
	data storeFile

	// lastUsed writes are throttled: bumps always land in memory, but only
	// persist when another mutation happens or the interval elapses.
	lastUsedFlush time.Time

	// verified caches SHA-256 digests of key material that has already
	// passed a bcrypt comparison this process lifetime, mapped to the entity
	// id. Without it every request pays a full bcrypt scan over all active
	// keys (~250ms per key at cost 12) — with a UI polling several endpoints
	// and one tray-minted key per desktop Open, that compounds into
	// multi-second request latency. Digests exist only in process memory;
	// bcrypt hashes remain the sole persistent form. Entries are dropped on
	// revoke/delete.
	verified map[[sha256.Size]byte]int64
}

type storeFile struct {
	NextID int64  `json:"next_id"`
	Keys   []*Key `json:"keys"`
}

const lastUsedFlushInterval = time.Minute

// Open loads (or initializes) the store at path.
func Open(path string) (*Store, error) {
	clean, err := safepath.CleanAbs(path)
	if err != nil {
		return nil, err
	}
	s := &Store{
		path:     clean,
		data:     storeFile{NextID: 1},
		verified: map[[sha256.Size]byte]int64{},
	}

	raw, err := os.ReadFile(filepath.Clean(clean))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read key store %s: %w", clean, err)
	}
	if uerr := json.Unmarshal(raw, &s.data); uerr != nil {
		return nil, fmt.Errorf("parse key store %s: %w", clean, uerr)
	}
	if s.data.NextID < 1 {
		s.data.NextID = 1
	}
	return s, nil
}

// persist writes the store through safepath.WriteFile (the agent's one
// write path), 0600. Callers must hold s.mu.
func (s *Store) persist() error {
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	if err := safepath.WriteFile(s.path, raw, 0o600); err != nil {
		return err
	}
	s.lastUsedFlush = time.Now()
	return nil
}

func truncateForBcrypt(key string) []byte {
	b := []byte(key)
	if len(b) > bcryptMaxLen {
		b = b[:bcryptMaxLen]
	}
	return b
}

// GenerateKeyString mints new key material: hw_ + base64url(randomBytes).
// The prefix is a human label only — verification compares the whole string.
func GenerateKeyString(keyLength int) (string, error) {
	raw := make([]byte, keyLength)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "hw_" + base64.RawURLEncoding.EncodeToString(raw), nil
}

// Create hashes apiKey and stores a new entity.
func (s *Store) Create(apiKey, name, description, role string, hashRounds int) (*Key, error) {
	hash, err := bcrypt.GenerateFromPassword(truncateForBcrypt(apiKey), hashRounds)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	k := &Key{
		ID:          s.data.NextID,
		Name:        name,
		APIKeyHash:  string(hash),
		Description: description,
		Role:        role,
		IsActive:    true,
		CreatedAt:   now,
		LastUsed:    now,
	}
	s.data.NextID++
	s.data.Keys = append(s.data.Keys, k)

	if err := s.persist(); err != nil {
		// Roll back the in-memory append so state matches disk.
		s.data.Keys = s.data.Keys[:len(s.data.Keys)-1]
		s.data.NextID--
		return nil, err
	}
	return k.clone(), nil
}

// Verify authenticates apiKey: a constant-time cache lookup for key material
// that has already proven itself this process lifetime, else a bcrypt
// comparison against every active key (Node-agent semantics). The bcrypt
// scan runs OUTSIDE the store mutex — at cost 12 each comparison takes
// ~250ms, and holding the lock through a scan would serialize every request
// in the process (including the public /status probe, which counts keys)
// behind it. Returns the matching key or nil. lastUsed is bumped in memory
// on every hit and flushed to disk at most once per interval.
func (s *Store) Verify(apiKey string) (*Key, error) {
	candidate := truncateForBcrypt(apiKey)
	digest := sha256.Sum256(candidate)

	s.mu.Lock()
	if id, hit := s.verified[digest]; hit {
		k := s.find(id)
		if k != nil && k.IsActive {
			match, err := s.recordUse(k)
			s.mu.Unlock()
			return match, err
		}
		delete(s.verified, digest)
	}
	// Snapshot the active keys so the bcrypt scan runs unlocked.
	active := make([]*Key, 0, len(s.data.Keys))
	for _, k := range s.data.Keys {
		if k.IsActive {
			active = append(active, k.clone())
		}
	}
	s.mu.Unlock()

	for _, k := range active {
		if bcrypt.CompareHashAndPassword([]byte(k.APIKeyHash), candidate) != nil {
			continue
		}
		s.mu.Lock()
		live := s.find(k.ID)
		if live == nil || !live.IsActive {
			// Deleted or revoked while the scan ran — the answer is no.
			s.mu.Unlock()
			return nil, nil
		}
		s.verified[digest] = live.ID
		match, err := s.recordUse(live)
		s.mu.Unlock()
		return match, err
	}
	return nil, nil
}

// recordUse bumps a key's lastUsed (throttled persistence) and returns its
// clone. Callers must hold s.mu.
func (s *Store) recordUse(k *Key) (*Key, error) {
	k.LastUsed = time.Now()
	if time.Since(s.lastUsedFlush) > lastUsedFlushInterval {
		if err := s.persist(); err != nil {
			return nil, err
		}
	}
	return k.clone(), nil
}

// List returns all keys, newest first.
func (s *Store) List() []*Key {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]*Key, 0, len(s.data.Keys))
	for i := len(s.data.Keys) - 1; i >= 0; i-- {
		out = append(out, s.data.Keys[i].clone())
	}
	return out
}

// Get returns the key with the given id.
func (s *Store) Get(id int64) (*Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := s.find(id)
	if k == nil {
		return nil, ErrNotFound
	}
	return k.clone(), nil
}

// Count returns the total number of keys (active or not) — the bootstrap
// availability check, mirroring the Node agent's Entities.count().
func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.data.Keys)
}

// Delete permanently removes a key, refusing to remove the last active admin.
func (s *Store) Delete(id int64) (*Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := s.find(id)
	if k == nil {
		return nil, ErrNotFound
	}
	if s.isLastActiveAdmin(k) {
		return nil, ErrLastAdmin
	}

	kept := s.data.Keys[:0]
	for _, other := range s.data.Keys {
		if other.ID != id {
			kept = append(kept, other)
		}
	}
	s.data.Keys = kept
	s.dropVerified(id)

	if err := s.persist(); err != nil {
		return nil, err
	}
	return k.clone(), nil
}

// Revoke deactivates a key, refusing to deactivate the last active admin.
func (s *Store) Revoke(id int64) (*Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := s.find(id)
	if k == nil {
		return nil, ErrNotFound
	}
	if s.isLastActiveAdmin(k) {
		return nil, ErrLastAdmin
	}

	k.IsActive = false
	s.dropVerified(id)
	if err := s.persist(); err != nil {
		k.IsActive = true
		return nil, err
	}
	return k.clone(), nil
}

// dropVerified removes any cached verification for a key id (revocation and
// deletion must take effect immediately). Callers must hold s.mu.
func (s *Store) dropVerified(id int64) {
	for digest, cachedID := range s.verified {
		if cachedID == id {
			delete(s.verified, digest)
		}
	}
}

// find returns the live (unclones) key with id. Callers must hold s.mu.
func (s *Store) find(id int64) *Key {
	for _, k := range s.data.Keys {
		if k.ID == id {
			return k
		}
	}
	return nil
}

// isLastActiveAdmin reports whether k is the only active admin key (lockout
// guard). Callers must hold s.mu.
func (s *Store) isLastActiveAdmin(k *Key) bool {
	if k.Role != "admin" || !k.IsActive {
		return false
	}
	for _, other := range s.data.Keys {
		if other.ID != k.ID && other.IsActive && other.Role == "admin" {
			return false
		}
	}
	return true
}

func (k *Key) clone() *Key {
	c := *k
	return &c
}

// RoleValid reports whether role is part of the v1 vocabulary.
func RoleValid(role string) bool {
	for _, r := range ValidRoles {
		if r == role {
			return true
		}
	}
	return false
}
