// Package prefs stores the preferences of each person who signs in to the agent, keyed by the account the key was minted for.
package prefs

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	_ "time/tzdata"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// Members are the preference names of the branding contract's write path.
var Members = []string{"language", "mode", "theme", "motion", "timezone"}

// Preferences is one person's stored values; a nil member is unset.
type Preferences struct {
	Language *string `json:"language"`
	Mode     *string `json:"mode"`
	Theme    *string `json:"theme"`
	Motion   *string `json:"motion"`
	Timezone *string `json:"timezone"`
}

// Store is the mutex-guarded, file-backed preference store, one record per person.
type Store struct {
	mu   sync.Mutex
	path string
	data map[string]map[string]string
}

// Open loads the store at path, an absent file being an empty store.
func Open(path string) (*Store, error) {
	clean, err := safepath.CleanAbs(path)
	if err != nil {
		return nil, err
	}
	s := &Store{path: clean, data: map[string]map[string]string{}}
	raw, err := os.ReadFile(filepath.Clean(clean))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if uerr := json.Unmarshal(raw, &s.data); uerr != nil {
		return nil, uerr
	}
	if s.data == nil {
		s.data = map[string]map[string]string{}
	}
	return s, nil
}

func view(record map[string]string) Preferences {
	pick := func(name string) *string {
		if value, ok := record[name]; ok {
			return &value
		}
		return nil
	}
	return Preferences{
		Language: pick("language"),
		Mode:     pick("mode"),
		Theme:    pick("theme"),
		Motion:   pick("motion"),
		Timezone: pick("timezone"),
	}
}

// Get answers the person's preferences, every member nil when none is stored.
func (s *Store) Get(person string) Preferences {
	s.mu.Lock()
	defer s.mu.Unlock()
	return view(s.data[person])
}

// Apply writes the patch, a nil value clearing the member, and reports whether any stored value changed.
func (s *Store) Apply(person string, patch map[string]*string) (Preferences, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record := s.data[person]
	if record == nil {
		record = map[string]string{}
	}
	changed := false
	for name, value := range patch {
		current, stored := record[name]
		switch {
		case value == nil && stored:
			delete(record, name)
			changed = true
		case value != nil && (!stored || current != *value):
			record[name] = *value
			changed = true
		}
	}
	if !changed {
		return view(record), false, nil
	}
	if len(record) == 0 {
		delete(s.data, person)
	} else {
		s.data[person] = record
	}
	if err := s.persist(); err != nil {
		return Preferences{}, false, err
	}
	return view(record), true, nil
}

func (s *Store) persist() error {
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	return safepath.WriteFile(s.path, raw, 0o600)
}
