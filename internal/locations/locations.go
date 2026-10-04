// Package locations holds the storage paths of machines, provisioners and templates: any number per kind, exactly one default, each item keeping the path it was made in.
package locations

import (
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// Kind names what a storage path holds.
type Kind string

// The three kinds of storage path.
const (
	Machines     Kind = "machines"
	Provisioners Kind = "provisioners"
	Templates    Kind = "templates"
)

// BuiltinID is the id of the one path per kind the configuration's root setting names.
const BuiltinID = "builtin"

// Location is one storage path as the API answers it.
type Location struct {
	ID          string `json:"id"`
	Type        Kind   `json:"type"`
	DisplayName string `json:"display_name"`
	Path        string `json:"path"`
	Enabled     bool   `json:"enabled"`
	Default     bool   `json:"default"`
	Builtin     bool   `json:"builtin"`
}

// Set is the live table of storage paths of every kind, safe for concurrent readers.
type Set struct {
	mu     sync.RWMutex
	byKind map[Kind][]Location
}

// New builds an empty set.
func New() *Set {
	return &Set{byKind: map[Kind][]Location{}}
}

// ValidKind reports whether value names one of the three kinds.
func ValidKind(value string) bool {
	switch Kind(value) {
	case Machines, Provisioners, Templates:
		return true
	default:
		return false
	}
}

// SamePath reports whether two paths name the same folder, case-insensitively on Windows.
func SamePath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func within(root, path string) bool {
	root, path = filepath.Clean(root), filepath.Clean(path)
	if runtime.GOOS == "windows" {
		root, path = strings.ToLower(root), strings.ToLower(path)
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func normalize(kind Kind, list []Location) []Location {
	out := make([]Location, len(list))
	chosen := -1
	builtin := -1
	for i := range list {
		out[i] = list[i]
		out[i].Type = kind
		out[i].Default = false
		if out[i].Builtin {
			builtin = i
		}
		if list[i].Default && list[i].Enabled && chosen < 0 {
			chosen = i
		}
	}
	if chosen < 0 {
		chosen = builtin
	}
	if chosen >= 0 {
		out[chosen].Default = true
	}
	return out
}

// Replace swaps in the paths of one kind, leaving exactly one enabled default, the built-in path when none is marked.
func (s *Set) Replace(kind Kind, list []Location) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byKind[kind] = normalize(kind, list)
}

// List answers a copy of every path of a kind.
func (s *Set) List(kind Kind) []Location {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Location(nil), s.byKind[kind]...)
}

// Enabled answers the enabled paths of a kind.
func (s *Set) Enabled(kind Kind) []Location {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Location, 0, len(s.byKind[kind]))
	for i := range s.byKind[kind] {
		if s.byKind[kind][i].Enabled {
			out = append(out, s.byKind[kind][i])
		}
	}
	return out
}

// Get answers the path of a kind with the given id.
func (s *Set) Get(kind Kind, id string) (Location, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.byKind[kind] {
		if s.byKind[kind][i].ID == id {
			return s.byKind[kind][i], true
		}
	}
	return Location{}, false
}

// Default answers the path new items of a kind land in.
func (s *Set) Default(kind Kind) (Location, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.byKind[kind] {
		if s.byKind[kind][i].Default {
			return s.byKind[kind][i], true
		}
	}
	return Location{}, false
}

// DefaultPath answers the folder of the default path of a kind, empty when the kind has none.
func (s *Set) DefaultPath(kind Kind) string {
	location, ok := s.Default(kind)
	if !ok {
		return ""
	}
	return location.Path
}

// Containing answers the deepest path of a kind that holds the given folder.
func (s *Set) Containing(kind Kind, path string) (Location, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	found := -1
	for i := range s.byKind[kind] {
		if !within(s.byKind[kind][i].Path, path) {
			continue
		}
		if found < 0 || len(s.byKind[kind][i].Path) > len(s.byKind[kind][found].Path) {
			found = i
		}
	}
	if found < 0 {
		return Location{}, false
	}
	return s.byKind[kind][found], true
}
