package locations

import (
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

type Kind string

const (
	Machines     Kind = "machines"
	Provisioners Kind = "provisioners"
	Templates    Kind = "templates"
)

const BuiltinID = "builtin"

type Location struct {
	ID          string `json:"id"`
	Type        Kind   `json:"type"`
	DisplayName string `json:"display_name"`
	Path        string `json:"path"`
	Enabled     bool   `json:"enabled"`
	Default     bool   `json:"default"`
	Builtin     bool   `json:"builtin"`
}

type Set struct {
	mu     sync.RWMutex
	byKind map[Kind][]Location
}

func New() *Set {
	return &Set{byKind: map[Kind][]Location{}}
}

func ValidKind(value string) bool {
	switch Kind(value) {
	case Machines, Provisioners, Templates:
		return true
	default:
		return false
	}
}

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

func (s *Set) Replace(kind Kind, list []Location) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byKind[kind] = normalize(kind, list)
}

func (s *Set) List(kind Kind) []Location {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Location(nil), s.byKind[kind]...)
}

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

func (s *Set) DefaultPath(kind Kind) string {
	location, ok := s.Default(kind)
	if !ok {
		return ""
	}
	return location.Path
}

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
