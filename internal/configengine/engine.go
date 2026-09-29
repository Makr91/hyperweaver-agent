package configengine

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/Makr91/hyperweaver-agent/internal/problem"
	"github.com/Makr91/hyperweaver-agent/internal/validation"
)

const setupTokenFile = "setup.token"

// Hook answers the failing rules of one leaf the schema cannot express.
type Hook func(pointer string, value any, name string, document map[string]any, configDir string) []problem.Error

// Hooks are the backend's own rules and its after-write function.
type Hooks struct {
	Writable      Hook
	Reachable     Hook
	OnSaved       func(name, actor string, status RestartStatus)
	SetupComplete func() bool
}

// RestartEntry is one changed leaf that needs a restart.
type RestartEntry struct {
	Pointer string `json:"pointer"`
	Title   string `json:"title"`
	Reason  string `json:"reason"`
}

// RestartStatus is the pending restart list with its last writer.
type RestartStatus struct {
	RestartRequired  bool           `json:"restart_required"`
	RequiresRestart  []RestartEntry `json:"requires_restart"`
	LastModifiedBy   *string        `json:"last_modified_by"`
	LastModifiedTime *string        `json:"last_modified_time"`
}

// ValidationError carries the failing rules of a refused save.
type ValidationError struct {
	Errors []problem.Error
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("configuration failed validation (%d error(s))", len(e.Errors))
}

// Engine holds every configuration file of one backend.
type Engine struct {
	mu               sync.RWMutex
	configDir        string
	names            []string
	schemaFS         fs.FS
	hooks            Hooks
	schemas          map[string]validation.Schema
	raw              map[string]map[string]any
	filled           map[string]map[string]any
	pending          map[string]RestartEntry
	lastModifiedBy   *string
	lastModifiedTime *string
	serviceUser      string
	auth             Auth
	exit             func()
	uploadLimit      int64
}

// New builds an engine over configDir for the code-fixed names, reading schemas from schemaFS.
func New(configDir string, names []string, schemaFS fs.FS, hooks Hooks) *Engine {
	return &Engine{
		configDir: configDir,
		names:     append([]string{}, names...),
		schemaFS:  schemaFS,
		hooks:     hooks,
		schemas:   map[string]validation.Schema{},
		raw:       map[string]map[string]any{},
		filled:    map[string]map[string]any{},
		pending:   map[string]RestartEntry{},
	}
}

// Dir answers the configuration directory.
func (e *Engine) Dir() string {
	return e.configDir
}

// Names answers the code-fixed list of file names.
func (e *Engine) Names() []string {
	return append([]string{}, e.names...)
}

func (e *Engine) known(name string) bool {
	for _, n := range e.names {
		if n == name {
			return true
		}
	}
	return false
}

func (e *Engine) filePath(name string) string {
	return filepath.Join(e.configDir, name+".config.yaml")
}

func (e *Engine) setupTokenPath() string {
	return filepath.Join(e.configDir, setupTokenFile)
}

func (e *Engine) readSchema(name string) (validation.Schema, error) {
	raw, err := fs.ReadFile(e.schemaFS, name+".schema.yaml")
	if err != nil {
		return nil, err
	}
	schema := map[string]any{}
	if uerr := yaml.Unmarshal(raw, &schema); uerr != nil {
		return nil, uerr
	}
	return normalize(schema).(map[string]any), nil
}

func (e *Engine) readRaw(name string) (map[string]any, *problem.Error) {
	raw, err := os.ReadFile(e.filePath(name))
	if err != nil {
		return nil, &problem.Error{Pointer: "", Rule: "yaml", Params: map[string]any{"message": err.Error()}}
	}
	var parsed any
	if uerr := yaml.Unmarshal(raw, &parsed); uerr != nil {
		return nil, &problem.Error{Pointer: "", Rule: "yaml", Params: map[string]any{"message": uerr.Error()}}
	}
	if parsed == nil {
		return map[string]any{}, nil
	}
	object, ok := parsed.(map[string]any)
	if !ok {
		return nil, &problem.Error{Pointer: "", Rule: "type", Params: map[string]any{"type": "object"}}
	}
	return normalize(object).(map[string]any), nil
}

func logRefusal(name string, e problem.Error) {
	slog.Error("configuration value failed its schema", "category", "app", "config", name,
		"pointer", e.Pointer, "rule", e.Rule, "params", e.Params)
}

func (e *Engine) hookErrors(name string, document, scope map[string]any, hooks Hooks) []problem.Error {
	errs := []problem.Error{}
	for _, leaf := range leaves(scope, "") {
		if leaf.value == nil {
			continue
		}
		value := valueAt(document, leaf.pointer)
		if hooks.Writable != nil {
			errs = append(errs, hooks.Writable(leaf.pointer, value, name, document, e.configDir)...)
		}
		if hooks.Reachable != nil {
			errs = append(errs, hooks.Reachable(leaf.pointer, value, name, document, e.configDir)...)
		}
	}
	return errs
}

func (e *Engine) loadOne(name string) bool {
	schema, err := e.readSchema(name)
	if err != nil {
		slog.Error("configuration schema could not be read", "category", "app", "config", name, "error", err)
		return false
	}
	e.schemas[name] = schema
	raw, perr := e.readRaw(name)
	if perr != nil {
		logRefusal(name, *perr)
		return false
	}
	filled := fillDefaults(schema, raw)
	errs := validation.Object(schema, filled, schema)
	errs = append(errs, e.hookErrors(name, filled, filled, Hooks{Writable: e.hooks.Writable})...)
	for _, pointer := range flaggedWithoutReason(schema, "") {
		errs = append(errs, problem.Error{Pointer: pointer, Rule: "restartReason", Params: map[string]any{}})
	}
	for _, pointer := range unknownKeys(schema, raw, "") {
		slog.Warn("unknown configuration key", "category", "app", "config", name, "pointer", pointer)
	}
	for _, failure := range errs {
		logRefusal(name, failure)
	}
	if len(errs) > 0 {
		return false
	}
	e.raw[name] = raw
	e.filled[name] = filled
	return true
}

// Load reads every file in list order, fills defaults in memory and evaluates each; any failure is an error after every pointer was logged.
func (e *Engine) Load() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	ok := true
	for _, name := range e.names {
		if !e.loadOne(name) {
			ok = false
		}
	}
	if !ok {
		return errors.New("configuration failed to load; every failing pointer is in the log")
	}
	e.fillSetupToken()
	return nil
}

// Get answers a copy of the filled document of one file.
func (e *Engine) Get(name string) map[string]any {
	e.mu.RLock()
	defer e.mu.RUnlock()
	copied, _ := clone(e.filled[name]).(map[string]any)
	return copied
}

// GetAt answers a copy of the value at an RFC 6901 pointer of the filled document.
func (e *Engine) GetAt(name, pointer string) any {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return clone(valueAt(e.filled[name], pointer))
}

// Raw answers a copy of the file as parsed, nothing filled.
func (e *Engine) Raw(name string) map[string]any {
	e.mu.RLock()
	defer e.mu.RUnlock()
	copied, _ := clone(e.raw[name]).(map[string]any)
	return copied
}

// Schema answers the schema document of one file.
func (e *Engine) Schema(name string) validation.Schema {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.schemas[name]
}

// SetOnSaved attaches the after-write function; it runs after every save and restore with the pending restart list, outside no lock, so it must not call the engine.
func (e *Engine) SetOnSaved(fn func(name, actor string, status RestartStatus)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.hooks.OnSaved = fn
}

// RestartPending answers the union of every write's restart list since the last restart.
func (e *Engine) RestartPending() RestartStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.pendingStatus()
}

func (e *Engine) pendingStatus() RestartStatus {
	list := make([]RestartEntry, 0, len(e.pending))
	for _, entry := range e.pending {
		list = append(list, entry)
	}
	sortEntries(list)
	return RestartStatus{
		RestartRequired:  len(list) > 0,
		RequiresRestart:  list,
		LastModifiedBy:   e.lastModifiedBy,
		LastModifiedTime: e.lastModifiedTime,
	}
}

// ClearRestart forgets the pending restart list.
func (e *Engine) ClearRestart() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pending = map[string]RestartEntry{}
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339)
}
