package configengine

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/Makr91/hyperweaver-agent/internal/problem"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
	"github.com/Makr91/hyperweaver-agent/internal/validation"
)

type prepared struct {
	name   string
	merged map[string]any
	filled map[string]any
	errors []problem.Error
}

func (e *Engine) prepare(name string, body map[string]any) prepared {
	schema := e.schemas[name]
	merged, _ := mergePatch(e.raw[name], body).(map[string]any)
	filled := fillDefaults(schema, merged)
	errs := []problem.Error{}
	for _, pointer := range readOnlyPointers(schema, body, "") {
		errs = append(errs, problem.Error{Pointer: pointer, Rule: "readOnly", Params: map[string]any{}})
	}
	errs = append(errs, validation.Object(schema, filled, schema)...)
	errs = append(errs, e.hookErrors(name, filled, body, e.hooks)...)
	return prepared{name: name, merged: merged, filled: filled, errors: errs}
}

func (e *Engine) writeFile(name string, merged map[string]any) error {
	target := e.filePath(name)
	if current, err := os.ReadFile(target); err == nil {
		if werr := safepath.WriteFile(target+".bak", current, 0o600); werr != nil {
			return werr
		}
	}
	raw, err := yaml.Marshal(merged)
	if err != nil {
		return err
	}
	return safepath.WriteFile(target, raw, 0o600)
}

func (e *Engine) commit(p prepared, actor string) ([]RestartEntry, error) {
	diff := restartDiff(e.schemas[p.name], e.filled[p.name], p.filled, "")
	if err := e.writeFile(p.name, p.merged); err != nil {
		return nil, err
	}
	e.raw[p.name] = p.merged
	e.filled[p.name] = p.filled
	for _, entry := range diff {
		e.pending[entry.Pointer] = entry
	}
	who := actor
	when := now()
	e.lastModifiedBy = &who
	e.lastModifiedTime = &when
	if e.hooks.OnSaved != nil {
		e.hooks.OnSaved(p.name, actor)
	}
	return diff, nil
}

// Save applies a JSON Merge Patch to one file: validate, write atomically with a .bak, replace the cache, record the restart diff.
func (e *Engine) Save(name string, body map[string]any, actor string) ([]RestartEntry, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.known(name) {
		return nil, errors.New("unknown configuration name " + name)
	}
	p := e.prepare(name, body)
	if len(p.errors) > 0 {
		return nil, &ValidationError{Errors: p.errors}
	}
	return e.commit(p, actor)
}

// SaveAll validates every patch before writing any, as PUT /api/setup does.
func (e *Engine) SaveAll(patches map[string]map[string]any, actor string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	list := []prepared{}
	errs := []problem.Error{}
	for _, name := range e.names {
		body, present := patches[name]
		if !present {
			continue
		}
		if body == nil {
			body = map[string]any{}
		}
		p := e.prepare(name, body)
		for _, failure := range p.errors {
			failure.Pointer = "/configs/" + name + failure.Pointer
			errs = append(errs, failure)
		}
		list = append(list, p)
	}
	if len(errs) > 0 {
		return &ValidationError{Errors: errs}
	}
	for _, p := range list {
		if _, err := e.commit(p, actor); err != nil {
			return err
		}
	}
	return nil
}

// Restore writes a whole raw document for one file after validating it, the backup-restore path.
func (e *Engine) Restore(name string, document map[string]any, actor string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.known(name) {
		return errors.New("unknown configuration name " + name)
	}
	schema := e.schemas[name]
	filled := fillDefaults(schema, document)
	errs := validation.Object(schema, filled, schema)
	errs = append(errs, e.hookErrors(name, filled, filled, e.hooks)...)
	if len(errs) > 0 {
		return &ValidationError{Errors: errs}
	}
	_, err := e.commit(prepared{name: name, merged: document, filled: filled}, actor)
	return err
}

// WithDeletions adds null for every map entry the raw file holds and the patch's full section omits.
func (e *Engine) WithDeletions(name string, body map[string]any) map[string]any {
	e.mu.RLock()
	defer e.mu.RUnlock()
	schema := e.schemas[name]
	raw := e.raw[name]
	out, _ := clone(body).(map[string]any)
	for key, value := range out {
		property, _ := propertiesOf(schema)[key].(map[string]any)
		section, _ := value.(map[string]any)
		rawSection, _ := raw[key].(map[string]any)
		if property == nil || section == nil {
			continue
		}
		out[key] = withMapDeletions(property, rawSection, section)
	}
	return out
}

func withMapDeletions(property validation.Schema, raw, patch map[string]any) map[string]any {
	if isMapSchema(property) {
		for key := range raw {
			if _, present := patch[key]; !present {
				patch[key] = nil
			}
		}
		return patch
	}
	for key, child := range propertiesOf(property) {
		childProperty, _ := child.(map[string]any)
		childPatch, _ := patch[key].(map[string]any)
		childRaw, _ := raw[key].(map[string]any)
		if childProperty == nil || childPatch == nil {
			continue
		}
		patch[key] = withMapDeletions(childProperty, childRaw, childPatch)
	}
	return patch
}

func (e *Engine) setupComplete() bool {
	if e.hooks.SetupComplete != nil {
		return e.hooks.SetupComplete()
	}
	_, err := os.Stat(e.setupTokenPath())
	return err != nil
}

// SetupComplete reports whether setup is complete.
func (e *Engine) SetupComplete() bool {
	return e.setupComplete()
}

func (e *Engine) fillSetupToken() {
	path := e.setupTokenPath()
	raw, err := os.ReadFile(path)
	if err != nil || strings.TrimSpace(string(raw)) != "" {
		return
	}
	token := make([]byte, 32)
	if _, rerr := rand.Read(token); rerr != nil {
		slog.Error("generate setup token", "error", rerr)
		return
	}
	if werr := safepath.WriteFile(path, []byte(hex.EncodeToString(token)), 0o600); werr != nil {
		slog.Error("write setup token", "error", werr, "path", path)
		return
	}
	slog.Info("setup token written", "category", "app", "path", path)
}

func (e *Engine) tokenMatches(token string) bool {
	if token == "" || e.setupComplete() {
		return false
	}
	raw, err := os.ReadFile(e.setupTokenPath())
	if err != nil {
		return false
	}
	stored := strings.TrimSpace(string(raw))
	return stored != "" && len(stored) == len(token) && subtle.ConstantTimeCompare([]byte(stored), []byte(token)) == 1
}

func (e *Engine) deleteSetupToken() {
	if err := os.Remove(e.setupTokenPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Error("delete setup token", "error", err)
	}
}

func (e *Engine) writeUpload(name, pointer string, content []byte) *problem.Error {
	writableFailure := &problem.Error{Pointer: pointer, Rule: "writable", Params: map[string]any{"user": e.serviceUser}}
	value, _ := e.GetAt(name, pointer).(string)
	if strings.TrimSpace(value) == "" {
		return writableFailure
	}
	root, err := filepath.EvalSymlinks(e.configDir)
	if err != nil {
		return writableFailure
	}
	target := value
	if !filepath.IsAbs(target) {
		target = filepath.Join(root, target)
	}
	target = filepath.Clean(target)
	if target != root && !strings.HasPrefix(target, root+string(filepath.Separator)) {
		return writableFailure
	}
	if merr := os.MkdirAll(filepath.Dir(target), 0o700); merr != nil {
		return writableFailure
	}
	if werr := safepath.WriteFile(target, content, 0o600); werr != nil {
		return writableFailure
	}
	return nil
}
