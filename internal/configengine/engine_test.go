package configengine

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
)

const testSchema = `$schema: https://json-schema.org/draft/2020-12/schema
title: Test
schemaVersion: 1
sections:
  main:
    title: Main
    order: 1
properties:
  schemaVersion:
    type: integer
    readOnly: true
    default: 1
    title: Schema version
  server:
    type: object
    section: main
    properties:
      port:
        type: integer
        minimum: 1
        maximum: 65535
        default: 9420
        title: Port
        requiresRestart: true
        restartReason: the listener is bound at boot
      bind:
        type: string
        default: 127.0.0.1
        title: Bind
  logging:
    type: object
    section: main
    properties:
      categories:
        type: object
        additionalProperties:
          type: string
          enum: [error, warn, info, debug]
`

func newTestEngine(t *testing.T, file string) *Engine {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.config.yaml"), []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	schemas := fstest.MapFS{"app.schema.yaml": &fstest.MapFile{Data: []byte(testSchema)}}
	return New(dir, []string{"app"}, schemas, Hooks{})
}

func TestLoadFillsDefaultsInMemoryOnly(t *testing.T) {
	e := newTestEngine(t, "schemaVersion: 1\nserver:\n  bind: 0.0.0.0\n")
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	if got := e.GetAt("app", "/server/port"); got != int64(9420) {
		t.Fatalf("default not filled in memory: %v", got)
	}
	if _, present := e.Raw("app")["server"].(map[string]any)["port"]; present {
		t.Fatal("default reached the raw document")
	}
}

func TestLoadRefusesABadValue(t *testing.T) {
	e := newTestEngine(t, "schemaVersion: 1\nserver:\n  port: 70000\n")
	if err := e.Load(); err == nil {
		t.Fatal("expected load to fail on port 70000")
	}
}

func TestSaveMergesWritesAndDiffs(t *testing.T) {
	e := newTestEngine(t, "schemaVersion: 1\nserver:\n  bind: 0.0.0.0\n")
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	diff, err := e.Save("app", map[string]any{"server": map[string]any{"port": int64(9500)}}, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if len(diff) != 1 || diff[0].Pointer != "/server/port" || diff[0].Reason == "" {
		t.Fatalf("expected one restart entry, got %+v", diff)
	}
	raw := e.Raw("app")["server"].(map[string]any)
	if raw["bind"] != "0.0.0.0" || raw["port"] != int64(9500) {
		t.Fatalf("merge lost a key: %+v", raw)
	}
	if _, err := os.Stat(filepath.Join(e.Dir(), "app.config.yaml.bak")); err != nil {
		t.Fatal("no .bak written")
	}
	status := e.RestartPending()
	if !status.RestartRequired || *status.LastModifiedBy != "tester" {
		t.Fatalf("pending list wrong: %+v", status)
	}
	e.ClearRestart()
	if e.RestartPending().RestartRequired {
		t.Fatal("pending list not cleared")
	}
}

func TestSaveRefusesReadOnlyAndBadValues(t *testing.T) {
	e := newTestEngine(t, "schemaVersion: 1\n")
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	_, err := e.Save("app", map[string]any{"schemaVersion": int64(2), "logging": map[string]any{"categories": map[string]any{"tasks": "loud"}}}, "tester")
	var verr *ValidationError
	if !errors.As(err, &verr) || len(verr.Errors) != 2 {
		t.Fatalf("expected two failures, got %v", err)
	}
	if verr.Errors[0].Rule != "readOnly" || verr.Errors[1].Pointer != "/logging/categories/tasks" {
		t.Fatalf("unexpected failures: %+v", verr.Errors)
	}
}

func TestNullRemovesAKey(t *testing.T) {
	e := newTestEngine(t, "schemaVersion: 1\nserver:\n  bind: 0.0.0.0\n")
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Save("app", map[string]any{"server": map[string]any{"bind": nil}}, "tester"); err != nil {
		t.Fatal(err)
	}
	if _, present := e.Raw("app")["server"].(map[string]any)["bind"]; present {
		t.Fatal("null did not remove the key")
	}
	if got := e.GetAt("app", "/server/bind"); got != "127.0.0.1" {
		t.Fatalf("default not refilled: %v", got)
	}
}

func TestSetupTokenLifecycle(t *testing.T) {
	e := newTestEngine(t, "schemaVersion: 1\n")
	if err := os.WriteFile(e.setupTokenPath(), []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(e.setupTokenPath())
	if len(raw) != 64 {
		t.Fatalf("empty token not filled: %q", raw)
	}
	if e.SetupComplete() {
		t.Fatal("setup complete while the token exists")
	}
	if !e.tokenMatches(string(raw)) || e.tokenMatches("nope") {
		t.Fatal("token match wrong")
	}
	if err := e.SaveAll(map[string]map[string]any{"app": {"server": map[string]any{"port": int64(9000)}}}, "setup"); err != nil {
		t.Fatal(err)
	}
	e.deleteSetupToken()
	if !e.SetupComplete() {
		t.Fatal("setup not complete after the token is deleted")
	}
}
