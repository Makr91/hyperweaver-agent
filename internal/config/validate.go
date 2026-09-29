package config

import (
	"net"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/locations"
	"github.com/Makr91/hyperweaver-agent/internal/problem"
)

func failure(pointer, rule string, params map[string]any) []problem.Error {
	if params == nil {
		params = map[string]any{}
	}
	return []problem.Error{{Pointer: pointer, Rule: rule, Params: params}}
}

func stringValue(value any) (string, bool) {
	s, ok := value.(string)
	return s, ok
}

func nested(document map[string]any, keys ...string) map[string]any {
	node := document
	for _, key := range keys {
		child, ok := node[key].(map[string]any)
		if !ok {
			return nil
		}
		node = child
	}
	return node
}

func storagePathRules(pointer string, document map[string]any, base string) []problem.Error {
	if !strings.HasPrefix(pointer, base+"/") {
		return nil
	}
	rest := strings.TrimPrefix(pointer, base+"/")
	id, field, _ := strings.Cut(rest, "/")
	if id == locations.BuiltinID {
		return failure(base+"/"+id, "pattern", map[string]any{"pattern": "storagePathId"})
	}
	segments := strings.Split(strings.TrimPrefix(base, "/"), "/")
	entries := nested(document, segments...)
	entry, _ := entries[id].(map[string]any)
	switch field {
	case "path":
		path, _ := stringValue(entry["path"])
		if !filepath.IsAbs(filepath.FromSlash(path)) {
			return failure(pointer, "pattern", map[string]any{"pattern": "absolutePath"})
		}
		for otherID, raw := range entries {
			other, _ := raw.(map[string]any)
			otherPath, _ := stringValue(other["path"])
			if otherID != id && locations.SamePath(otherPath, path) {
				return failure(pointer, "unique", map[string]any{"scope": strings.TrimPrefix(base, "/")})
			}
		}
	case "default":
		enabled, _ := entry["default"].(bool)
		if !enabled {
			return nil
		}
		for otherID, raw := range entries {
			other, _ := raw.(map[string]any)
			if otherDefault, _ := other["default"].(bool); otherID != id && otherDefault {
				return failure(pointer, "unique", map[string]any{"scope": strings.TrimPrefix(base, "/")})
			}
		}
	}
	return nil
}

func (c *Config) codeRules(pointer string, value any, name string, document map[string]any, _ string) []problem.Error {
	switch name {
	case "app":
		switch pointer {
		case "/server/bind_address":
			if s, ok := stringValue(value); ok && s != "" && net.ParseIP(s) == nil {
				return failure(pointer, "format", map[string]any{"format": "ip"})
			}
		case "/file_browser/root":
			if s, ok := stringValue(value); ok && s != "" && !filepath.IsAbs(filepath.FromSlash(s)) {
				return failure(pointer, "pattern", map[string]any{"pattern": "absolutePath"})
			}
		}
		if strings.HasPrefix(pointer, "/applications/") && strings.HasSuffix(pointer, "/path") {
			if s, ok := stringValue(value); ok && !filepath.IsAbs(filepath.FromSlash(s)) {
				return failure(pointer, "pattern", map[string]any{"pattern": "absolutePath"})
			}
		}
	case "auth":
		if pointer == "/oidc/client_id" {
			oidc := nested(document, "oidc")
			enabled, _ := oidc["enabled"].(bool)
			if s, _ := stringValue(value); enabled && strings.TrimSpace(s) == "" {
				return failure(pointer, "required", nil)
			}
		}
		if pointer == "/oidc/issuer" {
			oidc := nested(document, "oidc")
			enabled, _ := oidc["enabled"].(bool)
			s, _ := stringValue(value)
			if enabled {
				parsed, err := url.Parse(s)
				if err != nil || parsed.Host == "" || parsed.Scheme != "https" {
					return failure(pointer, "format", map[string]any{"format": "uri"})
				}
			}
		}
	case "machines":
		if pointer == "/provisioning/network/subnet" {
			if s, ok := stringValue(value); ok {
				if _, _, err := net.ParseCIDR(s); err != nil {
					return failure(pointer, "format", map[string]any{"format": "cidr"})
				}
			}
		}
		if errs := storagePathRules(pointer, document, "/provisioning/machines_paths"); errs != nil {
			return errs
		}
		if errs := storagePathRules(pointer, document, "/provisioning/provisioners_paths"); errs != nil {
			return errs
		}
	case "storage":
		if errs := storagePathRules(pointer, document, "/template_sources/storage_paths"); errs != nil {
			return errs
		}
		if strings.HasPrefix(pointer, "/artifact_storage/paths/") && strings.HasSuffix(pointer, "/path") {
			if s, ok := stringValue(value); ok && !filepath.IsAbs(filepath.FromSlash(s)) {
				return failure(pointer, "pattern", map[string]any{"pattern": "absolutePath"})
			}
		}
	}
	return nil
}
