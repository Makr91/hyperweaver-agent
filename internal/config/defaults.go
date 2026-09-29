package config

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

//go:embed schema/*.schema.yaml
var schemaFiles embed.FS

//go:embed seed/*.config.yaml
var seedFiles embed.FS

// Names is the code-fixed list of configuration files, in load order.
var Names = []string{"app", "auth", "db", "machines", "storage"}

// SchemaFS answers the embedded schema documents.
func SchemaFS() fs.FS {
	sub, err := fs.Sub(schemaFiles, "schema")
	if err != nil {
		return schemaFiles
	}
	return sub
}

// SeedFS answers the embedded first-install configuration files.
func SeedFS() fs.FS {
	sub, err := fs.Sub(seedFiles, "seed")
	if err != nil {
		return seedFiles
	}
	return sub
}

func ensureSeeds(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	seeds := SeedFS()
	for _, name := range Names {
		target := filepath.Join(dir, name+".config.yaml")
		if _, err := os.Stat(target); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat config %s: %w", target, err)
		}
		raw, err := fs.ReadFile(seeds, name+".config.yaml")
		if err != nil {
			return err
		}
		if werr := safepath.WriteFile(target, raw, 0o600); werr != nil {
			return fmt.Errorf("write seed config %s: %w", target, werr)
		}
	}
	return nil
}
