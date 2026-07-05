// Package webui provides the Hyperweaver UI artifact as an fs.FS. The dist
// directory is embedded at build time; the release workflow bakes the
// published hyperweaver-ui artifact into it (pinned by .ui-version), while
// the committed placeholder keeps development and CI builds compiling
// without it.
package webui

import (
	"embed"
	"io/fs"
	"os"
)

//go:embed all:dist
var embedded embed.FS

// FS returns the filesystem the UI is served from. A non-empty diskPath
// overrides the embedded artifact (the ui.path config setting).
func FS(diskPath string) (fs.FS, error) {
	if diskPath != "" {
		if _, err := os.Stat(diskPath); err != nil {
			return nil, err
		}
		return os.DirFS(diskPath), nil
	}
	return fs.Sub(embedded, "dist")
}
