package assets

import (
	"mime"
	"path/filepath"
	"strings"
	"time"
)

// Artifact is one artifact registry row (zoneweaver's Artifact shape with
// the SHI extras alongside). checksum is what the file actually hashed to
// when last verified; expected_sha256 is the recorded expectation (bundled
// registry seed, caller-supplied, or the HCL catalog). file_exists:false rows
// are expectations awaiting their binary (SHI's model).
type Artifact struct {
	ID         int64  `json:"id"`
	LocationID string `json:"storage_location_id"`
	// Installer-family rows only — the role directory
	Role     string `json:"role,omitempty"`
	Kind     string `json:"file_type"`
	Filename string `json:"filename"`
	// File location (empty on expectation-only rows)
	Path string `json:"path"`
	// The file's actual SHA-256
	SHA256         string     `json:"checksum"`
	ExpectedSHA256 string     `json:"expected_sha256,omitempty"`
	Size           int64      `json:"size"`
	Version        string     `json:"version,omitempty"`
	Exists         bool       `json:"file_exists"`
	VerifiedAt     *time.Time `json:"last_verified"`
	SourceURL      string     `json:"source_url,omitempty"`
	CreatedAt      time.Time  `json:"discovered_at"`
	UpdatedAt      time.Time  `json:"updatedAt"`
}

// Verified reports whether the file's hash is trustworthy: it exists, was
// hashed, and matches its expectation when one is recorded.
func (a *Artifact) Verified() bool {
	if !a.Exists || a.SHA256 == "" {
		return false
	}
	return a.ExpectedSHA256 == "" || strings.EqualFold(a.SHA256, a.ExpectedSHA256)
}

// ChecksumVerified is the wire's tri-state (zoneweaver's checksum_verified):
// true = matches the expectation, false = mismatch, nil = nothing to verify
// against.
func (a *Artifact) ChecksumVerified() *bool {
	if !a.Exists || a.SHA256 == "" || a.ExpectedSHA256 == "" {
		return nil
	}
	v := strings.EqualFold(a.SHA256, a.ExpectedSHA256)
	return &v
}

// Extension returns the filename's lowercase extension.
func (a *Artifact) Extension() string {
	return strings.ToLower(filepath.Ext(a.Filename))
}

// MimeType resolves the artifact's MIME type from its extension.
func (a *Artifact) MimeType() string {
	switch a.Extension() {
	case ".iso":
		return "application/x-iso9660-image"
	case ".vmdk", ".vdi", ".qcow2", ".raw", ".img":
		return "application/octet-stream"
	}
	if t := mime.TypeByExtension(a.Extension()); t != "" {
		return t
	}
	return "application/octet-stream"
}
