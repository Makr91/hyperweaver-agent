package assets

import (
	"errors"
	"regexp"
	"strings"
)

// Artifact types — the location-type vocabulary. iso/image are zoneweaver's
// flat, extension-filtered locations; installer/fixpack/hotfix are SHI's
// role-keyed cache kinds (<location>/<role>/<file>).
const (
	KindISO       = "iso"
	KindImage     = "image"
	KindInstaller = "installer"
	KindFixpack   = "fixpack"
	KindHotfix    = "hotfix"
)

// KindNames lists every artifact type for refusals.
const KindNames = "iso, image, installer, fixpack, hotfix"

// kindInterimFix is BoxVault's name for a hotfix on its download files; it is read as KindHotfix on every route that takes a kind.
const kindInterimFix = "interim-fix"

// NormalizeKind answers the artifact type a request names, interim-fix read as hotfix.
func NormalizeKind(kind string) string {
	if kind == kindInterimFix {
		return KindHotfix
	}
	return kind
}

// ErrNotFound is returned when no artifact or location matches the request.
var ErrNotFound = errors.New("artifact not found")

// ErrLocationNotFound distinguishes a missing storage location.
var ErrLocationNotFound = errors.New("storage location not found")

var (
	rolePattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	filenamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,254}$`)
	fixpackName     = regexp.MustCompile(`FP\d+`)
	hotfixName      = regexp.MustCompile(`(HF|IF)\d+`)
)

// KindOfName answers the kind a file discovered in a location carries: in an installer location a name carrying FP<digits> is a fixpack and one carrying HF<digits> or IF<digits> a hotfix, the rest installers; every other location's files carry its type.
func KindOfName(filename, locationType string) string {
	if locationType != KindInstaller {
		return locationType
	}
	switch {
	case fixpackName.MatchString(filename):
		return KindFixpack
	case hotfixName.MatchString(filename):
		return KindHotfix
	}
	return KindInstaller
}

// ValidRole reports whether s is usable as a role directory.
func ValidRole(s string) bool {
	return rolePattern.MatchString(s)
}

// ValidFilename reports whether s is usable as a stored filename.
func ValidFilename(s string) bool {
	return filenamePattern.MatchString(s) && !strings.Contains(s, "..")
}

// ValidKind reports whether s is one of the artifact types.
func ValidKind(s string) bool {
	switch s {
	case KindISO, KindImage, KindInstaller, KindFixpack, KindHotfix:
		return true
	}
	return false
}

// RoleKeyed reports whether a type stores files under role directories, the installer kinds under the folder a role reads, rather than flat (zoneweaver's iso/image).
func RoleKeyed(kind string) bool {
	switch kind {
	case KindInstaller, KindFixpack, KindHotfix:
		return true
	}
	return false
}
