package machines

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// The typed disk spec (Mark's word, sync 2026-07-17 — the ZERO-inference
// model): disks.boot.type is the ONLY dispatcher — template clones from
// settings.box, image attaches an existing file as-is, blank creates a fresh
// VDI, none is diskless. The old presence-dispatch ladder (path→attach,
// box→clone, size→blank) died with it. additional_disks[] entries take
// image|blank under the same rules; cdroms[] take exactly one of iso|path.
// Unknown keys in disks entries are NEVER read for behavior and always
// preserved verbatim in the stored document. Both agents ship the identical
// frozen refusal strings.

// Disk types — the disks.boot.type vocabulary (additional_disks[] entries
// take image|blank only).
const (
	DiskTypeTemplate = "template"
	DiskTypeImage    = "image"
	DiskTypeBlank    = "blank"
	DiskTypeNone     = "none"
)

// bhyveDiskKeys are the other-hypervisor keys a disks entry may carry —
// bhyve vocabulary with no effect here: warned (never refused) and preserved
// verbatim in the stored document (converged, sync 2026-07-17).
var bhyveDiskKeys = []string{"pool", "dataset", "diskif", "clone_strategy"}

// verbatimValue renders a document value for a refusal/warning string —
// strings ride verbatim (even empty), everything else through fmt.
func verbatimValue(value any) string {
	if s, ok := value.(string); ok {
		return s
	}
	return fmt.Sprint(value)
}

// EffectiveBootType resolves the boot medium's effective type: an ABSENT
// disks.boot is the spelled default — template when settings.box is present,
// none otherwise (exactly today's box/diskless ladder, now spelled); a
// PRESENT boot answers its declared type, "" when the type is missing or not
// in the vocabulary (ValidateDisks refuses that case with the frozen string).
func EffectiveBootType(disks, settings map[string]any) string {
	if _, present := disks["boot"]; !present {
		if stringOr(settings["box"], "") != "" {
			return DiskTypeTemplate
		}
		return DiskTypeNone
	}
	boot := mapOr(disks["boot"])
	switch declared := verbatimValue(boot["type"]); declared {
	case DiskTypeTemplate, DiskTypeImage, DiskTypeBlank, DiskTypeNone:
		return declared
	}
	return ""
}

// ValidateDisks enforces the typed disk spec against a disks section +
// settings (pure — no I/O: path existence and attachment are task-time
// checks in createStorage). problems carry the frozen refusal strings in
// document order (callers answer the FIRST as the 400 / task failure);
// warnings carry the never-refuse rows (bhyve vocabulary keys, an unused
// settings.box) for the create response's resource_warnings.
func ValidateDisks(disks, settings map[string]any) (problems, warnings []string) {
	refuse := func(message string) { problems = append(problems, message) }
	box := stringOr(settings["box"], "")

	// Boot entry — type REQUIRED whenever disks.boot is present.
	bootRaw, bootPresent := disks["boot"]
	boot := mapOr(bootRaw)
	declared := ""
	if bootPresent {
		if raw, typePresent := boot["type"]; !typePresent {
			refuse("disks.boot.type is required when disks.boot is present (template|image|blank|none)")
		} else {
			declared = verbatimValue(raw)
			switch declared {
			case DiskTypeTemplate, DiskTypeImage, DiskTypeBlank, DiskTypeNone:
			default:
				refuse("disks.boot.type " + declared + " is not a valid disk type (template|image|blank|none)")
				declared = ""
			}
		}
	}
	switch declared {
	case DiskTypeTemplate:
		// size = grow-to (legal); path never rides a clone.
		if box == "" {
			refuse("disks.boot.type template requires settings.box")
		}
		if _, has := boot["path"]; has {
			refuse("disks.boot.type template does not take path")
		}
	case DiskTypeImage:
		// The file attaches AS-IS — never created, deleted, or resized.
		if stringOr(boot["path"], "") == "" {
			refuse("disks.boot.type image requires path")
		}
		_, hasSize := boot["size"]
		_, hasVolumeName := boot["volume_name"]
		if hasSize || hasVolumeName {
			refuse("disks.boot.type image does not take size or volume_name (an image attaches as-is)")
		}
		// directory places CREATED files (the addendum, converged 2026-07-17)
		// — an image's full path already places it.
		if _, has := boot["directory"]; has {
			refuse("disks.boot.type image does not take directory")
		}
	case DiskTypeBlank:
		if sizeToMB(boot["size"]) <= 0 {
			refuse("disks.boot.type blank requires size")
		}
		if _, has := boot["path"]; has {
			refuse("disks.boot.type blank does not take path")
		}
	case DiskTypeNone:
		for key := range boot {
			if key != "type" {
				refuse("disks.boot.type none takes no other keys")
				break
			}
		}
	}

	// additional_disks[] — type REQUIRED, image|blank only, same per-type
	// rules; the index in every string is 1-BASED.
	for i, entry := range listOr(disks["additional_disks"]) {
		prefix := "disks.additional_disks[" + strconv.Itoa(i+1) + "]"
		disk := mapOr(entry)
		raw, typePresent := disk["type"]
		if !typePresent {
			refuse(prefix + ".type is required (image|blank)")
			continue
		}
		switch entryType := verbatimValue(raw); entryType {
		case DiskTypeImage:
			if stringOr(disk["path"], "") == "" {
				refuse(prefix + ".type image requires path")
			}
			_, hasSize := disk["size"]
			_, hasVolumeName := disk["volume_name"]
			if hasSize || hasVolumeName {
				refuse(prefix + ".type image does not take size or volume_name (an image attaches as-is)")
			}
			if _, has := disk["directory"]; has {
				refuse(prefix + ".type image does not take directory")
			}
		case DiskTypeBlank:
			if sizeToMB(disk["size"]) <= 0 {
				refuse(prefix + ".type blank requires size")
			}
			if _, has := disk["path"]; has {
				refuse(prefix + ".type blank does not take path")
			}
		default:
			refuse(prefix + ".type " + entryType + " is not a valid additional disk type (image|blank)")
		}
	}

	// cdroms[] — EXACTLY one of iso|path per entry (1-based index).
	for i, entry := range listOr(disks["cdroms"]) {
		cdrom := mapOr(entry)
		hasISO := stringOr(cdrom["iso"], "") != ""
		hasPath := stringOr(cdrom["path"], "") != ""
		if hasISO == hasPath {
			refuse("disks.cdroms[" + strconv.Itoa(i+1) + "] needs exactly one of iso or path")
		}
	}

	// Warnings — never refusals: bhyve vocabulary in any disk entry (deduped
	// by key) and a settings.box the effective boot type never reads.
	seenBhyveKeys := map[string]bool{}
	scanBhyveKeys := func(entry map[string]any) {
		for _, key := range bhyveDiskKeys {
			if _, has := entry[key]; has && !seenBhyveKeys[key] {
				seenBhyveKeys[key] = true
				warnings = append(warnings, key+" is bhyve vocabulary and has no effect on this hypervisor")
			}
		}
	}
	if bootPresent {
		scanBhyveKeys(boot)
	}
	for _, entry := range listOr(disks["additional_disks"]) {
		scanBhyveKeys(mapOr(entry))
	}
	if effective := EffectiveBootType(disks, settings); box != "" &&
		effective != "" && effective != DiskTypeTemplate {
		warnings = append(warnings, "settings.box is unused when disks.boot.type is "+effective)
	}
	return problems, warnings
}

// mediumSourceProperty is the provenance stamp's VirtualBox medium property
// key; mediumSourceSidecar is the fallback file's suffix (the frozen
// property-first, sidecar-fallback decision — converged, sync 2026-07-17).
const (
	mediumSourceProperty = "hyperweaver:source"
	mediumSourceSidecar  = ".hw-source"
)

// MediumSourceStamp reads a medium's provenance stamp — the VirtualBox
// medium property first, the <disk>.hw-source sidecar second ("" =
// unstamped: a foreign medium the agent never created). The delete flow's
// destroy-vs-preserve decision and GET /media both read through it.
func MediumSourceStamp(ctx context.Context, vboxExe, path string) string {
	if vboxExe != "" {
		if value, gerr := vbox.GetMediumProperty(ctx, vboxExe, path, mediumSourceProperty); gerr == nil && value != "" {
			return value
		}
	}
	raw, rerr := os.ReadFile(filepath.Clean(path + mediumSourceSidecar))
	if rerr != nil {
		return ""
	}
	return strings.TrimSpace(strings.SplitN(string(raw), "\n", 2)[0])
}

// stampMedium marks a medium the agent CREATED at materialization
// (source: template | blank): modifymedium --property first; on its failure
// the sidecar file carries the value (one line) with the fallback narrated.
// Both failing fails the step — an unstamped agent-created medium would read
// as foreign at delete time. image media are NEVER stamped.
func stampMedium(ctx context.Context, vboxExe, path, source string, out *tasks.OutputWriter) error {
	serr := vbox.SetMediumProperty(ctx, vboxExe, path, mediumSourceProperty, source)
	if serr == nil {
		return nil
	}
	out.Write("stderr", "modifymedium --property failed ("+serr.Error()+
		") — falling back to the sidecar "+path+mediumSourceSidecar+"\n")
	if werr := os.WriteFile(filepath.Clean(path+mediumSourceSidecar), []byte(source+"\n"), 0o600); werr != nil {
		return fmt.Errorf("stamp medium %s: property and sidecar both failed: %w", path, werr)
	}
	return nil
}

// removeMediumSidecar drops a rolled-back medium's sidecar stamp (cosmetic —
// the medium itself is already gone).
func removeMediumSidecar(path string) {
	_ = os.Remove(filepath.Clean(path + mediumSourceSidecar))
}

// diskDirectory resolves a CREATED disk's target folder — the `directory`
// addendum (converged, sync 2026-07-17: the pool/dataset mirror for VBox):
// the entry's directory when present must be an ABSOLUTE, EXISTING folder on
// the agent host (never created by the agent — the frozen refusal names it);
// absent = fallback, the machine folder (the spelled default). where names
// the entry for the refusal string.
func diskDirectory(entry map[string]any, fallback, where string) (string, error) {
	raw, present := entry["directory"]
	if !present {
		return fallback, nil
	}
	dir := verbatimValue(raw)
	refusal := errors.New(where + " directory " + dir + " is not an absolute existing directory on this host")
	if !filepath.IsAbs(dir) {
		return "", refusal
	}
	info, serr := os.Stat(dir)
	if serr != nil || !info.IsDir() {
		return "", refusal
	}
	return filepath.Clean(dir), nil
}

// mediumHolder answers which OTHER machine holds the medium (the image
// attach pre-check): "" when unattached or held only by selfName. The
// listing failing is a real error — the pre-check cannot silently skip.
func mediumHolder(ctx context.Context, vboxExe, path, selfName string) (string, error) {
	hdds, err := vbox.ListHDDs(ctx, vboxExe)
	if err != nil {
		return "", err
	}
	want := filepath.Clean(path)
	for i := range hdds {
		if !strings.EqualFold(filepath.Clean(hdds[i].Path), want) {
			continue
		}
		for _, holder := range hdds[i].InUseBy {
			if !strings.EqualFold(holder, selfName) {
				return holder, nil
			}
		}
	}
	return "", nil
}
