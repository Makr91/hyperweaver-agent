package machines

import (
	"errors"
	"fmt"

	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// ValidateModifyDocument dry-runs the modify translation — the accrue path's
// PUT-time validation: unknown hardware sections/knobs, malformed
// serial/parallel entries, and untyped add_disks reject at the PUT instead
// of at apply time.
func ValidateModifyDocument(metadata map[string]any, info *vbox.Info) error {
	if err := ValidateAddDisks(listOr(metadata["add_disks"])); err != nil {
		return err
	}
	for _, entry := range listOr(metadata["nics"]) {
		if _, err := nicAttachmentFlags(mapOr(entry), "1"); err != nil {
			return err
		}
	}
	_, _, err := modifyAttributeFlags(metadata, info)
	return err
}

// ValidateAddDisks enforces the typed disk entries on the modify add_disks
// family (the frozen create strings with this surface's own prefix, sync
// 2026-07-18 — the old presence-dispatch dialect died with the cut). Path
// existence and the in-use check stay task-time, like create.
func ValidateAddDisks(entries []any) error {
	for i, entry := range entries {
		disk := mapOr(entry)
		prefix := fmt.Sprintf("add_disks[%d]", i+1)
		raw, present := disk["type"]
		if !present {
			return errors.New(prefix + ".type is required (image|blank)")
		}
		switch entryType := verbatimValue(raw); entryType {
		case DiskTypeImage:
			if stringOr(disk["path"], "") == "" {
				return errors.New(prefix + ".type image requires path")
			}
			_, hasSize := disk["size"]
			_, hasVolumeName := disk["volume_name"]
			if hasSize || hasVolumeName {
				return errors.New(prefix + ".type image does not take size or volume_name (an image attaches as-is)")
			}
			if _, has := disk["directory"]; has {
				return errors.New(prefix + ".type image does not take directory")
			}
		case DiskTypeBlank:
			if sizeToMB(disk["size"]) <= 0 {
				return errors.New(prefix + ".type blank requires size")
			}
			if _, has := disk["path"]; has {
				return errors.New(prefix + ".type blank does not take path")
			}
		default:
			return errors.New(prefix + ".type " + entryType + " is not a valid additional disk type (image|blank)")
		}
	}
	return nil
}
