package utm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/procattr"
)

// Snapshots are OFFLINE qemu-img operations against the qcow2 inside the
// machine's .utm bundle — callers gate on stopped (qemu-img needs the write
// lock).

// QemuImgPath resolves qemu-img from PATH — UTM does not bundle a findable
// copy.
func QemuImgPath() (string, error) {
	path, err := exec.LookPath("qemu-img")
	if err != nil {
		return "", errors.New("qemu-img is required for utm snapshots (install it, e.g. brew install qemu)")
	}
	return path, nil
}

// VMDiskPath resolves the machine's qcow2 inside its bundle under
// ~/Library/Containers/com.utmapp.UTM/Data/Documents/<name>.utm/Data —
// exactly one qcow2 must live there.
func VMDiskPath(ctx context.Context, id string) (string, error) {
	regs, err := List(ctx)
	if err != nil {
		return "", err
	}
	name := ""
	for _, reg := range regs {
		if reg.UUID == id {
			name = reg.Name
			break
		}
	}
	if name == "" {
		return "", ErrNotFound
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	dataDir := filepath.Join(home, "Library", "Containers", "com.utmapp.UTM",
		"Data", "Documents", name+".utm", "Data")
	matches, err := filepath.Glob(filepath.Join(dataDir, "*.qcow2"))
	if err != nil {
		return "", fmt.Errorf("scan %s: %w", dataDir, err)
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("expected exactly one qcow2 in %s, found %d", dataDir, len(matches))
	}
	return matches[0], nil
}

// runQemuImg executes one qemu-img command, folding stderr into the returned
// error.
func runQemuImg(ctx context.Context, args ...string) (string, error) {
	qemuImg, err := QemuImgPath()
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, qemuImg, args...)
	cmd.SysProcAttr = procattr.NoConsole()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if rerr := cmd.Run(); rerr != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return "", fmt.Errorf("qemu-img %s: %w: %s", args[0], rerr, detail)
		}
		return "", fmt.Errorf("qemu-img %s: %w", args[0], rerr)
	}
	return stdout.String(), nil
}

// CreateSnapshot records a snapshot (`qemu-img snapshot -c`).
func CreateSnapshot(ctx context.Context, id, snapshotName string) error {
	disk, err := VMDiskPath(ctx, id)
	if err != nil {
		return err
	}
	_, err = runQemuImg(ctx, "snapshot", "-c", snapshotName, disk)
	return err
}

// DeleteSnapshot removes a snapshot (`qemu-img snapshot -d`).
func DeleteSnapshot(ctx context.Context, id, snapshotName string) error {
	disk, err := VMDiskPath(ctx, id)
	if err != nil {
		return err
	}
	_, err = runQemuImg(ctx, "snapshot", "-d", snapshotName, disk)
	return err
}

// RestoreSnapshot applies a snapshot (`qemu-img snapshot -a`).
func RestoreSnapshot(ctx context.Context, id, snapshotName string) error {
	disk, err := VMDiskPath(ctx, id)
	if err != nil {
		return err
	}
	_, err = runQemuImg(ctx, "snapshot", "-a", snapshotName, disk)
	return err
}

// snapshotRow matches a `qemu-img snapshot -l` table row: numeric ID, then
// the name (\S+ — the snapshot vocabulary allows dots and dashes).
var snapshotRow = regexp.MustCompile(`^\d+\s+(\S+)`)

// ListSnapshots returns the disk's snapshot names (`qemu-img snapshot -l`).
func ListSnapshots(ctx context.Context, id string) ([]string, error) {
	disk, err := VMDiskPath(ctx, id)
	if err != nil {
		return nil, err
	}
	out, err := runQemuImg(ctx, "snapshot", "-l", disk)
	if err != nil {
		return nil, err
	}
	names := []string{}
	for _, line := range strings.Split(out, "\n") {
		if match := snapshotRow.FindStringSubmatch(strings.TrimSpace(line)); match != nil {
			names = append(names, match[1])
		}
	}
	return names, nil
}
