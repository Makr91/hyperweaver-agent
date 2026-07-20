package machines

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// clearStaleSettings removes a leftover machine settings file from a
// previous failed attempt: unregistervm (deliberately WITHOUT --delete —
// that would take the whole working directory with it) keeps the .vbox
// file, and createvm then refuses with "settings file already exists"
// (runtime-proven 2026-07-06). Only acts when VirtualBox no longer knows
// the machine.
func (e *executors) clearStaleSettings(ctx context.Context, vboxExe, name string, out *tasks.OutputWriter) {
	if _, err := vbox.ShowVMInfo(ctx, vboxExe, name); !errors.Is(err, vbox.ErrNotFound) {
		return
	}
	workdir := e.machineWorkdir(name)
	for _, file := range []string{name + ".vbox", name + ".vbox-prev"} {
		path := filepath.Join(workdir, file)
		if _, serr := os.Stat(path); serr != nil {
			continue
		}
		out.Write("stderr", "Removing stale settings file from a previous attempt: "+path+"\n")
		if rerr := os.Remove(path); rerr != nil {
			out.Write("stderr", "Stale settings removal failed: "+rerr.Error()+"\n")
		}
	}
}

// clearStaleSourceRegistration drops a clone SOURCE's stale media-registry
// entry (registry hygiene, runtime-proven 2026-07-17: packer's
// stream-optimized VMDKs never take the UUID VirtualBox assigns at first
// registration, so a lingering entry fails the NEXT clone with an E_FAIL
// UUID mismatch). The close targets the entry's REGISTRY UUID — the path
// form re-opens the file and dies on the very mismatch being cleaned.
// Failures narrate; the clone's own error stays the honest signal.
func (e *executors) clearStaleSourceRegistration(ctx context.Context, vboxExe, sourcePath string, out *tasks.OutputWriter) {
	hdds, err := vbox.ListHDDs(ctx, vboxExe)
	if err != nil {
		out.Write("stderr", "Media-registry listing failed (clone proceeds): "+err.Error()+"\n")
		return
	}
	want := filepath.Clean(sourcePath)
	for i := range hdds {
		if !strings.EqualFold(filepath.Clean(hdds[i].Path), want) {
			continue
		}
		out.Write("stdout", "Releasing stale media-registry entry for "+sourcePath+"\n")
		if cerr := vbox.CloseMedium(ctx, vboxExe, hdds[i].UUID, false); cerr != nil {
			out.Write("stderr", "Stale registry release failed (the clone may refuse): "+cerr.Error()+"\n")
		}
		return
	}
}

func (e *executors) sweepOrphanCloneChildren(ctx context.Context, vboxExe, basePath string, out *tasks.OutputWriter) {
	hdds, err := vbox.ListHDDs(ctx, vboxExe)
	if err != nil {
		out.Write("stderr", "Media-registry listing failed (orphan-child sweep skipped): "+err.Error()+"\n")
		return
	}
	baseUUID := ""
	want := filepath.Clean(basePath)
	for i := range hdds {
		if strings.EqualFold(filepath.Clean(hdds[i].Path), want) {
			baseUUID = hdds[i].UUID
			break
		}
	}
	if baseUUID == "" {
		return
	}
	for i := range hdds {
		if hdds[i].ParentUUID != baseUUID || len(hdds[i].InUseBy) > 0 {
			continue
		}
		out.Write("stdout", "Removing orphaned differencing child from a previous attempt: "+hdds[i].Path+"\n")
		if cerr := vbox.CloseMedium(ctx, vboxExe, hdds[i].UUID, true); cerr != nil {
			out.Write("stderr", "Orphan child removal failed: "+cerr.Error()+"\n")
		}
	}
}

func (e *executors) stampDifferencingChild(ctx context.Context, vboxExe, machineName, basePath string, out *tasks.OutputWriter) error {
	hdds, err := vbox.ListHDDs(ctx, vboxExe)
	if err != nil {
		return fmt.Errorf("media registry listing for the differencing-child stamp: %w", err)
	}
	baseUUID := ""
	want := filepath.Clean(basePath)
	for i := range hdds {
		if strings.EqualFold(filepath.Clean(hdds[i].Path), want) {
			baseUUID = hdds[i].UUID
			break
		}
	}
	for i := range hdds {
		if hdds[i].ParentUUID != baseUUID || baseUUID == "" {
			continue
		}
		for _, holder := range hdds[i].InUseBy {
			if strings.EqualFold(holder, machineName) {
				out.Write("stdout", "Stamping differencing boot disk "+hdds[i].Path+"\n")
				return stampMedium(ctx, vboxExe, hdds[i].Path, DiskTypeTemplate, out)
			}
		}
	}
	return fmt.Errorf("differencing child of %s for machine %s not found in the media registry", basePath, machineName)
}

// clearStaleMedium makes a create retry idempotent: a previous failed run
// can leave the target medium on disk AND registered as an orphan in
// VirtualBox's media registry (runtime-proven 2026-07-06 — clonemedium onto
// it would fail). Close+delete via VirtualBox first; fall back to removing
// the bare file when it was never registered.
func clearStaleMedium(ctx context.Context, vboxExe, path string, out *tasks.OutputWriter) {
	if _, err := os.Stat(path); err != nil {
		return
	}
	out.Write("stderr", "Removing stale medium from a previous attempt: "+path+"\n")
	if cerr := vbox.CloseMedium(ctx, vboxExe, path, true); cerr != nil {
		if rerr := os.Remove(path); rerr != nil {
			out.Write("stderr", "Stale medium removal failed (the clone will error): "+rerr.Error()+"\n")
		}
	}
}

// cancelCreateStorage is machine_create_storage's post-kill cleanup (D-F): a
// kill mid-clone can leave half-written media the in-memory rollback list
// never saw — close and delete every medium the child places under the
// machine's working directory.
func (e *executors) cancelCreateStorage(task *tasks.Task, out *tasks.OutputWriter) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	vboxExe := VBoxManagePath(ctx)
	if vboxExe == "" {
		return
	}
	workdir := e.machineWorkdir(task.MachineName)
	candidates := []string{}
	for _, ext := range []string{".vmdk", ".vdi", ".vhd"} {
		candidates = append(candidates, filepath.Join(workdir, "boot"+ext))
	}
	if entries, err := os.ReadDir(filepath.Join(workdir, "disks")); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				candidates = append(candidates, filepath.Join(workdir, "disks", entry.Name()))
			}
		}
	}
	// Spec-named locations (the directory addendum + volume_name naming):
	// best-effort — only the EXACT filenames this step would have created are
	// swept, never a directory scan outside the workdir.
	if meta, merr := readCreateMetadata(task); merr == nil {
		candidates = append(candidates, cancelDiskCandidates(meta.Spec.Disks, workdir)...)
	}
	out.Write("stderr", "Storage step cancelled — removing half-made media\n")
	for _, path := range candidates {
		if _, serr := os.Stat(path); serr != nil {
			continue
		}
		if cerr := vbox.CloseMedium(ctx, vboxExe, path, true); cerr != nil {
			// Never registered with VirtualBox: delete the file directly.
			if rerr := os.Remove(path); rerr != nil {
				out.Write("stderr", "Cleanup of "+path+" failed: "+rerr.Error()+"\n")
			}
		}
		// A half-made medium's sidecar stamp goes with it.
		removeMediumSidecar(path)
	}
}

// cancelDiskCandidates names the EXACT files createStorage would have
// created from a disks section — volume_name'd boot media and blank
// additional disks, honoring each entry's directory (the addendum) — for the
// post-kill sweep. Custom directories contribute only these specific
// filenames, never a scan.
func cancelDiskCandidates(disks map[string]any, workdir string) []string {
	candidates := []string{}
	boot := mapOr(disks["boot"])
	bootDir := workdir
	if dir := stringOr(boot["directory"], ""); dir != "" && filepath.IsAbs(dir) {
		bootDir = dir
	}
	bootNames := []string{"boot"}
	if name := stringOr(boot["volume_name"], ""); name != "" && name != "boot" {
		bootNames = append(bootNames, name)
	}
	for _, name := range bootNames {
		for _, ext := range []string{".vmdk", ".vdi", ".vhd"} {
			candidates = append(candidates, filepath.Join(bootDir, name+ext))
		}
	}
	for i, entry := range listOr(disks["additional_disks"]) {
		disk := mapOr(entry)
		if stringOr(disk["type"], "") != DiskTypeBlank {
			continue
		}
		dir := filepath.Join(workdir, "disks")
		if custom := stringOr(disk["directory"], ""); custom != "" && filepath.IsAbs(custom) {
			dir = custom
		}
		name := stringOr(disk["volume_name"], fmt.Sprintf("disk%d", i+1))
		candidates = append(candidates, filepath.Join(dir, name+".vdi"))
	}
	return candidates
}

// cancelCreateConfig is machine_create_config's post-kill cleanup: the
// half-configured machine is unregistered (the error path's rule applied to
// cancellation).
func (e *executors) cancelCreateConfig(task *tasks.Task, out *tasks.OutputWriter) {
	// UTM machines have no unregister to run: utmctl delete's path plumbing
	// arrives with the lifecycle phase — narrate the possible leftover.
	if meta, merr := readCreateMetadata(task); merr == nil && meta.Spec.Hypervisor == HypervisorUTM {
		out.Write("stderr", "Config step cancelled — a half-imported machine may remain in UTM; delete it in the UTM UI\n")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	vboxExe := VBoxManagePath(ctx)
	if vboxExe == "" {
		return
	}
	out.Write("stderr", "Config step cancelled — unregistering the half-made machine\n")
	if err := vbox.UnregisterVM(ctx, vboxExe, task.MachineName, false); err != nil {
		// A machine that never reached createvm has nothing to unregister.
		out.Write("stderr", "Unregister after cancel: "+err.Error()+"\n")
	}
	e.clearStaleSettings(ctx, vboxExe, task.MachineName, out)
}
