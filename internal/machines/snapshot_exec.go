package machines

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/qga"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/utm"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// Snapshot operations + the current-state clone — the VBoxManage
// snapshot/clonevm surface (yardstick 2). The base's equivalent power is its
// ZFS snapshot family; on this hypervisor snapshots are VirtualBox-native and
// per-machine, so they ride the machine task queue (per-machine exclusivity
// serializes them against lifecycle exactly like every other operation).

// Snapshot-family operations.
const (
	OpSnapshotTake    = "snapshot_take"
	OpSnapshotRestore = "snapshot_restore"
	OpSnapshotDelete  = "snapshot_delete"
	OpSnapshotModify  = "snapshot_modify"
	OpCloneCurrent    = "machine_clone_current"
)

// snapshotMetadata is the snapshot tasks' metadata document. Take accepts a
// literal snapshot_name OR prefix (+ retention / max_age_days) — the
// Snapshoter-style rotation semantics shared with zoneweaver: the snapshot is
// named <prefix>-YYYYMMDD-HHMM and the prune keeps the newest N (or drops
// aged-out) <prefix>-* snapshots after the take.
type snapshotMetadata struct {
	SnapshotName string `json:"snapshot_name"`
	Prefix       string `json:"prefix,omitempty"`
	Retention    int    `json:"retention,omitempty"`
	MaxAgeDays   int    `json:"max_age_days,omitempty"`
	Description  string `json:"description,omitempty"`
	// Live takes the snapshot without pausing a running machine (--live).
	Live bool `json:"live,omitempty"`
	// Quiesce runs qga fsfreeze around the take when the guest agent answers
	// (application-consistent; a silent channel narrates and the snapshot
	// proceeds crash-consistent).
	Quiesce bool `json:"quiesce,omitempty"`
}

// readSnapshotMetadata parses a snapshot task's metadata. allowPrefix lets
// the take task name by prefix instead of a literal snapshot_name.
func readSnapshotMetadata(task *tasks.Task, allowPrefix bool) (*snapshotMetadata, error) {
	if len(task.Metadata) == 0 {
		return nil, errors.New("snapshot task has no metadata")
	}
	var meta snapshotMetadata
	if err := json.Unmarshal(task.Metadata, &meta); err != nil {
		return nil, fmt.Errorf("parse snapshot metadata: %w", err)
	}
	if meta.SnapshotName == "" && (!allowPrefix || meta.Prefix == "") {
		return nil, errors.New("snapshot task metadata has no snapshot_name")
	}
	return &meta, nil
}

// snapshotTimestampLayout names rotation snapshots — lexicographic order IS
// chronological order, so the prune sorts by name (VirtualBox snapshots carry
// no queryable creation time the machinereadable list exposes).
const snapshotTimestampLayout = "20060102-1504"

// resolveName answers the take's snapshot name — the shared rotation naming
// (prefix takes get <prefix>-<timestamp>).
func (m *snapshotMetadata) resolveName() string {
	if m.SnapshotName != "" {
		return m.SnapshotName
	}
	return m.Prefix + "-" + time.Now().Format(snapshotTimestampLayout)
}

// snapshotTake executes snapshot_take (`VBoxManage snapshot take`): quiesce →
// take → retention/age prune (prefix-scoped, exactly zoneweaver's semantics).
func (e *executors) snapshotTake(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	if e.dispatchUTM(ctx, task) {
		return e.snapshotTakeUTM(ctx, task, out)
	}
	machine, vboxExe, err := e.resolve(ctx, task)
	if err != nil {
		return err
	}
	meta, err := readSnapshotMetadata(task, true)
	if err != nil {
		return err
	}
	name := meta.resolveName()

	e.taskProgress(task, 20, "taking_snapshot")
	thaw := func() {}
	if meta.Quiesce {
		thaw = e.freezeGuest(ctx, machine, vboxExe, out)
	}
	out.Write("stdout", "Taking snapshot "+name+" of "+machine.Name+"\n")
	serr := vbox.TakeSnapshot(ctx, vboxExe, machine.VBoxTarget(),
		name, meta.Description, meta.Live)
	thaw()
	if serr != nil {
		out.Write("stderr", "Snapshot failed: "+serr.Error()+"\n")
		return serr
	}
	out.Write("stdout", "Snapshot "+name+" taken\n")

	// The prune runs only for prefix-named takes (rotation semantics) — a
	// literal named snapshot never deletes anything. Prune failures narrate
	// and never fail the take: the snapshot itself exists.
	if meta.Prefix != "" && (meta.Retention > 0 || meta.MaxAgeDays > 0) {
		e.taskProgress(task, 90, "pruning_snapshots")
		e.pruneSnapshots(meta.Prefix, meta.Retention, meta.MaxAgeDays,
			func() ([]string, error) {
				list, lerr := vbox.ListSnapshots(ctx, vboxExe, machine.VBoxTarget())
				if lerr != nil {
					return nil, lerr
				}
				names := make([]string, 0, len(list))
				for i := range list {
					names = append(names, list[i].Name)
				}
				return names, nil
			},
			func(snapshot string) error {
				return vbox.DeleteSnapshot(ctx, vboxExe, machine.VBoxTarget(), snapshot)
			}, out)
	}
	e.taskProgress(task, 100, "completed")
	return nil
}

// requireStoppedUTM gates the utm snapshot verbs: qemu-img needs the qcow2
// write lock, so the machine must be stopped.
func (e *executors) requireStoppedUTM(ctx context.Context, utmctlPath, target string) error {
	status, err := utm.Status(ctx, utmctlPath, target)
	if err != nil {
		return err
	}
	if utm.MapUTMState(status) != StatusStopped {
		return errors.New("utm snapshots are offline (qemu-img) — stop the machine first")
	}
	return nil
}

// snapshotTakeUTM is snapshot_take's utm branch: offline qemu-img against the
// bundle qcow2; quiesce/live/description have no utm channel and narrate as
// skipped.
func (e *executors) snapshotTakeUTM(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	machine, utmctlPath, err := e.resolveUTM(ctx, task)
	if err != nil {
		return err
	}
	meta, err := readSnapshotMetadata(task, true)
	if err != nil {
		return err
	}
	target := machine.VBoxTarget()
	if gerr := e.requireStoppedUTM(ctx, utmctlPath, target); gerr != nil {
		return gerr
	}
	name := meta.resolveName()

	e.taskProgress(task, 20, "taking_snapshot")
	if meta.Quiesce {
		out.Write("stdout", "quiesce has no channel on utm — skipped\n")
	}
	if meta.Live {
		out.Write("stdout", "live snapshots do not exist on utm (qemu-img is offline) — skipped\n")
	}
	if meta.Description != "" {
		out.Write("stdout", "utm snapshots carry no description — skipped\n")
	}
	out.Write("stdout", "Taking snapshot "+name+" of "+machine.Name+" (qemu-img snapshot -c)\n")
	if serr := utm.CreateSnapshot(ctx, target, name); serr != nil {
		out.Write("stderr", "Snapshot failed: "+serr.Error()+"\n")
		return serr
	}
	out.Write("stdout", "Snapshot "+name+" taken\n")

	if meta.Prefix != "" && (meta.Retention > 0 || meta.MaxAgeDays > 0) {
		e.taskProgress(task, 90, "pruning_snapshots")
		e.pruneSnapshots(meta.Prefix, meta.Retention, meta.MaxAgeDays,
			func() ([]string, error) { return utm.ListSnapshots(ctx, target) },
			func(snapshot string) error { return utm.DeleteSnapshot(ctx, target, snapshot) },
			out)
	}
	e.taskProgress(task, 100, "completed")
	return nil
}

// freezeGuest runs qga guest-fsfreeze-freeze before a snapshot and returns
// the thaw (always safe to call) — application-consistent when the guest
// agent answers; any failure narrates and the snapshot proceeds
// crash-consistent, never blocking (zoneweaver's freezeGuest contract).
func (e *executors) freezeGuest(ctx context.Context, machine *Machine, vboxExe string,
	out *tasks.OutputWriter,
) func() {
	noop := func() {}
	if !e.env.GuestAgentEnabled {
		return noop
	}
	if info, ierr := vbox.ShowVMInfo(ctx, vboxExe, machine.VBoxTarget()); ierr != nil ||
		MapVBoxState(info.State) != StatusRunning {
		return noop
	}
	workdir := e.machineWorkdir(machine.Name)
	if machine.Home != nil && *machine.Home != "" {
		workdir = *machine.Home
	}
	pipe := qga.PipePath(workdir, machine.Name)
	freezeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, ferr := qga.Do(freezeCtx, pipe, "guest-fsfreeze-freeze", nil); ferr != nil {
		out.Write("stdout", "Guest agent fsfreeze unavailable ("+ferr.Error()+") — snapshot proceeds crash-consistent\n")
		return noop
	}
	out.Write("stdout", "Guest filesystems frozen (qga fsfreeze)\n")
	return func() {
		thawCtx, thawCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer thawCancel()
		if _, terr := qga.Do(thawCtx, pipe, "guest-fsfreeze-thaw", nil); terr != nil {
			out.Write("stderr", "fsfreeze thaw failed: "+terr.Error()+"\n")
			return
		}
		out.Write("stdout", "Guest filesystems thawed\n")
	}
}

// pruneSnapshots applies the rotation retention to <prefix>-* snapshots:
// keep the newest retention (0 = keep all), then drop those older than
// maxAgeDays (0 = no age limit). Names sort chronologically by construction
// (the timestamp suffix); snapshots whose suffix does not parse are left
// alone. Every deletion narrates; failures never fail the caller — on
// VirtualBox a snapshot delete is a physical disk merge, which is exactly
// why the defaults keep so few. The list/delete primitives are the callers'
// (per-hypervisor); the rotation logic is shared.
func (e *executors) pruneSnapshots(prefix string, retention, maxAgeDays int,
	listNames func() ([]string, error), deleteSnapshot func(string) error,
	out *tasks.OutputWriter,
) {
	names, err := listNames()
	if err != nil {
		out.Write("stderr", "Snapshot prune skipped — list failed: "+err.Error()+"\n")
		return
	}
	matching := []string{}
	for _, name := range names {
		if strings.HasPrefix(name, prefix+"-") {
			matching = append(matching, name)
		}
	}
	sort.Strings(matching)

	remove := func(name, reason string) {
		out.Write("stdout", "Pruning "+name+" ("+reason+")\n")
		if derr := deleteSnapshot(name); derr != nil {
			out.Write("stderr", name+": "+derr.Error()+"\n")
		}
	}
	if retention > 0 && len(matching) > retention {
		for _, name := range matching[:len(matching)-retention] {
			remove(name, "retention")
		}
		matching = matching[len(matching)-retention:]
	}
	if maxAgeDays > 0 {
		cutoff := time.Now().AddDate(0, 0, -maxAgeDays)
		for _, name := range matching {
			stamp, perr := time.ParseInLocation(snapshotTimestampLayout,
				strings.TrimPrefix(name, prefix+"-"), time.Local)
			if perr != nil {
				continue
			}
			if stamp.Before(cutoff) {
				remove(name, "aged out")
			}
		}
	}
}

// snapshotRestore executes snapshot_restore. VirtualBox refuses restores on a
// running machine — refused here with a clear message instead of the raw
// VBoxManage error (the modify executor's rule).
func (e *executors) snapshotRestore(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	if e.dispatchUTM(ctx, task) {
		return e.snapshotRestoreUTM(ctx, task, out)
	}
	machine, vboxExe, err := e.resolve(ctx, task)
	if err != nil {
		return err
	}
	meta, err := readSnapshotMetadata(task, false)
	if err != nil {
		return err
	}
	defer e.refreshStatus(machine.Name, vboxExe)

	target := machine.VBoxTarget()
	if info, ierr := vbox.ShowVMInfo(ctx, vboxExe, target); ierr == nil &&
		MapVBoxState(info.State) == StatusRunning {
		return errors.New("machine is running — VirtualBox only restores snapshots on powered-off machines; stop it first")
	}

	out.Write("stdout", "Restoring "+machine.Name+" to snapshot "+meta.SnapshotName+"\n")
	if serr := vbox.RestoreSnapshot(ctx, vboxExe, target, meta.SnapshotName); serr != nil {
		out.Write("stderr", "Restore failed: "+serr.Error()+"\n")
		return serr
	}
	e.syncLiveConfiguration(ctx, machine.Name, vboxExe, target, out)
	out.Write("stdout", "Machine restored to "+meta.SnapshotName+"\n")
	return nil
}

// snapshotRestoreUTM applies a snapshot to a stopped utm machine
// (qemu-img snapshot -a).
func (e *executors) snapshotRestoreUTM(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	machine, utmctlPath, err := e.resolveUTM(ctx, task)
	if err != nil {
		return err
	}
	meta, err := readSnapshotMetadata(task, false)
	if err != nil {
		return err
	}
	target := machine.VBoxTarget()
	if gerr := e.requireStoppedUTM(ctx, utmctlPath, target); gerr != nil {
		return gerr
	}
	out.Write("stdout", "Restoring "+machine.Name+" to snapshot "+meta.SnapshotName+" (qemu-img snapshot -a)\n")
	if serr := utm.RestoreSnapshot(ctx, target, meta.SnapshotName); serr != nil {
		out.Write("stderr", "Restore failed: "+serr.Error()+"\n")
		return serr
	}
	out.Write("stdout", "Machine restored to "+meta.SnapshotName+"\n")
	return nil
}

// snapshotDelete executes snapshot_delete (state merges into children).
func (e *executors) snapshotDelete(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	if e.dispatchUTM(ctx, task) {
		return e.snapshotDeleteUTM(ctx, task, out)
	}
	machine, vboxExe, err := e.resolve(ctx, task)
	if err != nil {
		return err
	}
	meta, err := readSnapshotMetadata(task, false)
	if err != nil {
		return err
	}
	out.Write("stdout", "Deleting snapshot "+meta.SnapshotName+" of "+machine.Name+"\n")
	if serr := vbox.DeleteSnapshot(ctx, vboxExe, machine.VBoxTarget(), meta.SnapshotName); serr != nil {
		out.Write("stderr", "Snapshot delete failed: "+serr.Error()+"\n")
		return serr
	}
	out.Write("stdout", "Snapshot "+meta.SnapshotName+" deleted\n")
	return nil
}

// snapshotDeleteUTM removes a snapshot from a stopped utm machine
// (qemu-img snapshot -d).
func (e *executors) snapshotDeleteUTM(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	machine, utmctlPath, err := e.resolveUTM(ctx, task)
	if err != nil {
		return err
	}
	meta, err := readSnapshotMetadata(task, false)
	if err != nil {
		return err
	}
	target := machine.VBoxTarget()
	if gerr := e.requireStoppedUTM(ctx, utmctlPath, target); gerr != nil {
		return gerr
	}
	out.Write("stdout", "Deleting snapshot "+meta.SnapshotName+" of "+machine.Name+" (qemu-img snapshot -d)\n")
	if serr := utm.DeleteSnapshot(ctx, target, meta.SnapshotName); serr != nil {
		out.Write("stderr", "Snapshot delete failed: "+serr.Error()+"\n")
		return serr
	}
	out.Write("stdout", "Snapshot "+meta.SnapshotName+" deleted\n")
	return nil
}

// snapshotModifyMetadata is snapshot_modify's metadata document. Pointers
// distinguish absent from empty (zoneweaver's converged rule 2026-07-17):
// a nil field is untouched, a non-nil empty Description CLEARS the text.
type snapshotModifyMetadata struct {
	SnapshotName string  `json:"snapshot_name"`
	NewName      *string `json:"new_name,omitempty"`
	Description  *string `json:"description,omitempty"`
}

// snapshotModify executes snapshot_modify (`VBoxManage snapshot edit`):
// rename and/or description rewrite. Rename collisions and unknown snapshots
// surface as VBoxManage's own error, honestly.
func (e *executors) snapshotModify(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	if e.dispatchUTM(ctx, task) {
		return errors.New("snapshot modify is not supported on utm machines (qemu-img cannot rename)")
	}
	machine, vboxExe, err := e.resolve(ctx, task)
	if err != nil {
		return err
	}
	if len(task.Metadata) == 0 {
		return errors.New("snapshot task has no metadata")
	}
	var meta snapshotModifyMetadata
	if uerr := json.Unmarshal(task.Metadata, &meta); uerr != nil {
		return fmt.Errorf("parse snapshot metadata: %w", uerr)
	}
	if meta.SnapshotName == "" {
		return errors.New("snapshot task metadata has no snapshot_name")
	}
	if meta.NewName == nil && meta.Description == nil {
		return errors.New("snapshot modify metadata has neither new_name nor description")
	}

	changes := []string{}
	if meta.NewName != nil {
		changes = append(changes, "rename → "+*meta.NewName)
	}
	if meta.Description != nil {
		if *meta.Description == "" {
			changes = append(changes, "clear description")
		} else {
			changes = append(changes, "set description")
		}
	}
	out.Write("stdout", "Modifying snapshot "+meta.SnapshotName+" of "+machine.Name+
		" ("+strings.Join(changes, ", ")+")\n")
	if serr := vbox.SnapshotEdit(ctx, vboxExe, machine.VBoxTarget(),
		meta.SnapshotName, meta.NewName, meta.Description); serr != nil {
		out.Write("stderr", "Snapshot modify failed: "+serr.Error()+"\n")
		return serr
	}
	out.Write("stdout", "Snapshot "+meta.SnapshotName+" modified\n")
	return nil
}
