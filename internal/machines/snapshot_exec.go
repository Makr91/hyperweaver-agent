package machines

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/qga"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
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
	if task.Metadata == nil {
		return nil, errors.New("snapshot task has no metadata")
	}
	var meta snapshotMetadata
	if err := json.Unmarshal([]byte(*task.Metadata), &meta); err != nil {
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

// snapshotTake executes snapshot_take (`VBoxManage snapshot take`): quiesce →
// take → retention/age prune (prefix-scoped, exactly zoneweaver's semantics).
func (e *executors) snapshotTake(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	machine, vboxExe, err := e.resolve(ctx, task)
	if err != nil {
		return err
	}
	meta, err := readSnapshotMetadata(task, true)
	if err != nil {
		return err
	}
	name := meta.SnapshotName
	if name == "" {
		name = meta.Prefix + "-" + time.Now().Format(snapshotTimestampLayout)
	}

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
		e.pruneSnapshots(ctx, vboxExe, machine.VBoxTarget(), meta.Prefix,
			meta.Retention, meta.MaxAgeDays, out)
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
// why the defaults keep so few.
func (e *executors) pruneSnapshots(ctx context.Context, vboxExe, target, prefix string,
	retention, maxAgeDays int, out *tasks.OutputWriter,
) {
	list, err := vbox.ListSnapshots(ctx, vboxExe, target)
	if err != nil {
		out.Write("stderr", "Snapshot prune skipped — list failed: "+err.Error()+"\n")
		return
	}
	matching := []string{}
	for i := range list {
		if strings.HasPrefix(list[i].Name, prefix+"-") {
			matching = append(matching, list[i].Name)
		}
	}
	sort.Strings(matching)

	remove := func(name, reason string) {
		out.Write("stdout", "Pruning "+name+" ("+reason+")\n")
		if derr := vbox.DeleteSnapshot(ctx, vboxExe, target, name); derr != nil {
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

// snapshotDelete executes snapshot_delete (state merges into children).
func (e *executors) snapshotDelete(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
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
	machine, vboxExe, err := e.resolve(ctx, task)
	if err != nil {
		return err
	}
	if task.Metadata == nil {
		return errors.New("snapshot task has no metadata")
	}
	var meta snapshotModifyMetadata
	if uerr := json.Unmarshal([]byte(*task.Metadata), &meta); uerr != nil {
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

// cloneCurrentMetadata is machine_clone_current's metadata: the SOURCE machine
// plus the identity-stripped spec the clone row stores (the handler strips
// server_id/consoleport/macs/addressing exactly like the spec-rebuild clone).
type cloneCurrentMetadata struct {
	Source string `json:"source"`
	Spec   *Spec  `json:"spec"`
	// Snapshot names a source snapshot to clone from ("" = current state).
	Snapshot string `json:"snapshot,omitempty"`
	// Linked makes a differencing clone against Snapshot instead of a full
	// copy (VirtualBox requires a snapshot for linked clones).
	Linked bool `json:"linked,omitempty"`
}

// cloneCurrent executes machine_clone_current: `VBoxManage clonevm` copies
// the source's CURRENT disk state (the base's clone semantics — its ZFS
// snapshot copy), then the clone's identity is fixed up: fresh NAT ssh
// port-forward (the copied rule would collide with the source's host port),
// VRDE off (consoleport was stripped), and the registry row lands with the
// stripped spec. The task's MachineName is the CLONE.
func (e *executors) cloneCurrent(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	if task.Metadata == nil {
		return errors.New("clone task has no metadata")
	}
	var meta cloneCurrentMetadata
	if err := json.Unmarshal([]byte(*task.Metadata), &meta); err != nil {
		return fmt.Errorf("parse clone metadata: %w", err)
	}
	if meta.Source == "" || meta.Spec == nil {
		return errors.New("clone task metadata needs source and spec")
	}
	vboxExe := VBoxManagePath(ctx)
	if vboxExe == "" {
		return errors.New("VirtualBox is not installed")
	}

	source, err := e.store.Get(ctx, meta.Source)
	if err != nil {
		return fmt.Errorf("source machine %s: %w", meta.Source, err)
	}
	sourceTarget := source.VBoxTarget()
	info, err := vbox.ShowVMInfo(ctx, vboxExe, sourceTarget)
	if err != nil {
		return fmt.Errorf("source machine %s has no VM to clone: %w", meta.Source, err)
	}
	if meta.Snapshot == "" && MapVBoxState(info.State) == StatusRunning {
		return errors.New("source machine is running — stop it, or clone from a snapshot (snapshot parameter)")
	}

	e.taskProgress(task, 10, "cloning_vm")
	out.Write("stdout", "Cloning "+meta.Source+" → "+task.MachineName+" (VBoxManage clonevm — current state)\n")
	if cerr := vbox.CloneVM(ctx, vboxExe, sourceTarget, task.MachineName,
		e.env.MachinesDir, meta.Snapshot, meta.Linked); cerr != nil {
		return cerr
	}
	cleanup := func(step string, ferr error) error {
		out.Write("stderr", step+" failed — unregistering the half-made clone\n")
		if uerr := vbox.UnregisterVM(ctx, vboxExe, task.MachineName, true); uerr != nil {
			out.Write("stderr", "Unregister failed: "+uerr.Error()+"\n")
		}
		return ferr
	}

	cloneInfo, err := vbox.ShowVMInfo(ctx, vboxExe, task.MachineName)
	if err != nil {
		return cleanup("clone inspection", err)
	}

	// Clones are DATA-COMPLETE (Mark's ruling, sync 2026-07-18): clonevm
	// copied every attached disk into the clone's own folder — those copies
	// are the clone's OWN media and stamp "clone" so delete destroys them.
	// Anything outside the clone folder (referenced ISOs, shared media) stays
	// unstamped/foreign. Stamp failures narrate — an unstamped copy is merely
	// preserved at delete, never destroyed wrongly.
	e.taskProgress(task, 40, "stamping_media")
	clonePrefix := strings.ToLower(filepath.Clean(cloneInfo.Home)) + string(filepath.Separator)
	for key, value := range cloneInfo.Raw {
		if value == "none" || value == "emptydrive" || value == "" {
			continue
		}
		if attachmentPattern.FindStringSubmatch(key) == nil || strings.Contains(key, "ImageUUID") {
			continue
		}
		if !filepath.IsAbs(value) ||
			!strings.HasPrefix(strings.ToLower(filepath.Clean(value)), clonePrefix) {
			continue
		}
		if perr := stampMedium(ctx, vboxExe, value, "clone", out); perr != nil {
			out.Write("stderr", "Stamping "+value+" failed (preserved at delete): "+perr.Error()+"\n")
		} else {
			out.Write("stdout", "Stamped clone medium "+value+"\n")
		}
	}

	// Fresh provisioning transport: the copied natpf1 ssh rule carries the
	// SOURCE's host port — delete it and forward a newly allocated one.
	e.taskProgress(task, 50, "fixing_identity")
	sshPort, perr := allocateLocalPort(ctx)
	if perr != nil {
		return cleanup("ssh port-forward allocation", perr)
	}
	if derr := vbox.ModifyVM(ctx, vboxExe, task.MachineName,
		[]string{"--natpf1", "delete", "ssh"}); derr != nil {
		out.Write("stderr", "No copied ssh forward to delete (continuing): "+derr.Error()+"\n")
	}
	flags := []string{
		fmt.Sprintf("--natpf1=ssh,tcp,127.0.0.1,%d,,22", sshPort),
		// consoleport was stripped from the spec — the copied VRDE port would
		// collide with the source's; the user re-enables via modify.
		"--vrde=off",
	}
	if merr := vbox.ModifyVM(ctx, vboxExe, task.MachineName, flags); merr != nil {
		return cleanup("clone identity fix-up", merr)
	}
	out.Write("stdout", fmt.Sprintf("Provisioning SSH port-forward: 127.0.0.1:%d → guest 22\n", sshPort))

	e.taskProgress(task, 80, "creating_database_record")
	rawSpec, err := json.Marshal(meta.Spec)
	if err != nil {
		return cleanup("spec serialization", err)
	}
	serverID := ""
	if meta.Spec.Settings != nil {
		serverID = stringOr(meta.Spec.Settings["server_id"], "")
	}
	if _, cerr := e.store.Create(ctx, &NewMachine{
		Name:     task.MachineName,
		Host:     source.Host,
		Home:     cloneInfo.Home,
		ServerID: serverID,
		Spec:     rawSpec,
	}); cerr != nil {
		return cleanup("create machine row", cerr)
	}
	if cloneInfo.UUID != "" {
		if uerr := e.store.SetUUID(ctx, task.MachineName, cloneInfo.UUID); uerr != nil {
			return uerr
		}
	}
	e.syncLiveConfiguration(ctx, task.MachineName, vboxExe, task.MachineName, out)
	e.refreshStatus(task.MachineName, vboxExe)

	e.taskProgress(task, 100, "completed")
	out.Write("stdout", "Machine "+task.MachineName+" cloned from "+meta.Source+" (current state)\n")
	return nil
}
