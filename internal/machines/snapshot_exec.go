package machines

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	if len(task.Metadata) == 0 {
		return errors.New("clone task has no metadata")
	}
	var meta cloneCurrentMetadata
	if err := json.Unmarshal(task.Metadata, &meta); err != nil {
		return fmt.Errorf("parse clone metadata: %w", err)
	}
	if meta.Source == "" || meta.Spec == nil {
		return errors.New("clone task metadata needs source and spec")
	}
	// The utm branch keys on the SOURCE row's hypervisor — the clone's own row
	// does not exist yet, so dispatchUTM cannot answer here. Load errors fall
	// through: the VBox path re-loads and reports them.
	if source, serr := e.store.Get(ctx, meta.Source); serr == nil && source.Hypervisor == HypervisorUTM {
		return e.cloneCurrentUTM(ctx, task, &meta, source, out)
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

// cloneCurrentUTM is machine_clone_current's utm branch — UTM has no clonevm,
// so the copy is Export (source stopped) → Import → Customize (name + spec
// resources) → fresh MAC on NIC 0 → inherited forwards cleared and a fresh
// ssh forward on the first emulated interface → the registry row, exactly the
// VBox clone's landing (Hypervisor utm, UUID = the imported id).
func (e *executors) cloneCurrentUTM(ctx context.Context, task *tasks.Task,
	meta *cloneCurrentMetadata, source *Machine, out *tasks.OutputWriter,
) error {
	if meta.Snapshot != "" || meta.Linked {
		return errors.New("linked/snapshot clones are VirtualBox mechanisms — utm clones copy current state")
	}
	utmctlPath := UTMCtlPath(ctx)
	if utmctlPath == "" {
		return errors.New("UTM is not installed")
	}
	sourceTarget := source.VBoxTarget()
	status, err := utm.Status(ctx, utmctlPath, sourceTarget)
	if err != nil {
		return fmt.Errorf("source machine %s has no VM to clone: %w", meta.Source, err)
	}
	if utm.MapUTMState(status) != StatusStopped {
		return errors.New("source machine is " + status + " — utm export needs it stopped; stop it first")
	}

	workdir := e.machineWorkdir(task.MachineName)
	if merr := os.MkdirAll(workdir, 0o750); merr != nil {
		return merr
	}
	exportPath := filepath.Join(workdir, "clone-export.utm")

	e.taskProgress(task, 10, "exporting_source")
	out.Write("stdout", "Cloning "+meta.Source+" → "+task.MachineName+" (utm export → import — current state)\n")
	if xerr := utm.Export(ctx, sourceTarget, exportPath); xerr != nil {
		return fmt.Errorf("source export failed: %w", xerr)
	}
	defer func() {
		if rerr := os.RemoveAll(exportPath); rerr != nil {
			out.Write("stderr", "Temp export cleanup failed: "+rerr.Error()+"\n")
		}
	}()

	e.taskProgress(task, 30, "importing_clone")
	id, err := utm.Import(ctx, exportPath)
	if err != nil {
		return fmt.Errorf("clone import failed: %w", err)
	}
	cleanup := func(step string, ferr error) error {
		out.Write("stderr", step+" failed — deleting the half-made clone\n")
		if derr := utm.Delete(ctx, utmctlPath, id); derr != nil {
			out.Write("stderr", "Delete failed: "+derr.Error()+"\n")
		}
		return ferr
	}

	e.taskProgress(task, 50, "fixing_identity")
	settings := map[string]any{}
	if meta.Spec.Settings != nil {
		settings = meta.Spec.Settings
	}
	// Only spec-carried resources apply — an absent key keeps the source's
	// exported value (Customize skips zero fields).
	opts := utm.CustomizeOptions{Name: task.MachineName}
	if v, ok := settings["vcpus"]; ok {
		opts.CPUs = int(VCPUCount(v, 2))
	}
	if v, ok := settings["memory"]; ok {
		opts.MemoryMB = int(memoryToMB(v))
	}
	if cerr := utm.Customize(ctx, id, opts); cerr != nil {
		return cleanup("clone identity fix-up", cerr)
	}
	if merr := utm.SetMACAddress(ctx, id, 0, utm.RandomMAC()); merr != nil {
		return cleanup("mac address", merr)
	}

	nics, nerr := utm.ReadNetworkInterfaces(ctx, id)
	if nerr != nil {
		return cleanup("read network interfaces", nerr)
	}
	emulatedIndex := -1
	for index, mode := range nics {
		if mode == "emulated" && (emulatedIndex < 0 || index < emulatedIndex) {
			emulatedIndex = index
		}
	}
	if emulatedIndex < 0 {
		return cleanup("network interfaces",
			errors.New("clone has no emulated network interface — port forwards need one"))
	}
	// The copied forwards carry the SOURCE's host ports — clear them before
	// the fresh allocation (the VBox path's natpf1-delete rule).
	forwards, ferr := utm.ReadForwardedPorts(ctx, id)
	if ferr != nil {
		return cleanup("read forwarded ports", ferr)
	}
	stale := []int{}
	for _, fw := range forwards {
		if fw.NIC == emulatedIndex {
			stale = append(stale, fw.HostPort)
		}
	}
	if cerr := utm.ClearPortForwards(ctx, id, emulatedIndex, stale); cerr != nil {
		return cleanup("clear inherited forwards", cerr)
	}
	sshPort, perr := allocateLocalPort(ctx)
	if perr != nil {
		return cleanup("ssh port-forward allocation", perr)
	}
	if aerr := utm.AddPortForwards(ctx, id, emulatedIndex, []utm.ForwardedPort{{
		Protocol: "tcp", GuestPort: 22, HostIP: "127.0.0.1", HostPort: sshPort,
	}}); aerr != nil {
		return cleanup("ssh port-forward", aerr)
	}
	out.Write("stdout", fmt.Sprintf("Provisioning SSH port-forward: 127.0.0.1:%d → guest 22\n", sshPort))

	e.taskProgress(task, 80, "creating_database_record")
	rawSpec, err := json.Marshal(meta.Spec)
	if err != nil {
		return cleanup("spec serialization", err)
	}
	if _, cerr := e.store.Create(ctx, &NewMachine{
		Name:       task.MachineName,
		Host:       source.Host,
		Home:       workdir,
		ServerID:   stringOr(settings["server_id"], ""),
		Hypervisor: HypervisorUTM,
		Spec:       rawSpec,
	}); cerr != nil {
		return cleanup("create machine row", cerr)
	}
	if uerr := e.store.SetUUID(ctx, task.MachineName, id); uerr != nil {
		return uerr
	}
	e.refreshStatusUTM(task.MachineName, utmctlPath)

	e.taskProgress(task, 100, "completed")
	out.Write("stdout", "Machine "+task.MachineName+" cloned from "+meta.Source+" (current state)\n")
	return nil
}
