package machines

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

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
	OpCloneCurrent    = "machine_clone_current"
)

// snapshotMetadata is the snapshot tasks' metadata document.
type snapshotMetadata struct {
	SnapshotName string `json:"snapshot_name"`
	Description  string `json:"description,omitempty"`
	// Live takes the snapshot without pausing a running machine (--live).
	Live bool `json:"live,omitempty"`
}

// readSnapshotMetadata parses a snapshot task's metadata.
func readSnapshotMetadata(task *tasks.Task) (*snapshotMetadata, error) {
	if task.Metadata == nil {
		return nil, errors.New("snapshot task has no metadata")
	}
	var meta snapshotMetadata
	if err := json.Unmarshal([]byte(*task.Metadata), &meta); err != nil {
		return nil, fmt.Errorf("parse snapshot metadata: %w", err)
	}
	if meta.SnapshotName == "" {
		return nil, errors.New("snapshot task metadata has no snapshot_name")
	}
	return &meta, nil
}

// snapshotTake executes snapshot_take (`VBoxManage snapshot take`).
func (e *executors) snapshotTake(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	machine, vboxExe, err := e.resolve(ctx, task)
	if err != nil {
		return err
	}
	meta, err := readSnapshotMetadata(task)
	if err != nil {
		return err
	}
	out.Write("stdout", "Taking snapshot "+meta.SnapshotName+" of "+machine.Name+"\n")
	if serr := vbox.TakeSnapshot(ctx, vboxExe, machine.VBoxTarget(),
		meta.SnapshotName, meta.Description, meta.Live); serr != nil {
		out.Write("stderr", "Snapshot failed: "+serr.Error()+"\n")
		return serr
	}
	out.Write("stdout", "Snapshot "+meta.SnapshotName+" taken\n")
	return nil
}

// snapshotRestore executes snapshot_restore. VirtualBox refuses restores on a
// running machine — refused here with a clear message instead of the raw
// VBoxManage error (the modify executor's rule).
func (e *executors) snapshotRestore(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	machine, vboxExe, err := e.resolve(ctx, task)
	if err != nil {
		return err
	}
	meta, err := readSnapshotMetadata(task)
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
	meta, err := readSnapshotMetadata(task)
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
