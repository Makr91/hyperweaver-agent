package machines

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/utm"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// Machine lifecycle operations (task queue vocabulary). Lifecycle is native
// VBoxManage for every machine (the zoneweaver model — the agent drives the
// hypervisor and the guest itself; vagrant/Hosts.rb are never executed). The
// machine_create_*/machine_* provisioning operations are the orchestration
// children of the create and provision chains.
const (
	OpStart    = "start"
	OpStop     = "stop"
	OpRestart  = "restart" // never dispatched: a restart is a stop→start chain
	OpSuspend  = "suspend"
	OpReset    = "reset"  // controlvm reset — the hard reboot VirtualBox offers beyond the stop→start chain
	OpPause    = "pause"  // controlvm pause
	OpResume   = "resume" // controlvm resume
	OpDelete   = "delete"
	OpDiscover = "discover"
	OpPrepare  = "machine_prepare"
)

// stopMetadata is the stop/delete task metadata document.
type stopMetadata struct {
	Force bool `json:"force"`
}

// deleteMetadata is the delete task's metadata document. CleanupDisks is the
// base's cleanup_datasets translated: false unregisters the VM but leaves
// every medium file (and the working directory holding them) on disk.
type deleteMetadata struct {
	CleanupDisks bool `json:"cleanup_disks"`
}

// RegisterExecutors wires the machine operations into the task queue:
// lifecycle, the create-orchestration children, the provision-pipeline
// children, and the template download.
func RegisterExecutors(queue *tasks.Queue, store *Store, reconciler *Reconciler, shutdownTimeout time.Duration, env *ProvisionEnv) {
	e := &executors{
		queue:           queue,
		store:           store,
		reconciler:      reconciler,
		shutdownTimeout: shutdownTimeout,
		env:             env,
	}
	queue.Register(OpStart, tasks.Executor{Run: e.start, OnCancel: e.cancelStart})
	queue.Register(OpStop, tasks.Executor{Run: e.stop})
	queue.Register(OpSuspend, tasks.Executor{Run: e.suspend})
	queue.Register(OpReset, tasks.Executor{Run: e.controlAction(OpReset, "reset")})
	queue.Register(OpPause, tasks.Executor{Run: e.controlAction(OpPause, "pause")})
	queue.Register(OpResume, tasks.Executor{Run: e.controlAction(OpResume, "resume")})
	queue.Register(OpDelete, tasks.Executor{Run: e.deleteMachine})
	queue.Register(OpDiscover, tasks.Executor{Run: e.discover})
	queue.Register(OpImport, tasks.Executor{Run: e.importAppliance})
	queue.Register(OpMove, tasks.Executor{Run: e.moveMachine})
	queue.Register(OpUnattended, tasks.Executor{Run: e.unattendedInstall})

	// Snapshot family + current-state clone (VBoxManage snapshot/clonevm —
	// yardstick 2: the whole hypervisor surface, policy-free).
	queue.Register(OpSnapshotTake, tasks.Executor{Run: e.snapshotTake})
	queue.Register(OpSnapshotRestore, tasks.Executor{Run: e.snapshotRestore})
	queue.Register(OpSnapshotDelete, tasks.Executor{Run: e.snapshotDelete})
	queue.Register(OpSnapshotModify, tasks.Executor{Run: e.snapshotModify})
	queue.Register(OpCloneCurrent, tasks.Executor{Run: e.cloneCurrent})
	queue.Register(OpTemplateDelete, tasks.Executor{Run: e.templateDelete})
	queue.Register(OpTemplateExport, tasks.Executor{Run: e.templateExport})
	queue.Register(OpTemplatePublish, tasks.Executor{Run: e.templatePublish})
	queue.Register(OpTemplateMove, tasks.Executor{Run: e.templateMove})
	// machine_modify — the base's zone_modify (TASK_OBJECT_OPERATIONS +
	// zone_lifecycle category). Its serialization guard here is the queue's
	// one-running-task-per-machine rule, so it stays category-unmapped.
	queue.Register(OpModify, tasks.Executor{Run: e.modifyMachine})

	// Create-orchestration children (storage/config carry post-kill cleanup:
	// a cancellation mid-clone or mid-configure must not leave debris).
	queue.Register(OpPrepare, tasks.Executor{Run: e.prepareDocument})
	queue.Register(OpCreateStorage, tasks.Executor{Run: e.createStorage, OnCancel: e.cancelCreateStorage})
	queue.Register(OpCreateConfig, tasks.Executor{Run: e.createConfig, OnCancel: e.cancelCreateConfig})
	queue.Register(OpCreateFinalize, tasks.Executor{Run: e.createFinalize})
	queue.Register(OpTemplateDownload, tasks.Executor{Run: e.templateDownload})

	// Provisioning-network backbone (the base's setup/teardown operations,
	// category-locked like its network_provisioning family).
	queue.Register(OpNetworkSetup, tasks.Executor{Run: e.networkSetup})
	queue.Register(OpNetworkTeardown, tasks.Executor{Run: e.networkTeardown})

	// Provision-chain children — the ONE document walk (Mark's ruling
	// 2026-07-17: there are no phases): the stored provisioning: section's
	// methods and hooks chain directly under the orchestration parent in
	// document order; sync/syncback keep their sub-parents as the walk's
	// outer brackets.
	queue.Register(OpWaitSSH, tasks.Executor{Run: e.waitSSH})
	queue.Register(OpSyncParent, tasks.Executor{Run: e.parentAnchor})
	queue.Register(OpSyncFolder, tasks.Executor{Run: e.syncFolder})
	queue.Register(OpShellScript, tasks.Executor{Run: e.runShellScript})
	// OpProvisionParent survives ONLY as the /run-provisioners anchor.
	queue.Register(OpProvisionParent, tasks.Executor{Run: e.parentAnchor})
	queue.Register(OpProvisionPlaybook, tasks.Executor{Run: e.provisionPlaybook})
	// local/remote is an entry's execution MECHANISM (in-guest ansible vs
	// ansible-playbook on the agent host), never a phase.
	queue.Register(OpRemotePlaybook, tasks.Executor{Run: e.runRemotePlaybook})
	queue.Register(OpDockerCompose, tasks.Executor{Run: e.dockerCompose})
	// Sequence hooks (provisioning.pre[]/post[]) — ONE operation; the entry's
	// own target picks guest or host.
	queue.Register(OpHook, tasks.Executor{Run: e.runHook})
	// Syncback (folders[].syncback — guest→host pulls, the walk's closing
	// bracket by document structure, and ad-hoc via POST
	// /machines/{name}/sync {"syncback": true}).
	queue.Register(OpSyncbackParent, tasks.Executor{Run: e.parentAnchor})
	queue.Register(OpSyncbackFolder, tasks.Executor{Run: e.syncbackFolder})
	// Key rotation (machine_key_rotate — key_rotate proposal, sync
	// 2026-07-17): after the syncback bracket, adopt the box's rotated
	// private key into the working copy; never the whole-walk stamp owner.
	queue.Register(OpKeyRotate, tasks.Executor{Run: e.keyRotate})
	// Transport removal (machine_transport_remove — the remove-on-completion
	// flag, converged sync 2026-07-18): between the pipeline-owned stop and
	// boot after the whole-walk stamp, remove the flagged adapters and update
	// the document to match.
	queue.Register(OpTransportRemove, tasks.Executor{Run: e.transportRemove})
}

type executors struct {
	queue           *tasks.Queue
	store           *Store
	reconciler      *Reconciler
	shutdownTimeout time.Duration
	env             *ProvisionEnv
}

// resolve loads the machine a task targets and the VBoxManage path.
func (e *executors) resolve(ctx context.Context, task *tasks.Task) (*Machine, string, error) {
	machine, err := e.store.Get(ctx, task.MachineName)
	if err != nil {
		return nil, "", fmt.Errorf("machine %s: %w", task.MachineName, err)
	}
	exe := VBoxManagePath(ctx)
	if exe == "" {
		return nil, "", errors.New("VirtualBox is not installed")
	}
	return machine, exe, nil
}

// resolveUTM is resolve's utm sibling: the machine plus the utmctl path.
func (e *executors) resolveUTM(ctx context.Context, task *tasks.Task) (*Machine, string, error) {
	machine, err := e.store.Get(ctx, task.MachineName)
	if err != nil {
		return nil, "", fmt.Errorf("machine %s: %w", task.MachineName, err)
	}
	exe := UTMCtlPath(ctx)
	if exe == "" {
		return nil, "", errors.New("UTM is not installed")
	}
	return machine, exe, nil
}

// dispatchUTM reports whether the task's machine row carries the utm
// hypervisor — the branch key every lifecycle executor checks before its
// VBox flow. Load errors answer false: the flow's own resolve reports them.
func (e *executors) dispatchUTM(ctx context.Context, task *tasks.Task) bool {
	machine, err := e.store.Get(ctx, task.MachineName)
	return err == nil && machine.Hypervisor == HypervisorUTM
}

// refreshStatus records the machine's live state after an operation. The row
// is reloaded first so the freshest UUID addresses the VM.
func (e *executors) refreshStatus(name, vboxExe string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	machine, err := e.store.Get(ctx, name)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			mlog().Error("reload machine for refresh", "machine", name, "error", err)
		}
		return
	}
	info, err := vbox.ShowVMInfo(ctx, vboxExe, machine.VBoxTarget())
	if errors.Is(err, vbox.ErrNotFound) {
		// No VM behind a UUID-less row is its normal configured state, not
		// an orphan (MarkMissing's rule).
		if machine.UUID == nil {
			return
		}
		if serr := e.store.SetOrphaned(ctx, name, true); serr != nil &&
			!errors.Is(serr, ErrNotFound) {
			mlog().Error("record machine orphaned", "machine", name, "error", serr)
		}
		return
	}
	if err != nil {
		mlog().Warn("refresh machine status failed", "machine", name, "error", err)
		return
	}
	if serr := e.store.SetStatus(ctx, name, MapVBoxState(info.State)); serr != nil {
		mlog().Error("record machine status", "machine", name, "error", serr)
	}
}

// refreshStatusUTM is refreshStatus's utm twin. utmctl's not-found text is
// unmapped, so ANY status failure on a UUID-carrying row flags orphan — the
// sweep self-heals false positives.
func (e *executors) refreshStatusUTM(name, utmctlPath string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	machine, err := e.store.Get(ctx, name)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			mlog().Error("reload machine for refresh", "machine", name, "error", err)
		}
		return
	}
	status, err := utm.Status(ctx, utmctlPath, machine.VBoxTarget())
	if err != nil {
		// No VM behind a UUID-less row is its normal configured state, not
		// an orphan (MarkMissing's rule).
		if machine.UUID == nil {
			return
		}
		if serr := e.store.SetOrphaned(ctx, name, true); serr != nil &&
			!errors.Is(serr, ErrNotFound) {
			mlog().Error("record machine orphaned", "machine", name, "error", serr)
		}
		return
	}
	if serr := e.store.SetStatus(ctx, name, utm.MapUTMState(status)); serr != nil {
		mlog().Error("record machine status", "machine", name, "error", serr)
	}
}
