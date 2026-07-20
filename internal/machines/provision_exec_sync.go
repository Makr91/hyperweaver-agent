package machines

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/sshrun"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// syncFolder executes machine_sync — ONE folder (executeZoneSyncTask 1:1):
// skip disabled/virtualbox entries, resolve a relative map against the
// working directory, pre-create the destination, transport over the folder's
// ladder (runFolderTransport — binary rsync/scp with pure-Go fallbacks),
// chown to owner:group after.
func (e *executors) syncFolder(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	meta, err := readProvisionMetadata(task)
	if err != nil {
		return err
	}
	if meta.Folder == nil {
		return errors.New("folder is required in task metadata")
	}
	folder := meta.Folder
	if folder.Disabled {
		out.Write("stdout", "Folder sync skipped (disabled)\n")
		// A disabled folder can still be the walk's final task — its skip is
		// a success, so the whole-walk stamp must not be lost with it.
		e.stampIfFinal(task, meta, out)
		return nil
	}
	if folder.Map == "" || folder.To == "" {
		return errors.New("folder missing source (map) or destination (to)")
	}
	if strings.EqualFold(folder.Type, "virtualbox") {
		return e.attachSharedFolder(ctx, task, meta, folder, out)
	}

	workdir := e.machineWorkdir(task.MachineName)
	source := folder.Map
	if !strings.HasPrefix(source, "/") && !strings.Contains(source, ":") {
		source = workdir + "/" + strings.TrimPrefix(strings.TrimPrefix(source, "./"), ".")
	}

	e.taskProgress(task, 10, "creating_destination")
	out.Write("stdout", "Syncing "+source+" → "+folder.To+" ("+transportFor(folder)+")\n")
	if rerr := sshrun.Run(ctx, meta.IP, meta.Port, meta.Credentials,
		"sudo mkdir -p "+folder.To, workdir, e.env.ProvisionKeyPath, time.Minute, out.Write); rerr != nil {
		return fmt.Errorf("pre-create %s: %w", folder.To, rerr)
	}

	e.taskProgress(task, 30, "syncing_files")
	if terr := e.runFolderTransport(ctx, meta, folder, source, workdir, out); terr != nil {
		return terr
	}

	e.taskProgress(task, 85, "setting_ownership")
	owner := folder.Owner
	if owner == "" {
		owner = meta.Credentials.Username
	}
	if owner == "" {
		owner = "root"
	}
	group := folder.Group
	if group == "" {
		group = owner
	}
	if cerr := sshrun.Run(ctx, meta.IP, meta.Port, meta.Credentials,
		"sudo chown -R "+owner+":"+group+" "+folder.To,
		workdir, e.env.ProvisionKeyPath, time.Minute, out.Write); cerr != nil {
		out.Write("stderr", "chown "+folder.To+" failed: "+cerr.Error()+"\n")
	}
	e.stampIfFinal(task, meta, out)
	e.taskProgress(task, 100, "completed")
	return nil
}

// attachSharedFolder lands a `type: virtualbox` folder as a REAL VirtualBox
// shared folder (Mark's go 2026-07-12 — these were skipped before): register
// on the VM (hot-add works while running; already-registered narrates as the
// idempotent re-sync), then mount in the guest — vboxsf needs Guest
// Additions, so a mount failure narrates the automount fallback instead of
// failing the pipeline.
func (e *executors) attachSharedFolder(ctx context.Context, task *tasks.Task,
	meta *provisionTaskMetadata, folder *Folder, out *tasks.OutputWriter,
) error {
	machine, vboxExe, err := e.resolve(ctx, task)
	if err != nil {
		return err
	}
	hostPath := filepath.FromSlash(folder.Map)
	if !filepath.IsAbs(hostPath) {
		hostPath = filepath.Join(e.machineWorkdir(task.MachineName),
			strings.TrimPrefix(strings.TrimPrefix(folder.Map, "./"), "."))
	}
	shareName := sharedFolderName(folder.To)

	e.taskProgress(task, 20, "registering_shared_folder")
	out.Write("stdout", "Registering VirtualBox shared folder "+shareName+" ("+hostPath+" → "+folder.To+")\n")
	if aerr := vbox.SharedFolderAdd(ctx, vboxExe, machine.VBoxTarget(), shareName, hostPath, folder.To); aerr != nil {
		if !strings.Contains(aerr.Error(), "already exists") {
			return aerr
		}
		out.Write("stdout", "Shared folder already registered — continuing\n")
	}

	// Guest mount (vagrant's model): skipped when automount already landed it.
	owner := folder.Owner
	if owner == "" {
		owner = meta.Credentials.Username
	}
	if owner == "" {
		owner = "root"
	}
	group := folder.Group
	if group == "" {
		group = owner
	}
	e.taskProgress(task, 60, "mounting_in_guest")
	mount := fmt.Sprintf(
		"sudo mkdir -p %s && (mount | grep -q ' %s ' || sudo mount -t vboxsf -o uid=$(id -u %s),gid=$(getent group %s | cut -d: -f3) %s %s)",
		folder.To, folder.To, owner, group, shareName, folder.To)
	if merr := sshrun.Run(ctx, meta.IP, meta.Port, meta.Credentials, mount,
		e.machineWorkdir(task.MachineName), e.env.ProvisionKeyPath, time.Minute, out.Write); merr != nil {
		out.Write("stderr", "Guest mount failed ("+merr.Error()+") — vboxsf needs Guest Additions; the automount lands it at "+folder.To+" when they run\n")
	} else {
		out.Write("stdout", "Shared folder mounted at "+folder.To+"\n")
	}
	e.stampIfFinal(task, meta, out)
	e.taskProgress(task, 100, "completed")
	return nil
}

// sharedFolderName derives the share's registry name from the guest path
// (vagrant's rule: "/vagrant" → "vagrant").
func sharedFolderName(guestPath string) string {
	name := strings.Trim(strings.ReplaceAll(guestPath, "/", "_"), "_")
	if name == "" {
		return "shared"
	}
	return name
}

// runFolderTransport lands one folder over the transport ladder (Mark's
// vagrant-optional ruling 2026-07-07): the folder's chosen tool first — the
// runtime-proven binary path — falling to the agent's built-in pure-Go
// transports ONLY when the tool is ABSENT. A failed run stays a failure:
// silently switching transports would hide real errors.
//
//	rsync: system/vagrant rsync binary → built-in Go rsync client (the
//	       guest's own rsync serves the remote half, same as the binary path)
//	scp:   system/vagrant/Windows-OpenSSH scp binary → built-in SFTP
func (e *executors) runFolderTransport(ctx context.Context, meta *provisionTaskMetadata,
	folder *Folder, source, workdir string, out *tasks.OutputWriter,
) error {
	if transportFor(folder) == SyncSCP {
		// scp and SFTP write as the SSH user (rsync writes as root through
		// --rsync-path='sudo rsync') — hand the freshly sudo-created
		// destination to that user first; the post-sync chown still sets the
		// folder's final ownership.
		e.preChownDestination(ctx, meta, folder, workdir, out)
		if scpExe, lerr := sshrun.FindTool("scp"); lerr == nil {
			if serr := sshrun.SCPSync(ctx, scpExe, meta.IP, meta.Port, meta.Credentials,
				source, folder.To, workdir, e.env.ProvisionKeyPath, out.Write); serr != nil {
				return fmt.Errorf("%s → %s: %w", folder.Map, folder.To, serr)
			}
			return nil
		}
		out.Write("stdout", "scp binary not found on this host — using the built-in SFTP transport (pure Go, no host tools)\n")
		if serr := sshrun.SFTPSync(ctx, meta.IP, meta.Port, meta.Credentials,
			source, folder.To, workdir, e.env.ProvisionKeyPath, out.Write); serr != nil {
			return fmt.Errorf("%s → %s: %w", folder.Map, folder.To, serr)
		}
		return nil
	}

	options := &sshrun.SyncOptions{
		Args:    folder.Args,
		Exclude: folder.Exclude,
		Delete:  folder.Delete,
	}
	// PATH first, then vagrant's embedded toolchain (a vagrant install
	// carries a working rsync on every platform) — but vagrant is OPTIONAL:
	// no rsync binary anywhere drops to the embedded Go rsync client.
	if rsyncExe, lerr := sshrun.FindTool("rsync"); lerr == nil {
		if serr := sshrun.SyncFiles(ctx, rsyncExe, meta.IP, meta.Port, meta.Credentials,
			source, folder.To, workdir, e.env.ProvisionKeyPath, options, out.Write); serr != nil {
			return fmt.Errorf("%s → %s: %w", folder.Map, folder.To, serr)
		}
		return nil
	}
	out.Write("stdout", "rsync binary not found on this host — using the built-in Go rsync client (the guest's own rsync serves the remote half)\n")
	if serr := sshrun.BuiltinRsyncSync(ctx, meta.IP, meta.Port, meta.Credentials,
		source, folder.To, workdir, e.env.ProvisionKeyPath, options, out.Write); serr != nil {
		return fmt.Errorf("%s → %s: %w", folder.Map, folder.To, serr)
	}
	return nil
}

// preChownDestination hands the destination directory to the SSH user before
// a user-privileged transport writes into it (sudo mkdir -p left it
// root-owned). Failures narrate and never fail the sync — the transport's
// own error tells the real story.
func (e *executors) preChownDestination(ctx context.Context, meta *provisionTaskMetadata,
	folder *Folder, workdir string, out *tasks.OutputWriter,
) {
	owner := meta.Credentials.Username
	if owner == "" {
		owner = "root"
	}
	if cerr := sshrun.Run(ctx, meta.IP, meta.Port, meta.Credentials,
		"sudo chown -R "+owner+":"+owner+" "+folder.To,
		workdir, e.env.ProvisionKeyPath, time.Minute, out.Write); cerr != nil {
		out.Write("stderr", "pre-sync chown "+folder.To+" failed: "+cerr.Error()+"\n")
	}
}

// transportFor resolves a folder's sync transport: the folder's own type
// wins; anything not scp is rsync (the base is rsync-only; scp exists for
// Mark's broken-macOS-rsync rule and the document's per-folder choice).
func transportFor(folder *Folder) string {
	if strings.EqualFold(folder.Type, SyncSCP) {
		return SyncSCP
	}
	return SyncRsync
}
