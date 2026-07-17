package machines

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/sshrun"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// The syncback executor — folders[].syncback (Mark's ruling 2026-07-12,
// replacing his Hosts.rb results hack): flagged folders pull guest→host as
// the document walk's CLOSING BRACKET by document structure (after the post
// hooks), and ad-hoc via POST /machines/{name}/sync {"syncback": true}. One folder
// per task, the exact reverse of machine_sync: guest folder.to → host
// folder.map, transport per the folder's own ladder. Two deliberate
// asymmetries against the push: folder.delete is NEVER honored (a pull must
// not delete host files) and no chown runs (pulled files stay the agent's).

// Syncback operations.
const (
	OpSyncbackParent = "machine_syncback_parent"
	OpSyncbackFolder = "machine_syncback"
)

// SyncbackFolders filters a folder set down to the guest→host pull targets:
// syncback-flagged, enabled, non-virtualbox.
func SyncbackFolders(folders []Folder) []Folder {
	kept := []Folder{}
	for i := range folders {
		if folders[i].Syncback && !folders[i].Disabled &&
			!strings.EqualFold(folders[i].Type, "virtualbox") {
			kept = append(kept, folders[i])
		}
	}
	return kept
}

// syncbackFolder executes machine_syncback — ONE folder, guest→host.
func (e *executors) syncbackFolder(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	meta, err := readProvisionMetadata(task)
	if err != nil {
		return err
	}
	if meta.Folder == nil {
		return errors.New("folder is required in task metadata")
	}
	folder := meta.Folder
	if !folder.Syncback || folder.Disabled || strings.EqualFold(folder.Type, "virtualbox") {
		out.Write("stdout", "Syncback skipped (folder is not an eligible syncback target)\n")
		return nil
	}
	if folder.Map == "" || folder.To == "" {
		return errors.New("folder missing destination (map) or source (to)")
	}

	// The host destination is the push's SOURCE resolution reversed: a
	// relative map lands under the machine's working directory.
	workdir := e.machineWorkdir(task.MachineName)
	dest := folder.Map
	if !strings.HasPrefix(dest, "/") && !strings.Contains(dest, ":") {
		dest = filepath.Join(workdir,
			filepath.FromSlash(strings.TrimPrefix(strings.TrimPrefix(dest, "./"), ".")))
	}
	if merr := os.MkdirAll(dest, 0o750); merr != nil {
		return merr
	}

	e.taskProgress(task, 20, "pulling_files")
	out.Write("stdout", "Syncing back "+folder.To+" → "+dest+" ("+transportFor(folder)+")\n")
	if folder.Delete {
		out.Write("stdout", "folder.delete is push-only — a pull never deletes host files\n")
	}
	if terr := e.runFolderPullTransport(ctx, meta, folder, dest, workdir, out); terr != nil {
		return terr
	}
	e.stampIfFinal(task, meta, out)
	e.taskProgress(task, 100, "completed")
	return nil
}

// runFolderPullTransport pulls one folder over the transport ladder — the
// push ladder's mirror (runFolderTransport): the folder's chosen tool first,
// the built-in pure-Go transports only when the tool is ABSENT. A failed run
// stays a failure.
func (e *executors) runFolderPullTransport(ctx context.Context, meta *provisionTaskMetadata,
	folder *Folder, dest, workdir string, out *tasks.OutputWriter,
) error {
	if transportFor(folder) == SyncSCP {
		if scpExe, lerr := sshrun.FindTool("scp"); lerr == nil {
			if serr := sshrun.SCPSyncPull(ctx, scpExe, meta.IP, meta.Port, meta.Credentials,
				folder.To, dest, workdir, e.env.ProvisionKeyPath, out.Write); serr != nil {
				return errors.Join(errors.New(folder.To+" → "+folder.Map), serr)
			}
			return nil
		}
		out.Write("stdout", "scp binary not found on this host — using the built-in SFTP pull (pure Go, no host tools)\n")
		if serr := sshrun.SFTPSyncPull(ctx, meta.IP, meta.Port, meta.Credentials,
			folder.To, dest, workdir, e.env.ProvisionKeyPath, out.Write); serr != nil {
			return errors.Join(errors.New(folder.To+" → "+folder.Map), serr)
		}
		return nil
	}

	options := &sshrun.SyncOptions{
		Args:    folder.Args,
		Exclude: folder.Exclude,
		// Delete deliberately unset: pull never deletes host files.
	}
	if rsyncExe, lerr := sshrun.FindTool("rsync"); lerr == nil {
		if serr := sshrun.SyncFilesPull(ctx, rsyncExe, meta.IP, meta.Port, meta.Credentials,
			folder.To, dest, workdir, e.env.ProvisionKeyPath, options, out.Write); serr != nil {
			return errors.Join(errors.New(folder.To+" → "+folder.Map), serr)
		}
		return nil
	}
	out.Write("stdout", "rsync binary not found on this host — using the built-in Go rsync pull (the guest's own rsync serves the remote half)\n")
	if serr := sshrun.BuiltinRsyncSyncPull(ctx, meta.IP, meta.Port, meta.Credentials,
		folder.To, dest, workdir, e.env.ProvisionKeyPath, options, out.Write); serr != nil {
		return errors.Join(errors.New(folder.To+" → "+folder.Map), serr)
	}
	return nil
}
