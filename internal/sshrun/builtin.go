package sshrun

// The built-in pure-Go sync transports (Mark's ruling 2026-07-07: the agent
// must not NEED vagrant — or any host binary — to function). They are the
// fallback floor under the binary transports, engaged only when the tool is
// absent: BuiltinRsyncSync speaks the rsync protocol itself (the guest's own
// rsync serves the remote half, exactly like the binary path), and SFTPSync
// rides sshd's sftp subsystem so it works against any guest at all.

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/gokrazy/rsync/rsyncclient"
	"github.com/pkg/sftp"
)

// stderrOrDiscard adapts an optional StreamFunc to the transports' stderr
// writer (every remote-rsync surface writes its diagnostics there).
func stderrOrDiscard(stream StreamFunc) io.Writer {
	if stream == nil {
		return io.Discard
	}
	return streamWriter{stream: "stderr", cb: stream}
}

// shellQuoteArgs single-quotes each argument for the remote shell (the same
// quoting discipline the extra-vars command uses).
func shellQuoteArgs(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, "'"+strings.ReplaceAll(arg, "'", `'\''`)+"'")
	}
	return strings.Join(quoted, " ")
}

// BuiltinRsyncSync syncs a local directory INTO the machine with the embedded
// pure-Go rsync client (github.com/gokrazy/rsync) over one SSH session the
// agent opens itself — no agent-side rsync binary, no spawned processes. The
// remote half is the guest's own `sudo rsync --server` (the identical remote
// command the binary path's --rsync-path drives), so folder args, exclude,
// and delete all keep their rsync semantics.
func BuiltinRsyncSync(ctx context.Context, ip string, port int, credentials Credentials,
	localDir, remoteDir, basePath, defaultKeyPath string, options *SyncOptions, stream StreamFunc,
) error {
	flags := append([]string{}, defaultRsyncArgs...)
	if options != nil && len(options.Args) > 0 {
		flags = append([]string{}, options.Args...)
	}
	if options != nil && options.Delete {
		flags = append(flags, "--delete")
	}
	if options != nil {
		for _, pattern := range options.Exclude {
			flags = append(flags, "--exclude="+pattern)
		}
	}

	client, err := rsyncclient.New(flags, rsyncclient.WithSender(),
		rsyncclient.WithStderr(stderrOrDiscard(stream)))
	if err != nil {
		return fmt.Errorf("built-in rsync client: %w", err)
	}

	sshClient, closeSSH, _, err := connectSSH(ctx, ip, port, credentials, basePath, defaultKeyPath)
	if err != nil {
		return err
	}
	defer closeSSH()

	session, err := sshClient.NewSession()
	if err != nil {
		return fmt.Errorf("ssh session: %w", err)
	}
	defer func() {
		_ = session.Close()
	}()

	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	session.Stderr = stderrOrDiscard(stream)

	remote := "sudo rsync " + shellQuoteArgs(client.ServerCommandOptions(remoteDir))
	if serr := session.Start(remote); serr != nil {
		return fmt.Errorf("start remote rsync server: %w", serr)
	}

	// Trailing slash = content sync, the folder contract's semantics.
	source := strings.TrimSuffix(filepath.ToSlash(localDir), "/") + "/"
	if _, rerr := client.Run(ctx, struct {
		io.Reader
		io.Writer
	}{stdout, stdin}, []string{source}); rerr != nil {
		_ = stdin.Close()
		if ctx.Err() != nil {
			return fmt.Errorf("built-in rsync cancelled or timed out: %w", ctx.Err())
		}
		return fmt.Errorf("built-in rsync (does the guest have rsync installed?): %w", rerr)
	}
	_ = stdin.Close()
	if werr := session.Wait(); werr != nil {
		return fmt.Errorf("remote rsync server exit: %w", werr)
	}
	if stream != nil {
		stream("stdout", "Built-in rsync transfer complete: "+source+" → "+remoteDir+"\n")
	}
	return nil
}

// SFTPSync copies a local directory's CONTENT into the machine over sshd's
// sftp subsystem — the always-available floor: pure Go on the agent side and
// nothing but a stock sshd on the guest. Folder args/exclude/delete do not
// apply (no rsync semantics without rsync); files land as the SSH user, so
// the caller pre-hands the destination to that user and chowns afterwards.
func SFTPSync(ctx context.Context, ip string, port int, credentials Credentials,
	localDir, remoteDir, basePath, defaultKeyPath string, stream StreamFunc,
) error {
	sshClient, closeSSH, _, err := connectSSH(ctx, ip, port, credentials, basePath, defaultKeyPath)
	if err != nil {
		return err
	}
	defer closeSSH()

	ftp, err := sftp.NewClient(sshClient)
	if err != nil {
		return fmt.Errorf("open sftp subsystem: %w", err)
	}
	defer func() {
		_ = ftp.Close()
	}()

	// Root-scoped walk: every open stays inside localDir (no symlink
	// traversal out of the working copy, and no TOCTOU between the walk and
	// the open — gosec G122's exact recommendation).
	root, err := os.OpenRoot(localDir)
	if err != nil {
		return err
	}
	defer func() {
		_ = root.Close()
	}()

	files := 0
	walkErr := fs.WalkDir(root.FS(), ".", func(rel string, entry fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		remote := remoteDir
		if rel != "." {
			remote = path.Join(remoteDir, rel)
		}
		if entry.IsDir() {
			return ftp.MkdirAll(remote)
		}
		if !entry.Type().IsRegular() {
			if stream != nil {
				stream("stderr", "SFTP skipped non-regular file "+rel+"\n")
			}
			return nil
		}
		info, ierr := entry.Info()
		if ierr != nil {
			return ierr
		}
		src, oerr := root.Open(rel)
		if oerr != nil {
			return oerr
		}
		defer func() {
			_ = src.Close()
		}()
		dst, cerr := ftp.Create(remote)
		if cerr != nil {
			return fmt.Errorf("create %s: %w", remote, cerr)
		}
		if _, cerr := io.Copy(dst, src); cerr != nil {
			_ = dst.Close()
			return fmt.Errorf("copy %s: %w", remote, cerr)
		}
		if cerr := dst.Close(); cerr != nil {
			return fmt.Errorf("close %s: %w", remote, cerr)
		}
		if merr := ftp.Chmod(remote, info.Mode().Perm()); merr != nil && stream != nil {
			stream("stderr", "SFTP chmod "+remote+": "+merr.Error()+"\n")
		}
		files++
		return nil
	})
	if walkErr != nil {
		return walkErr
	}
	if stream != nil {
		stream("stdout", fmt.Sprintf("SFTP sync complete: %d files → %s\n", files, remoteDir))
	}
	return nil
}

// UploadFile lands ONE local file at a remote path over the sftp subsystem —
// the shell-provisioner transport (scripts upload the way vagrant's shell
// provisioner does, never relying on a folder sync to have carried them).
func UploadFile(ctx context.Context, ip string, port int, credentials Credentials,
	localPath, remotePath, basePath, defaultKeyPath string,
) error {
	sshClient, closeSSH, _, err := connectSSH(ctx, ip, port, credentials, basePath, defaultKeyPath)
	if err != nil {
		return err
	}
	defer closeSSH()

	ftp, err := sftp.NewClient(sshClient)
	if err != nil {
		return fmt.Errorf("open sftp subsystem: %w", err)
	}
	defer func() {
		_ = ftp.Close()
	}()

	src, err := os.Open(filepath.Clean(localPath))
	if err != nil {
		return err
	}
	defer func() {
		_ = src.Close()
	}()
	dst, err := ftp.Create(remotePath)
	if err != nil {
		return fmt.Errorf("create %s: %w", remotePath, err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return fmt.Errorf("copy %s: %w", remotePath, err)
	}
	if err := dst.Close(); err != nil {
		return fmt.Errorf("close %s: %w", remotePath, err)
	}
	return nil
}
