package sshrun

// The guest→host pull transports (folders[].syncback — Mark's ruling
// 2026-07-12, replacing his Hosts.rb results hack): the exact reverse of the
// push transports in sync.go/builtin.go, riding the same ladder — the
// folder's chosen binary tool first, the pure-Go floor beneath. Pull
// semantics deliberately differ from push in two ways: folder.delete is
// NEVER honored (a pull must not delete host files), and no chown runs (the
// pulled files stay the agent's own).

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gokrazy/rsync/rsyncclient"
	"github.com/pkg/sftp"

	"github.com/Makr91/hyperweaver-agent/internal/procattr"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// newCommand builds one transport process, wrapping in sshpass for password
// auth — the push transports' exact rule (the secret rides the SSHPASS
// environment variable, never argv). Nil when password auth is requested but
// sshpass is absent on the agent host.
func newCommand(ctx context.Context, exe string, args []string, credentials Credentials) *exec.Cmd {
	command := exec.CommandContext(ctx, exe, args...)
	command.Env = toolEnv(exe)
	if credentials.Password != "" && credentials.SSHKeyPath == "" {
		sshpass, perr := exec.LookPath("sshpass")
		if perr != nil {
			return nil
		}
		command = exec.CommandContext(ctx, sshpass, append([]string{"-e", exe}, args...)...)
		command.Env = append(toolEnv(exe), "SSHPASS="+credentials.Password)
	}
	command.SysProcAttr = procattr.NoConsole()
	return command
}

// SyncFilesPull rsyncs a remote directory's CONTENT into a local directory
// (`rsync -e ssh user@ip:remote/ local`). The remote sender runs `sudo
// rsync` (the push path's --rsync-path rule) so root-owned provisioning
// results are readable. folder args/exclude apply; delete never does.
func SyncFilesPull(ctx context.Context, rsyncExe, ip string, port int, credentials Credentials,
	remoteDir, localDir, basePath, defaultKeyPath string, options *SyncOptions, stream StreamFunc,
) error {
	exe, err := safepath.ValidateExecutable(rsyncExe)
	if err != nil {
		return err
	}

	flags := defaultRsyncArgs
	if options != nil && len(options.Args) > 0 {
		flags = options.Args
	}
	args := append([]string{}, flags...)
	if options != nil {
		for _, pattern := range options.Exclude {
			args = append(args, "--exclude="+pattern)
		}
	}

	sshCommand := []string{
		"ssh",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
		"-p", strconv.Itoa(port),
	}
	if keyPath := credentialKeyPath(credentials, basePath, defaultKeyPath); keyPath != "" {
		sshCommand = append(sshCommand, "-i", cygwinPath(keyPath))
	}
	args = append(args,
		"--rsync-path=sudo rsync",
		"-e", strings.Join(sshCommand, " "),
	)

	username := credentials.Username
	if username == "" {
		username = "root"
	}
	// Trailing slash on the REMOTE source: content sync into the local dir.
	source := fmt.Sprintf("%s@%s:%s", username, ip, strings.TrimSuffix(remoteDir, "/")+"/")
	args = append(args, source, cygwinPath(localDir))

	command := newCommand(ctx, exe, args, credentials)
	if command == nil {
		return fmt.Errorf("password-auth sync needs sshpass on the agent host")
	}
	return streamCommand(command, stream)
}

// SCPSyncPull copies a remote directory's content into a local directory
// with `scp -r user@ip:remote/. local`. scp cannot elevate on the remote
// side, so root-only files fail — the rsync path is the stronger pull.
func SCPSyncPull(ctx context.Context, scpExe, ip string, port int, credentials Credentials,
	remoteDir, localDir, basePath, defaultKeyPath string, stream StreamFunc,
) error {
	exe, err := safepath.ValidateExecutable(scpExe)
	if err != nil {
		return err
	}
	args := []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
		"-P", strconv.Itoa(port),
		"-r",
	}
	keyPath := credentialKeyPath(credentials, basePath, defaultKeyPath)
	dest := strings.TrimSuffix(localDir, "/")
	if isCygwinTool(exe) {
		keyPath = cygwinPath(keyPath)
		dest = cygwinPath(dest)
	} else {
		keyPath = filepath.ToSlash(keyPath)
		dest = filepath.ToSlash(dest)
	}
	if keyPath != "" {
		args = append(args, "-i", keyPath)
	}
	username := credentials.Username
	if username == "" {
		username = "root"
	}
	// remote/dir/. copies the CONTENT (the push path's rule, reversed).
	source := fmt.Sprintf("%s@%s:%s/.", username, ip, strings.TrimSuffix(remoteDir, "/"))
	args = append(args, source, dest)

	command := newCommand(ctx, exe, args, credentials)
	if command == nil {
		return fmt.Errorf("password-auth sync needs sshpass on the agent host")
	}
	return streamCommand(command, stream)
}

// BuiltinRsyncSyncPull pulls a remote directory's content with the embedded
// pure-Go rsync client in its default RECEIVER mode — the remote half is the
// guest's own `sudo rsync --server --sender` over one SSH session, so folder
// args and exclude keep their rsync semantics (delete is never passed).
func BuiltinRsyncSyncPull(ctx context.Context, ip string, port int, credentials Credentials,
	remoteDir, localDir, basePath, defaultKeyPath string, options *SyncOptions, stream StreamFunc,
) error {
	flags := append([]string{}, defaultRsyncArgs...)
	if options != nil && len(options.Args) > 0 {
		flags = append([]string{}, options.Args...)
	}
	if options != nil {
		for _, pattern := range options.Exclude {
			flags = append(flags, "--exclude="+pattern)
		}
	}

	client, err := rsyncclient.New(flags,
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

	// Trailing slash on the remote source: content sync (the folder contract).
	source := strings.TrimSuffix(remoteDir, "/") + "/"
	remote := "sudo rsync " + shellQuoteArgs(client.ServerCommandOptions(source))
	if serr := session.Start(remote); serr != nil {
		return fmt.Errorf("start remote rsync server: %w", serr)
	}

	if _, rerr := client.Run(ctx, struct {
		io.Reader
		io.Writer
	}{stdout, stdin}, []string{filepath.ToSlash(localDir)}); rerr != nil {
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
		stream("stdout", "Built-in rsync pull complete: "+source+" → "+localDir+"\n")
	}
	return nil
}

// SFTPSyncPull downloads a remote directory's content over sshd's sftp
// subsystem — the always-available floor. Reads as the SSH user (no sudo in
// sftp); root-only files narrate and skip rather than failing the pull.
func SFTPSyncPull(ctx context.Context, ip string, port int, credentials Credentials,
	remoteDir, localDir, basePath, defaultKeyPath string, stream StreamFunc,
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

	root := strings.TrimSuffix(remoteDir, "/")
	files := 0
	walker := ftp.Walk(root)
	for walker.Step() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if werr := walker.Err(); werr != nil {
			if stream != nil {
				stream("stderr", "SFTP pull: "+walker.Path()+": "+werr.Error()+"\n")
			}
			continue
		}
		remote := walker.Path()
		rel := strings.TrimPrefix(strings.TrimPrefix(remote, root), "/")
		local := localDir
		if rel != "" {
			local = filepath.Join(localDir, filepath.FromSlash(rel))
		}
		info := walker.Stat()
		if info.IsDir() {
			if merr := os.MkdirAll(local, 0o750); merr != nil {
				return merr
			}
			continue
		}
		if !info.Mode().IsRegular() {
			if stream != nil {
				stream("stderr", "SFTP pull skipped non-regular file "+rel+"\n")
			}
			continue
		}
		src, oerr := ftp.Open(remote)
		if oerr != nil {
			if stream != nil {
				stream("stderr", "SFTP pull: "+remote+": "+oerr.Error()+" (skipped — sftp cannot elevate)\n")
			}
			continue
		}
		_, werr := safepath.WriteFileFrom(local, src, 0o600)
		_ = src.Close()
		if werr != nil {
			return fmt.Errorf("write %s: %w", local, werr)
		}
		files++
	}
	if stream != nil {
		stream("stdout", fmt.Sprintf("SFTP pull complete: %d files → %s\n", files, localDir))
	}
	return nil
}
