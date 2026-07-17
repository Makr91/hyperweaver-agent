package sshrun

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/Makr91/hyperweaver-agent/internal/procattr"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// cygwinPath converts a Windows path for Cygwin-built transports (vagrant's
// embedded rsync/scp): C:\foo\bar → /cygdrive/c/foo/bar — vagrant's own
// cygwin_path rule. A bare drive-letter path reads as a remote host:path to
// Cygwin rsync ("The source and destination cannot both be remote", the
// vagrant behavior the cut orphaned; runtime-proven 2026-07-07). No-op off
// Windows.
func cygwinPath(path string) string {
	if runtime.GOOS != "windows" {
		return path
	}
	path = strings.ReplaceAll(path, `\`, "/")
	if len(path) >= 2 && path[1] == ':' {
		path = "/cygdrive/" + strings.ToLower(string(path[0])) + path[2:]
	}
	return path
}

// isCygwinTool reports a Cygwin/MSYS-built transport binary (vagrant's
// embedded tree; there is no native Windows rsync) — those need cygwinPath
// for every local path; Windows' native OpenSSH scp takes drive-letter paths.
func isCygwinTool(exe string) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	lower := strings.ToLower(exe)
	return strings.Contains(lower, "vagrant") ||
		strings.Contains(lower, "cygwin") || strings.Contains(lower, "msys")
}

// toolEnv puts the transport's own directory FIRST on the child's PATH so
// rsync's `-e ssh` resolves to the sibling ssh binary it shipped with
// (vagrant's embedded ssh.exe beside its rsync.exe) instead of whichever ssh
// the agent inherited.
func toolEnv(exe string) []string {
	if runtime.GOOS != "windows" {
		return os.Environ()
	}
	return append(os.Environ(),
		"PATH="+filepath.Dir(exe)+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// defaultRsyncArgs is the base's rsync default flag set (vagrant-zones
// parity).
var defaultRsyncArgs = []string{"--verbose", "--archive", "-z", "--copy-links"}

// FindTool locates a sync transport binary (rsync | scp): PATH first, then
// vagrant's embedded toolchain — Mark's rule: a vagrant install carries a
// working rsync (Windows: <Vagrant>\embedded\usr\bin\rsync.exe; macOS/Linux:
// /opt/vagrant/embedded/bin), which also sidesteps Apple's ancient rsync —
// then Windows' own OpenSSH directory (scp/ssh ship with Windows 10+ even
// when the service manager keeps them off PATH). Vagrant is OPTIONAL: a
// miss here drops the caller to the built-in pure-Go transports.
func FindTool(name string) (string, error) {
	if path, err := exec.LookPath(name); err == nil {
		return path, nil
	}
	candidates := []string{
		`C:\Program Files\Vagrant\embedded\usr\bin\` + name + ".exe",
		`C:\HashiCorp\Vagrant\embedded\usr\bin\` + name + ".exe",
		`C:\Windows\System32\OpenSSH\` + name + ".exe",
		"/opt/vagrant/embedded/bin/" + name,
		"/opt/vagrant/embedded/usr/bin/" + name,
	}
	for _, candidate := range candidates {
		if path, err := safepath.ValidateExecutable(candidate); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("%s is not available on the agent host (PATH, vagrant's embedded toolchain, and the Windows OpenSSH directory checked)", name)
}

// SyncOptions carries one folder's rsync modifiers (the folder document's
// args/exclude/delete).
type SyncOptions struct {
	Args    []string
	Exclude []string
	Delete  bool
}

// SyncFiles rsyncs a local directory INTO the machine over SSH —
// SSHManager.syncFiles verbatim: default flags unless the folder overrides
// them, --delete/--exclude appended, remote side runs `sudo rsync`, the
// source carries a trailing slash (content sync), password auth rides
// sshpass via the SSHPASS environment variable (never argv).
func SyncFiles(ctx context.Context, rsyncExe, ip string, port int, credentials Credentials,
	localDir, remoteDir, basePath, defaultKeyPath string, options *SyncOptions, stream StreamFunc,
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
	if options != nil && options.Delete {
		args = append(args, "--delete")
	}
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
	keyPath := credentialKeyPath(credentials, basePath, defaultKeyPath)
	if keyPath != "" {
		// rsync's -e ssh is the sibling Cygwin ssh (toolEnv), so the key path
		// speaks its dialect too.
		sshCommand = append(sshCommand, "-i", cygwinPath(keyPath))
	}
	args = append(args,
		"--rsync-path=sudo rsync",
		"-e", strings.Join(sshCommand, " "),
	)

	// Every Windows rsync is a Cygwin build: local paths convert to
	// /cygdrive form or they read as remote host:path specs.
	source := cygwinPath(localDir)
	if !strings.HasSuffix(source, "/") {
		source += "/"
	}
	username := credentials.Username
	if username == "" {
		username = "root"
	}
	args = append(args, source, fmt.Sprintf("%s@%s:%s", username, ip, remoteDir))

	command := exec.CommandContext(ctx, exe, args...)
	command.Env = toolEnv(exe)
	if credentials.Password != "" && keyPath == "" {
		// Password auth — the resolver found no key file anywhere (the ladder's
		// rule): sshpass reads SSHPASS from the environment — the secret never
		// appears on a command line.
		sshpass, perr := exec.LookPath("sshpass")
		if perr != nil {
			return fmt.Errorf("password-auth sync needs sshpass on the agent host: %w", perr)
		}
		command = exec.CommandContext(ctx, sshpass, append([]string{"-e", exe}, args...)...)
		command.Env = append(toolEnv(exe), "SSHPASS="+credentials.Password)
	}
	command.SysProcAttr = procattr.NoConsole()

	return streamCommand(command, stream)
}

// SCPSync copies a local directory into the machine with scp -r — the sync
// transport for hosts whose rsync is unusable (Mark's rule: macOS ships an
// ancient Apple rsync with broken chown handling; scp is why SCP support
// exists at all). Folder args/exclude/delete do not apply — scp has no
// equivalents; the caller narrates the downgrade.
func SCPSync(ctx context.Context, scpExe, ip string, port int, credentials Credentials,
	localDir, remoteDir, basePath, defaultKeyPath string, stream StreamFunc,
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
	// Windows ships a NATIVE OpenSSH scp (drive-letter paths fine); vagrant's
	// embedded scp is Cygwin and needs /cygdrive form — convert per binary.
	keyPath := credentialKeyPath(credentials, basePath, defaultKeyPath)
	source := strings.TrimSuffix(localDir, "/")
	if isCygwinTool(exe) {
		keyPath = cygwinPath(keyPath)
		source = cygwinPath(source)
	} else {
		keyPath = filepath.ToSlash(keyPath)
		source = filepath.ToSlash(source)
	}
	if keyPath != "" {
		args = append(args, "-i", keyPath)
	}
	username := credentials.Username
	if username == "" {
		username = "root"
	}
	// scp of dir/. copies the CONTENT (rsync's trailing-slash semantics).
	source += "/."
	args = append(args, source, fmt.Sprintf("%s@%s:%s", username, ip, remoteDir))

	command := exec.CommandContext(ctx, exe, args...)
	command.Env = toolEnv(exe)
	if credentials.Password != "" && keyPath == "" {
		// Password auth only when the resolver found no key file anywhere.
		sshpass, perr := exec.LookPath("sshpass")
		if perr != nil {
			return fmt.Errorf("password-auth sync needs sshpass on the agent host: %w", perr)
		}
		command = exec.CommandContext(ctx, sshpass, append([]string{"-e", exe}, args...)...)
		command.Env = append(toolEnv(exe), "SSHPASS="+credentials.Password)
	}
	command.SysProcAttr = procattr.NoConsole()
	return streamCommand(command, stream)
}

// credentialKeyPath resolves the key the binary ssh transports (rsync/scp)
// use — the SAME tiered resolver authMethods walks (Mark's three-tier
// ruling, sync 2026-07-17: one resolver, two consumers). Empty ONLY when the
// ladder resolved to password auth (no key file exists anywhere) — the
// callers' sshpass gate keys off exactly that.
func credentialKeyPath(credentials Credentials, basePath, defaultKeyPath string) string {
	path, _ := effectiveKeyPath(credentials, basePath, defaultKeyPath)
	return path
}

// streamCommand runs a prepared command, forwarding its output line-streamed.
func streamCommand(command *exec.Cmd, stream StreamFunc) error {
	if stream != nil {
		command.Stdout = streamWriter{stream: "stdout", cb: stream}
		command.Stderr = streamWriter{stream: "stderr", cb: stream}
	}
	if err := command.Run(); err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(command.Path), err)
	}
	return nil
}

// EnsureProvisionKey generates the agent's ed25519 provisioning keypair at
// keyPath (idempotent — an existing key is kept; SSHManager.generateSSHKey).
// Returns the public key line for injection into guests.
func EnsureProvisionKey(keyPath string) (string, error) {
	clean, err := safepath.CleanAbs(keyPath)
	if err != nil {
		return "", err
	}
	publicPath := clean + ".pub"

	if _, serr := os.Stat(clean); serr == nil {
		raw, rerr := os.ReadFile(filepath.Clean(publicPath))
		if rerr != nil {
			return "", fmt.Errorf("provisioning key exists but its public half is unreadable: %w", rerr)
		}
		return strings.TrimSpace(string(raw)), nil
	}

	if merr := os.MkdirAll(filepath.Dir(clean), 0o750); merr != nil {
		return "", merr
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	pemBlock, err := ssh.MarshalPrivateKey(private, "hyperweaver-agent@provisioning")
	if err != nil {
		return "", err
	}
	if werr := safepath.WriteFile(clean, pem.EncodeToMemory(pemBlock), 0o600); werr != nil {
		return "", werr
	}
	sshPublic, err := ssh.NewPublicKey(public)
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPublic))) +
		" hyperweaver-agent@provisioning"
	if werr := safepath.WriteFile(publicPath, []byte(line+"\n"), 0o600); werr != nil {
		return "", werr
	}
	plog().Info("provisioning SSH key generated", "path", clean)
	return line, nil
}
