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
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/Makr91/hyperweaver-agent/internal/procattr"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// defaultRsyncArgs is the base's rsync default flag set (vagrant-zones
// parity).
var defaultRsyncArgs = []string{"--verbose", "--archive", "-z", "--copy-links"}

// FindTool locates a sync transport binary (rsync | scp): PATH first, then
// vagrant's embedded toolchain — Mark's rule: a vagrant install carries a
// working rsync (Windows: <Vagrant>\embedded\usr\bin\rsync.exe; macOS/Linux:
// /opt/vagrant/embedded/bin), which also sidesteps Apple's ancient rsync.
func FindTool(name string) (string, error) {
	if path, err := exec.LookPath(name); err == nil {
		return path, nil
	}
	candidates := []string{
		`C:\Program Files\Vagrant\embedded\usr\bin\` + name + ".exe",
		`C:\HashiCorp\Vagrant\embedded\usr\bin\` + name + ".exe",
		"/opt/vagrant/embedded/bin/" + name,
		"/opt/vagrant/embedded/usr/bin/" + name,
	}
	for _, candidate := range candidates {
		if path, err := safepath.ValidateExecutable(candidate); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("%s is not available on the agent host (PATH and vagrant's embedded toolchain checked)", name)
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
	if keyPath := credentialKeyPath(credentials, basePath, defaultKeyPath); keyPath != "" {
		sshCommand = append(sshCommand, "-i", keyPath)
	}
	args = append(args,
		"--rsync-path=sudo rsync",
		"-e", strings.Join(sshCommand, " "),
	)

	source := localDir
	if !strings.HasSuffix(source, "/") {
		source += "/"
	}
	username := credentials.Username
	if username == "" {
		username = "root"
	}
	args = append(args, source, fmt.Sprintf("%s@%s:%s", username, ip, remoteDir))

	command := exec.CommandContext(ctx, exe, args...)
	if credentials.Password != "" && credentials.SSHKeyPath == "" {
		// Password auth: sshpass reads SSHPASS from the environment — the
		// secret never appears on a command line.
		sshpass, perr := exec.LookPath("sshpass")
		if perr != nil {
			return fmt.Errorf("password-auth sync needs sshpass on the agent host: %w", perr)
		}
		command = exec.CommandContext(ctx, sshpass, append([]string{"-e", exe}, args...)...)
		command.Env = append(os.Environ(), "SSHPASS="+credentials.Password)
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
	if keyPath := credentialKeyPath(credentials, basePath, defaultKeyPath); keyPath != "" {
		args = append(args, "-i", keyPath)
	}
	username := credentials.Username
	if username == "" {
		username = "root"
	}
	// scp of dir/. copies the CONTENT (rsync's trailing-slash semantics).
	source := strings.TrimSuffix(localDir, "/") + "/."
	args = append(args, source, fmt.Sprintf("%s@%s:%s", username, ip, remoteDir))

	command := exec.CommandContext(ctx, exe, args...)
	if credentials.Password != "" && credentials.SSHKeyPath == "" {
		sshpass, perr := exec.LookPath("sshpass")
		if perr != nil {
			return fmt.Errorf("password-auth sync needs sshpass on the agent host: %w", perr)
		}
		command = exec.CommandContext(ctx, sshpass, append([]string{"-e", exe}, args...)...)
		command.Env = append(os.Environ(), "SSHPASS="+credentials.Password)
	}
	command.SysProcAttr = procattr.NoConsole()
	return streamCommand(command, stream)
}

// credentialKeyPath resolves the key the ssh transport uses (explicit →
// default provisioning key; empty for password auth).
func credentialKeyPath(credentials Credentials, basePath, defaultKeyPath string) string {
	if credentials.SSHKeyPath != "" {
		return resolveKeyPath(credentials.SSHKeyPath, basePath)
	}
	if credentials.Password != "" {
		return ""
	}
	return defaultKeyPath
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
