package vbox

// Unattended OS installation (`unattended detect|install`) — VirtualBox's
// own answer-file machinery: it prepares an auxiliary floppy/ISO with the
// distro-appropriate unattended script and boots the installer.

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/procattr"
)

// UnattendedDetect asks VirtualBox what an installer ISO contains
// (`unattended detect --iso`). Keys are VBoxManage's own detection fields
// normalized to snake_case (os_typeid, os_version, os_flavor, os_languages,
// os_hints, unattended_installation_supported).
func UnattendedDetect(ctx context.Context, vboxManage, iso string) (map[string]string, error) {
	cmd := exec.CommandContext(ctx, vboxManage, "unattended", "detect", "--iso="+iso)
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("VBoxManage unattended detect: %w: %s", err, strings.TrimSpace(string(out)))
	}
	detected := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		key = strings.ReplaceAll(key, " ", "_")
		if key == "" {
			continue
		}
		detected[key] = strings.TrimSpace(value)
	}
	return detected, nil
}

// UnattendedOptions carries `unattended install`'s knobs. PasswordFile is a
// file holding the account password (--password-file — the password never
// rides the process argv, so it never shows in the host's process list).
type UnattendedOptions struct {
	ISO                        string
	User                       string
	PasswordFile               string
	FullUserName               string
	ProductKey                 string
	Hostname                   string
	Locale                     string
	Country                    string
	TimeZone                   string
	Language                   string
	ImageIndex                 int
	InstallAdditions           bool
	AdditionsISO               string
	PostInstallCommand         string
	PackageSelectionAdjustment string
	Start                      bool
}

// UnattendedInstall configures the machine for an unattended OS install and
// optionally boots it headless.
func UnattendedInstall(ctx context.Context, vboxManage, name string, o *UnattendedOptions) error {
	args := []string{
		"unattended", "install", name,
		"--iso=" + o.ISO,
		"--user=" + o.User,
		"--password-file=" + o.PasswordFile,
	}
	if o.FullUserName != "" {
		args = append(args, "--full-user-name="+o.FullUserName)
	}
	if o.ProductKey != "" {
		args = append(args, "--key="+o.ProductKey)
	}
	if o.Hostname != "" {
		args = append(args, "--hostname="+o.Hostname)
	}
	if o.Locale != "" {
		args = append(args, "--locale="+o.Locale)
	}
	if o.Country != "" {
		args = append(args, "--country="+o.Country)
	}
	if o.TimeZone != "" {
		args = append(args, "--time-zone="+o.TimeZone)
	}
	if o.Language != "" {
		args = append(args, "--language="+o.Language)
	}
	if o.ImageIndex > 0 {
		args = append(args, "--image-index="+strconv.Itoa(o.ImageIndex))
	}
	if o.InstallAdditions {
		args = append(args, "--install-additions")
		if o.AdditionsISO != "" {
			args = append(args, "--additions-iso="+o.AdditionsISO)
		}
	}
	if o.PostInstallCommand != "" {
		args = append(args, "--post-install-command="+o.PostInstallCommand)
	}
	if o.PackageSelectionAdjustment != "" {
		args = append(args, "--package-selection-adjustment="+o.PackageSelectionAdjustment)
	}
	if o.Start {
		args = append(args, "--start-vm=headless")
	}
	return runConfig(ctx, vboxManage, args...)
}
