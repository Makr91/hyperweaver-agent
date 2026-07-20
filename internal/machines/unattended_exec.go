package machines

// Unattended OS installation (Mark's verb-survey go 2026-07-12): VirtualBox's
// own answer-file install onto an existing machine — the ISO-first
// install-yourself flow automated.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// OpUnattended is the unattended-install task operation.
const OpUnattended = "machine_unattended_install"

// UnattendedAccount is the guest account the installer creates — nested like
// the provision chain's credentials document (Mark's visibility ruling keeps
// it readable in task metadata, never redacted).
type UnattendedAccount struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

// UnattendedMetadata is the machine_unattended_install task's metadata: the
// ISO reference (raw Path or cached-ISO Iso filename — cdroms[]'s exact
// vocabulary), the account document, and VBoxManage's unattended knobs.
type UnattendedMetadata struct {
	Path                       string            `json:"path,omitempty"`
	Iso                        string            `json:"iso,omitempty"`
	Account                    UnattendedAccount `json:"account"`
	FullName                   string            `json:"full_name,omitempty"`
	ProductKey                 string            `json:"product_key,omitempty"`
	Hostname                   string            `json:"hostname,omitempty"`
	Locale                     string            `json:"locale,omitempty"`
	Country                    string            `json:"country,omitempty"`
	TimeZone                   string            `json:"time_zone,omitempty"`
	Language                   string            `json:"language,omitempty"`
	ImageIndex                 int               `json:"image_index,omitempty"`
	InstallAdditions           bool              `json:"install_additions,omitempty"`
	AdditionsISO               string            `json:"additions_iso,omitempty"`
	PostInstallCommand         string            `json:"post_install_command,omitempty"`
	PackageSelectionAdjustment string            `json:"package_selection_adjustment,omitempty"`
	Start                      *bool             `json:"start,omitempty"`
}

// unattendedInstall executes machine_unattended_install.
func (e *executors) unattendedInstall(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	machine, vboxExe, err := e.resolve(ctx, task)
	if err != nil {
		return err
	}
	var meta UnattendedMetadata
	if len(task.Metadata) == 0 {
		return errors.New("unattended task has no metadata")
	}
	if uerr := json.Unmarshal(task.Metadata, &meta); uerr != nil {
		return fmt.Errorf("parse unattended metadata: %w", uerr)
	}
	if meta.Account.User == "" || meta.Account.Password == "" {
		return errors.New("account user and password are required in task metadata")
	}

	target := machine.VBoxTarget()
	info, err := vbox.ShowVMInfo(ctx, vboxExe, target)
	if errors.Is(err, vbox.ErrNotFound) {
		return errors.New("no VM exists behind this machine yet")
	}
	if err != nil {
		return err
	}
	switch MapVBoxState(info.State) {
	case StatusStopped, StatusAborted:
	default:
		return fmt.Errorf("machine is %s — unattended install needs a powered-off machine", info.State)
	}

	e.taskProgress(task, 10, "resolving_iso")
	iso, err := e.resolveCdromPath(ctx, map[string]any{"path": meta.Path, "iso": meta.Iso})
	if err != nil {
		return err
	}
	if iso == "" {
		return errors.New("an installer ISO is required (path or cached-ISO iso name)")
	}

	start := true
	if meta.Start != nil {
		start = *meta.Start
	}
	// The password reaches VBoxManage through a transient 0600 file
	// (--password-file) — never the process argv, so never the host's
	// process list. Written through safepath (the one write path), named by
	// the task id. The metadata document stays the readable record.
	passwordPath := filepath.Join(os.TempDir(), "hw-unattended-"+task.ID+".pwd")
	if werr := safepath.WriteFile(passwordPath, []byte(meta.Account.Password+"\n"), 0o600); werr != nil {
		return fmt.Errorf("stage password file: %w", werr)
	}
	defer func() {
		_ = os.Remove(passwordPath)
	}()
	options := &vbox.UnattendedOptions{
		ISO:                        iso,
		User:                       meta.Account.User,
		PasswordFile:               passwordPath,
		FullUserName:               meta.FullName,
		ProductKey:                 meta.ProductKey,
		Hostname:                   meta.Hostname,
		Locale:                     meta.Locale,
		Country:                    meta.Country,
		TimeZone:                   meta.TimeZone,
		Language:                   meta.Language,
		ImageIndex:                 meta.ImageIndex,
		InstallAdditions:           meta.InstallAdditions,
		AdditionsISO:               meta.AdditionsISO,
		PostInstallCommand:         meta.PostInstallCommand,
		PackageSelectionAdjustment: meta.PackageSelectionAdjustment,
		Start:                      start,
	}

	e.taskProgress(task, 30, "configuring_unattended_install")
	out.Write("stdout", "Preparing unattended install of "+iso+" onto "+machine.Name+"\n")
	defer e.refreshStatus(machine.Name, vboxExe)
	if ierr := vbox.UnattendedInstall(ctx, vboxExe, target, options); ierr != nil {
		return ierr
	}
	if start {
		out.Write("stdout", "Unattended install configured — machine booting headless into the installer (watch progress on the console/screenshot)\n")
	} else {
		out.Write("stdout", "Unattended install configured — start the machine to begin installation\n")
	}
	e.taskProgress(task, 100, "completed")
	return nil
}
