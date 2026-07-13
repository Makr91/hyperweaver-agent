package machines

// OVA/OVF appliance import + machine relocation (Mark's verb-survey go
// 2026-07-12): export's missing pair and `movevm`.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// Appliance-import and relocation operations.
const (
	OpImport = "machine_import"
	OpMove   = "machine_move"
)

// ImportMetadata is the machine_import task's metadata document.
type ImportMetadata struct {
	// Path is the agent-host .ova/.ovf file.
	Path string `json:"path"`
	// Name overrides the appliance's suggested machine name.
	Name string `json:"name,omitempty"`
}

// MoveMetadata is the machine_move task's metadata document.
type MoveMetadata struct {
	TargetPath string `json:"target_path"`
}

// importAppliance executes machine_import: VBoxManage import into the
// machines root, then one reconciliation sweep so the row appears.
func (e *executors) importAppliance(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	var meta ImportMetadata
	if task.Metadata == nil {
		return errors.New("import task has no metadata")
	}
	if err := json.Unmarshal([]byte(*task.Metadata), &meta); err != nil {
		return fmt.Errorf("parse import metadata: %w", err)
	}
	if meta.Path == "" {
		return errors.New("path is required in task metadata")
	}
	path := filepath.FromSlash(meta.Path)
	if _, serr := os.Stat(filepath.Clean(path)); serr != nil {
		return fmt.Errorf("appliance file: %w", serr)
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".ova", ".ovf":
	default:
		return errors.New("appliance must be an .ova or .ovf file")
	}
	exe := VBoxManagePath(ctx)
	if exe == "" {
		return errors.New("VirtualBox is not installed")
	}

	out.Write("stdout", "Importing appliance "+path+"\n")
	if ierr := vbox.ImportAppliance(ctx, exe, path, meta.Name, e.env.MachinesDir); ierr != nil {
		return ierr
	}
	out.Write("stdout", "Import complete — reconciling the registry\n")
	e.reconciler.RunOnce(ctx, out)
	return nil
}

// moveMachine executes machine_move: relocate the VM's VirtualBox files
// (powered-off only — VirtualBox refuses otherwise, honestly). The agent's
// working directory (documents, installers) does not move.
func (e *executors) moveMachine(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	machine, vboxExe, err := e.resolve(ctx, task)
	if err != nil {
		return err
	}
	var meta MoveMetadata
	if task.Metadata == nil {
		return errors.New("move task has no metadata")
	}
	if uerr := json.Unmarshal([]byte(*task.Metadata), &meta); uerr != nil {
		return fmt.Errorf("parse move metadata: %w", uerr)
	}
	if meta.TargetPath == "" {
		return errors.New("target_path is required in task metadata")
	}
	target := filepath.FromSlash(meta.TargetPath)
	if merr := os.MkdirAll(target, 0o750); merr != nil {
		return merr
	}

	defer e.refreshStatus(machine.Name, vboxExe)
	out.Write("stdout", "Moving "+machine.Name+"'s VirtualBox files to "+target+"\n")
	if merr := vbox.MoveVM(ctx, vboxExe, machine.VBoxTarget(), target); merr != nil {
		return merr
	}
	out.Write("stdout", "Move complete (the agent working directory stays where it was)\n")
	return nil
}
