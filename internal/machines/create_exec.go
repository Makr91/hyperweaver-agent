package machines

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/Makr91/hyperweaver-agent/internal/provisioner"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// The create orchestration children — zoneweaver's ZoneCreationManager
// (SubTaskExecutors/StorageManager/ConfigurationManager/ZoneLifecycle)
// spoken in VBoxManage, with Hosts.rb's exact VirtualBox directive set.
// Chain: machine_prepare (render the package template + materialize the
// working directory — the provisioning-content step our registry replaces
// zoneweaver's artifact with) → machine_create_storage (media) →
// machine_create_config (createvm/modifyvm/attach) → machine_create_finalize
// (row + document sections). Children hand results forward by updating their
// OWN task metadata (_execution_output) and reading it through depends_on —
// the base's exact handoff.

// Create-chain operations.
const (
	OpCreateOrchestration = "machine_create_orchestration"
	OpCreateStorage       = "machine_create_storage"
	OpCreateConfig        = "machine_create_config"
	OpCreateFinalize      = "machine_create_finalize"
)

// createExecutionOutput is the _execution_output document children pass
// forward.
type createExecutionOutput struct {
	// Document is the machine's own rendered hosts[HostIndex] entry
	// (multi-host converged wire, sync 2026-07-17: M-Q1) —
	// settings/networks/disks/zones plus
	// the provisioner sections (folders/provisioning/vars/roles) — as ordered
	// JSON bytes: the rendered YAML's own key order, which finalize stores
	// verbatim (a map here would alphabetize it).
	Document json.RawMessage `json:"document"`
	// BootdiskPath is the machine's cloned boot medium (for a clone-strategy
	// boot: the shared multiattach base).
	BootdiskPath string `json:"bootdisk_path,omitempty"`
	// BootdiskMultiattach marks a clone-strategy boot.
	BootdiskMultiattach bool `json:"bootdisk_multiattach,omitempty"`
	// MediaCreated tracks created media for reverse-order rollback.
	MediaCreated []string `json:"media_created,omitempty"`
	// UUID is the VirtualBox identity createvm reported.
	UUID string `json:"uuid,omitempty"`
}

// createTaskMetadata is every create child's metadata: the creation spec
// verbatim (the base carries the request body verbatim) plus the running
// _execution_output.
type createTaskMetadata struct {
	Spec            *Spec                  `json:"spec"`
	ExecutionOutput *createExecutionOutput `json:"_execution_output,omitempty"`
}

// readCreateMetadata parses a create child's own metadata.
func readCreateMetadata(task *tasks.Task) (*createTaskMetadata, error) {
	if len(task.Metadata) == 0 {
		return nil, errors.New("create task has no metadata")
	}
	var meta createTaskMetadata
	if err := json.Unmarshal(task.Metadata, &meta); err != nil {
		return nil, fmt.Errorf("parse create metadata: %w", err)
	}
	if meta.Spec == nil {
		return nil, errors.New("create task metadata has no spec")
	}
	return &meta, nil
}

// dependencyOutput loads the _execution_output the dependency child recorded
// (the base reads the storage task through depends_on).
func (e *executors) dependencyOutput(ctx context.Context, task *tasks.Task) (*createExecutionOutput, error) {
	if task.DependsOn == nil {
		return nil, errors.New("create child has no dependency to read")
	}
	previous, err := e.queue.Store().Get(ctx, *task.DependsOn)
	if err != nil {
		return nil, fmt.Errorf("dependency task: %w", err)
	}
	if len(previous.Metadata) == 0 {
		return nil, errors.New("dependency task carries no metadata")
	}
	var meta createTaskMetadata
	if err := json.Unmarshal(previous.Metadata, &meta); err != nil {
		return nil, fmt.Errorf("parse dependency metadata: %w", err)
	}
	if meta.ExecutionOutput == nil {
		return nil, errors.New("dependency task recorded no execution output")
	}
	return meta.ExecutionOutput, nil
}

// recordOutput writes the child's _execution_output into its own metadata.
func (e *executors) recordOutput(ctx context.Context, task *tasks.Task, spec *Spec, out *createExecutionOutput) error {
	raw, err := json.Marshal(&createTaskMetadata{Spec: spec, ExecutionOutput: out})
	if err != nil {
		return err
	}
	return e.queue.Store().UpdateMetadata(ctx, task.ID, string(raw))
}

// machineWorkdir is the machine's working directory under the machines root
// — the provisioning dataset analog, and where the VM's media live.
func (e *executors) machineWorkdir(machineName string) string {
	return filepath.Join(e.env.MachinesDir, provisioner.MachineDirName(machineName))
}
