package machines

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Makr91/hyperweaver-agent/internal/sshrun"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// The provision-chain children — the ONE document walk (Mark's ruling
// 2026-07-17: there are no phases): machine_wait_ssh polls the guest,
// machine_sync lands ONE folder (transport per the folder's own type: rsync |
// scp; virtualbox attaches a real shared folder), and every walk executor
// below runs ONE document entry exactly where the stored provisioning:
// section placed it. The chain is linear — every child depends_on its
// predecessor — so the walk's LAST task carries final: true and stamps
// provisioner_state on success (stampIfFinal).

// Provision-chain operations. OpProvisionParent survives ONLY as the
// /run-provisioners anchor — the full pipeline chains method and hook
// children directly under the orchestration parent.
const (
	OpProvisionOrchestration = "machine_provision_orchestration"
	OpWaitSSH                = "machine_wait_ssh"
	OpSyncParent             = "machine_sync_parent"
	OpSyncFolder             = "machine_sync"
	OpShellScript            = "machine_shell"
	OpProvisionParent        = "machine_provision_parent"
	OpProvisionPlaybook      = "machine_provision"
	OpRemotePlaybook         = "machine_provision_remote"
	OpDockerCompose          = "machine_docker_compose"
	OpHook                   = "machine_hook"
)

// provisionTaskMetadata is the wait_ssh/sync/shell/provision/remote/docker/
// hook children's metadata — the base's exact shape: {ip, port, credentials,
// folder?, script?, playbook?, compose_file?, hook?} plus final, marking the
// walk's overall LAST task (the provisioned-state stamp rides it — the
// whole-walk stamp ruling). Communicator/WinRM are zoneweaver's exact winrm
// metadata shape (sync 2026-07-17: W-Q1..W-Q5): communicator "winrm" flips
// the SAME ops onto their winrm MECHANISM (never new ops), and the winrm
// block carries the document's RULED knobs — the guest port, transport, and
// peer-verification the connection vars derive from.
type provisionTaskMetadata struct {
	IP           string             `json:"ip"`
	Port         int                `json:"port"`
	Credentials  sshrun.Credentials `json:"credentials"`
	Communicator string             `json:"communicator,omitempty"`
	WinRM        *struct {
		Port                int    `json:"port"`
		Transport           string `json:"transport"`
		SSLPeerVerification bool   `json:"ssl_peer_verification"`
	} `json:"winrm,omitempty"`
	Folder      *Folder   `json:"folder,omitempty"`
	Script      string    `json:"script,omitempty"`
	Playbook    *Playbook `json:"playbook,omitempty"`
	ComposeFile string    `json:"compose_file,omitempty"`
	Hook        *Hook     `json:"hook,omitempty"`
	Final       bool      `json:"final,omitempty"`
}

func readProvisionMetadata(task *tasks.Task) (*provisionTaskMetadata, error) {
	if len(task.Metadata) == 0 {
		return nil, errors.New("provision task has no metadata")
	}
	var meta provisionTaskMetadata
	if err := json.Unmarshal(task.Metadata, &meta); err != nil {
		return nil, fmt.Errorf("parse provision metadata: %w", err)
	}
	if meta.IP == "" {
		return nil, errors.New("ip is required in task metadata")
	}
	if meta.Port == 0 {
		meta.Port = 22
	}
	return &meta, nil
}

// stampIfFinal records provisioner_state.last_provisioned_at when the task is
// the walk's final child. The chain is linear — every child depends_on its
// predecessor and failures cascade-cancel — so the final task's success
// proves the WHOLE walk's (Mark's whole-walk stamp ruling): a partial run
// must never mark the machine provisioned, or the once/not_first filters flip
// after a mid-chain failure. context.Background() keeps the bookkeeping alive
// through cancellation; a stamp failure narrates and never fails the task.
func (e *executors) stampIfFinal(task *tasks.Task, meta *provisionTaskMetadata, out *tasks.OutputWriter) {
	if !meta.Final {
		return
	}
	e.taskProgress(task, 95, "recording_provision_state")
	if serr := e.store.StampProvisionerState(context.Background(), task.MachineName); serr != nil {
		out.Write("stderr", "Failed to record provision state: "+serr.Error()+"\n")
	}
}

// syncParentAnchor is the zone_sync_parent/zone_provision_parent executor —
// the parents are pure anchors: their children's completion drives their
// aggregation (they are created as running containers and finish through the
// parent-progress rollup).
func (e *executors) parentAnchor(_ context.Context, _ *tasks.Task, _ *tasks.OutputWriter) error {
	return nil
}
