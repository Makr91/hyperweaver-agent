// Package tasks implements the agent's task queue (Agent API v1, ported from
// the Node zoneweaver-agent's TaskQueue): SQLite-persisted tasks with
// priorities, single-predecessor dependency chains, parent-task progress
// aggregation, per-operation-category concurrency locks, live output
// streaming with debounced persistence, and operation-aware cancellation of
// pending AND running tasks (architecture D-F).
package tasks

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"
)

// Task statuses. completed_with_errors is a parent-task terminal state: some
// children failed, some completed (design §3; the Node agent buries this
// distinction in progress_info — here it is the status proper). prepared is
// the upload handshake's holding state (zoneweaver's artifact upload): the
// queue never claims it; the upload handler flips it to pending once the
// file has landed.
const (
	StatusPending             = "pending"
	StatusPrepared            = "prepared"
	StatusRunning             = "running"
	StatusCompleted           = "completed"
	StatusFailed              = "failed"
	StatusCancelled           = "cancelled"
	StatusCompletedWithErrors = "completed_with_errors"
)

// Task priorities (higher runs first), the Node agent's TaskPriority levels
// minus its redundant NORMAL alias.
const (
	PriorityCritical   = 100 // delete operations
	PriorityHigh       = 80  // stop operations
	PriorityMedium     = 60  // start/create operations
	PriorityService    = 50  // service operations
	PriorityLow        = 40  // restart, auto-started consoles
	PriorityBackground = 20  // discovery, periodic scans
)

// Task is one queue entry. JSON field names are the Agent API v1 Task schema.
type Task struct {
	ID string `json:"id"`
	// Target machine name
	MachineName string `json:"machine_name"`
	// Operation kind. Vocabulary: start, stop, suspend, delete, discover, machine_modify (PUT's infrastructure changes), machine_import (OVA/OVF appliance import), machine_move (movevm relocation), machine_unattended_install (VBoxManage answer-file install), restart (never dispatched — a restart is a stop→start chain); create orchestration: machine_create_orchestration (parent), machine_prepare, machine_create_storage, machine_create_config, machine_create_finalize, template_download; provisioning pipeline: machine_provision_orchestration (parent — the document-walk children chain directly under it), machine_wait_ssh, machine_sync_parent, machine_sync (one per folder), machine_hook (one per provisioning.pre[]/post[] sequence-hook entry — pre entries before the first method, post entries after the last), machine_shell (one per provisioning.shell.scripts[] entry, in the document walk), machine_provision (one per ansible local[] playbook entry), machine_provision_remote (one per ansible remote[] entry — ansible-playbook ON the agent host over the guest transport; needs host ansible), machine_docker_compose (one per provisioning.docker.docker_compose[] file — no engine setup; an absent guest engine fails the task honestly), machine_provision_parent (ONLY as the /run-provisioners anchor), machine_syncback_parent, machine_syncback (one per syncback-flagged folder — the post-provision guest→host pull), machine_key_rotate (queued only when settings.vagrant_ssh_insert_key is set and the communicator is not winrm — adopts the box's rotated private key into the working copy after the syncback bracket; never the whole-walk stamp owner); network: provisioning_network_setup, provisioning_network_teardown; consoles/snapshots: reset, pause, resume, snapshot_take (user takes AND the rotation service's scheduled rows — created_by snapshot_rotation), snapshot_restore, snapshot_delete, snapshot_modify (rename and/or description edit via PUT), machine_clone_current (clonevm current-state clone); templates: template_download, template_delete, template_export, template_upload (publish), template_move; filesystem (machine_name "filesystem"): file_move, file_copy, file_archive_create, file_archive_extract; registry/artifacts/system: provisioner_import, provisioner_export (one version → registry-shaped tar.gz + archive sha256 sidecar), provisioner_catalog_install (fetch catalog.json → download the versioned asset → verify sha256 → import), artifact_scan, artifact_download, artifact_upload, artifact_move, artifact_copy, artifact_delete_file, artifact_delete_folder, hcl_download, agent_update, set_hostname (PUT /network/hostname's queued rename — zoneweaver's exact op name, machine_name "system"; the converged wire, sync 2026-07-17).
	Operation string `json:"operation"`
	// completed_with_errors is a parent-task terminal state: some children failed, some completed. prepared is the artifact-upload handshake's holding state (never dispatched; the upload landing at POST /artifacts/upload/{taskId} flips it to pending; agent restart cancels it).
	Status string `json:"status"`
	// Higher runs first: 100 critical, 80 high, 60 medium, 50 service, 40 low, 20 background
	Priority int `json:"priority"`
	// API key name (or system source) that created the task
	CreatedBy string `json:"created_by"`
	// Predecessor that must complete first; its failure or cancellation cancels this task
	DependsOn *string `json:"depends_on"`
	// Progress-aggregation anchor this task reports into
	ParentTaskID *string    `json:"parent_task_id"`
	ErrorMessage *string    `json:"error_message"`
	CreatedAt    time.Time  `json:"created_at"`
	StartedAt    *time.Time `json:"started_at"`
	CompletedAt  *time.Time `json:"completed_at"`
	// Last modification — the since query parameter compares against this
	UpdatedAt time.Time `json:"updatedAt"`
	// JSON-encoded execution parameters
	Metadata        *string `json:"metadata"`
	ProgressPercent float64 `json:"progress_percent"`
	// Freeform progress detail; parent tasks carry {completed_tasks, failed_tasks, total_tasks, status}. machine_provision tasks carry {status} at the coarse phases and — while the playbook runs — the STARTcloud progress callback's live reports as {status: "running_playbook", ansible_percent, message} (the guest's own 0-100% and role label, parsed from the packages' PROGRESS::{json} stdout marker; progress_percent maps it into this task's 40→90 window). Playbooks without the callback simply keep the coarse phases. REGISTRY TRANSFERS (the converged task wire, sync 2026-07-17 — no new endpoints, both agents identical): while template_download streams the .box, template_upload chunk-uploads to the registry, or provisioner_catalog_install downloads the catalog archive, progress_info carries exactly {status: "downloading"|"uploading", received_bytes: <int>, total_bytes: <int|null>} — received_bytes is bytes transferred so far (the ONE field name for BOTH directions), total_bytes is the Content-Length or known file size, JSON null when unknown — and progress_percent maps the bytes into that step's existing window (download 10→60, publish upload 85→95, catalog install 0→90). Updates emit at most every 1s OR every 1% of the total, whichever comes first, with a final update always emitted at completion; an unknown total parks the percent at the window floor (no fake percent) while received_bytes still streams.
	ProgressInfo json.RawMessage `json:"progress_info"`
	// JSON-encoded array of output entries as last flushed — ALWAYS null on GET /tasks (the list never carries output blobs); GET /tasks/{taskId} (detail), GET /tasks/{taskId}/output, and the /tasks/{taskId}/stream WebSocket serve it in full
	Output *string `json:"output"`
}

// NewTask describes a task to enqueue. Inserting the row IS enqueueing
// (Node-agent model); the queue's poll loop picks it up.
type NewTask struct {
	MachineName  string
	Operation    string
	Priority     int
	CreatedBy    string
	DependsOn    *string
	ParentTaskID *string
	Metadata     *string

	// Parent marks a progress-aggregation anchor: the task is created in
	// status running and never dispatched — child completions drive its
	// progress and final status.
	Parent bool

	// Prepared creates the task in status prepared (the artifact-upload
	// handshake): never dispatched until Requeue flips it to pending.
	Prepared bool
}

// newTaskID mints a random UUIDv4 (the Node agent's task id format).
func newTaskID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40 // version 4
	raw[8] = (raw[8] & 0x3f) | 0x80 // RFC 4122 variant
	s := hex.EncodeToString(raw)
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32], nil
}
