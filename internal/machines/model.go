// Package machines implements the agent's machine registry and lifecycle
// (Agent API v1 machines surface): VirtualBox VMs registered in
// agent.sqlite, kept truthful by queued discover tasks (VirtualBox
// authoritative, SHI's getRealStatus rule), and operated through tasks
// executed by the queue. Lifecycle is hypervisor commands only — the Node
// agent's ZoneManager model spoken in VBoxManage; vagrant identifies which
// project owns a VM (provenance for the provisioning phase) and never drives
// lifecycle. Machines built OUTSIDE the agent (the VirtualBox GUI, an old
// SHI install) are first-class: discovery imports them.
package machines

import (
	"encoding/json"
	"time"
)

// Machine statuses. VirtualBox state names map onto these; "configured"
// means a registry row with no VM behind it yet (SHI's clone model: no VM
// until first start).
const (
	StatusConfigured = "configured"
	StatusRunning    = "running"
	StatusStopped    = "stopped"
	StatusSuspended  = "suspended"
	StatusPaused     = "paused"
	StatusAborted    = "aborted"
	StatusStarting   = "starting"
	StatusStopping   = "stopping"
	StatusUnknown    = "unknown"
)

// Machine backings — provenance metadata (lifecycle always drives VBoxManage
// directly).
const (
	// BackingVagrant machines are owned by a vagrant project (Home) — the
	// provisioning operations run there.
	BackingVagrant = "vagrant"
	// BackingVBox machines exist only in VirtualBox.
	BackingVBox = "vbox"
)

// Machine is one registry row (the Agent API v1 Machine schema); backing and
// home are this agent's dual-path fields.
type Machine struct {
	ID             int64           `json:"id"`
	Name           string          `json:"name"`
	Host           string          `json:"host"`
	Status         string          `json:"status"`
	Backing        string          `json:"backing"`
	Home           *string         `json:"home"`
	UUID           *string         `json:"uuid"`
	ServerID       *string         `json:"server_id"`
	IsOrphaned     bool            `json:"is_orphaned"`
	AutoDiscovered bool            `json:"auto_discovered"`
	LastSeen       *time.Time      `json:"last_seen"`
	Notes          *string         `json:"notes"`
	Tags           json.RawMessage `json:"tags"`
	Configuration  json.RawMessage `json:"configuration"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updatedAt"`
}

// MapVBoxState translates a VirtualBox VMState into the machine status
// vocabulary.
func MapVBoxState(state string) string {
	switch state {
	case "running":
		return StatusRunning
	case "poweroff", "powered off":
		return StatusStopped
	case "saved":
		return StatusSuspended
	case "paused":
		return StatusPaused
	case "aborted", "aborted-saved":
		return StatusAborted
	case "starting", "restoring":
		return StatusStarting
	case "stopping", "saving":
		return StatusStopping
	default:
		return StatusUnknown
	}
}
