package tasks

// Operation categories are the queue's concurrency guard (Node-agent model):
// at most one task of a category runs at a time, so two lifecycle operations
// can never race the same hypervisor state. The category set is this agent's
// (design §3) — the Node agent's ~20 illumos categories collapse to the five
// that exist on a VirtualBox/Vagrant host.
const (
	CategoryMachineLifecycle    = "machine_lifecycle"
	CategoryMachineProvision    = "machine_provision"
	CategoryTemplate            = "template"
	CategoryArtifact            = "artifact"
	CategorySystem              = "system"
	CategoryNetworkProvisioning = "network_provisioning"
)

// operationCategories maps operation names to their category. An unmapped
// operation runs without a category lock — machine lifecycle operations are
// deliberately unmapped: their guard is the queue's one-running-task-PER-
// MACHINE rule (zoneweaver's per-zone exclusivity), which serializes a
// machine's own operations while different machines' tasks run in parallel
// (SHI's per-server ExecutorManager model — a global lifecycle category
// would forbid parallel machine builds).
var operationCategories = map[string]string{
	// One import at a time: imports copy large trees into the shared
	// provisioner registry directory.
	"provisioner_import": CategorySystem,
	// One cache mutation at a time: scans and downloads write the same
	// registry rows and cache tree.
	"artifact_scan":     CategoryArtifact,
	"artifact_download": CategoryArtifact,
	"hcl_download":      CategoryArtifact,
	// One template download at a time: two same-tuple downloads race the
	// same target files (runtime-proven 2026-07-06 — the loser dies at the
	// rename); the later one then no-ops on the already-exists check.
	"template_download": CategoryTemplate,
	// One agent update at a time — it ends with the process exiting.
	"agent_update": CategorySystem,
	// One provisioning-network mutation at a time (the base's
	// network_provisioning category): setup and teardown converge the same
	// host-only interface + DHCP server.
	"provisioning_network_setup":    CategoryNetworkProvisioning,
	"provisioning_network_teardown": CategoryNetworkProvisioning,
}

// OperationCategory returns the concurrency category for an operation, or ""
// when it has none.
func OperationCategory(operation string) string {
	return operationCategories[operation]
}
