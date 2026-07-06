package tasks

// Operation categories are the queue's concurrency guard (Node-agent model):
// at most one task of a category runs at a time, so two lifecycle operations
// can never race the same hypervisor state. The category set is this agent's
// (design §3) — the Node agent's ~20 illumos categories collapse to the five
// that exist on a VirtualBox/Vagrant host.
const (
	CategoryMachineLifecycle = "machine_lifecycle"
	CategoryMachineProvision = "machine_provision"
	CategoryTemplate         = "template"
	CategoryArtifact         = "artifact"
	CategorySystem           = "system"
)

// operationCategories maps operation names to their category. Operations the
// coming phases register (machines in Phase B, provisioners/assets in C,
// templates in D) are mapped here as they land; an unmapped operation runs
// without a category lock.
var operationCategories = map[string]string{
	// One import at a time: imports copy large trees into the shared
	// provisioner registry directory.
	"provisioner_import": CategorySystem,
}

// OperationCategory returns the concurrency category for an operation, or ""
// when it has none.
func OperationCategory(operation string) string {
	return operationCategories[operation]
}
