// Package procattr provides per-OS process attributes for the agent's child
// processes. The agent's Windows build is a GUI-subsystem binary
// (-H=windowsgui): it owns no console, so Windows allocates a brand-new
// visible console window for every console-subsystem child it spawns
// (vagrant, VBoxManage, git, ...) unless each spawn opts out — without this,
// a prerequisite probe flashes a burst of cmd windows across the user's
// desktop.
package procattr
