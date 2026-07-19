package utm

import (
	"context"
	_ "embed"
	"fmt"
	"regexp"
	"strings"
)

//go:embed scripts/import_vm.applescript
var importVMScript []byte

//go:embed scripts/export_vm.applescript
var exportVMScript []byte

// importedVMID matches the machine identity in the import script's returned
// value ("virtual machine id <ID> of application ...").
var importedVMID = regexp.MustCompile(`virtual machine id ([A-F0-9-]+)`)

// Import brings a .utm bundle into UTM (`import new virtual machine`) and
// returns the new machine's id parsed from the script output — the create
// chain's template-import step.
func Import(ctx context.Context, utmFile string) (string, error) {
	out, err := runOSA(ctx, importVMScript, "AppleScript", utmFile)
	if err != nil {
		return "", fmt.Errorf("UTM import: %w", err)
	}
	match := importedVMID.FindStringSubmatch(out)
	if len(match) < 2 || match[1] == "" {
		return "", fmt.Errorf("UTM import: no machine id in output: %s", strings.TrimSpace(out))
	}
	return match[1], nil
}

// Export writes a machine to a .utm file (`export vm to`) — Import's pair
// and the template-export building block.
func Export(ctx context.Context, id, outputPath string) error {
	_, err := runOSA(ctx, exportVMScript, "AppleScript", id, outputPath)
	return err
}
