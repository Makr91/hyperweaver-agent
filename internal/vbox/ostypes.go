package vbox

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/procattr"
)

// OSType is one `VBoxManage list ostypes` entry — the vocabulary
// settings.os_type accepts (createvm/modifyvm --os-type).
type OSType struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	// Family groups the picker — the text before the parenthesis on the
	// Family line: "Windows", "Linux / Debian", "BSD / FreeBSD", "Other".
	Family string `json:"family"`
	// FamilyDescription is the parenthesized remainder of the Family line
	// ("Microsoft Windows", "Linux", ...).
	FamilyDescription string `json:"family_description,omitempty"`
	// Architecture is VirtualBox's own vocabulary: "x86", "x86 (64-bit)",
	// "ARMv8 (64-bit)".
	Architecture string `json:"architecture"`
}

// ListOSTypes enumerates the guest OS types THIS VirtualBox build supports
// (7.2 block format, verified on Mark's host 2026-07-09: an
// "ID / Description: <id> -- <desc>" line followed by Family: and
// Architecture: lines, blocks separated by blank lines).
func ListOSTypes(ctx context.Context, vboxManage string) ([]OSType, error) {
	cmd := exec.CommandContext(ctx, vboxManage, "list", "ostypes")
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("VBoxManage list ostypes: %w", err)
	}

	types := []OSType{}
	var current *OSType
	for _, raw := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "ID / Description:"):
			entry := strings.TrimSpace(strings.TrimPrefix(line, "ID / Description:"))
			id, description, found := strings.Cut(entry, " -- ")
			if !found {
				continue
			}
			types = append(types, OSType{
				ID:          strings.TrimSpace(id),
				Description: strings.TrimSpace(description),
			})
			current = &types[len(types)-1]
		case current != nil && strings.HasPrefix(line, "Family:"):
			family := strings.TrimSpace(strings.TrimPrefix(line, "Family:"))
			if open := strings.LastIndex(family, "("); open > 0 && strings.HasSuffix(family, ")") {
				current.FamilyDescription = family[open+1 : len(family)-1]
				family = strings.TrimSpace(family[:open])
			}
			current.Family = family
		case current != nil && strings.HasPrefix(line, "Architecture:"):
			current.Architecture = strings.TrimSpace(strings.TrimPrefix(line, "Architecture:"))
		}
	}
	return types, nil
}
