package vbox

// NVRAM / UEFI verbs (`modifynvram`) — EFI-firmware machines only; a BIOS
// machine has no variable store and VirtualBox's own error says so.

import "context"

// InitUEFIVarStore (re)creates the machine's UEFI variable store.
func InitUEFIVarStore(ctx context.Context, vboxManage, name string) error {
	return runConfig(ctx, vboxManage, "modifynvram", name, "inituefivarstore")
}

// EnrollMSSignatures enrolls Microsoft's standard DB/KEK signatures — what
// stock Windows/shim-signed Linux boots validate against.
func EnrollMSSignatures(ctx context.Context, vboxManage, name string) error {
	return runConfig(ctx, vboxManage, "modifynvram", name, "enrollmssignatures")
}

// EnrollOraclePK enrolls Oracle's default platform key.
func EnrollOraclePK(ctx context.Context, vboxManage, name string) error {
	return runConfig(ctx, vboxManage, "modifynvram", name, "enrollorclpk")
}

// SetSecureBoot toggles Secure Boot enforcement.
func SetSecureBoot(ctx context.Context, vboxManage, name string, enabled bool) error {
	flag := "--disable"
	if enabled {
		flag = "--enable"
	}
	return runConfig(ctx, vboxManage, "modifynvram", name, "secureboot", flag)
}
