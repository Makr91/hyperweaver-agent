package hostinfo

import (
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// osName reads the marketing name Windows reports about itself
// (e.g. "Windows 10 Pro").
func osName() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "Windows"
	}
	defer func() {
		_ = key.Close()
	}()

	name, _, err := key.GetStringValue("ProductName")
	if err != nil || name == "" {
		return "Windows"
	}
	return name
}

// totalMemory asks kernel32 for the physically installed RAM (reported in
// kilobytes).
func totalMemory() uint64 {
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetPhysicallyInstalledSystemMemory")
	var kilobytes uint64
	ret, _, _ := proc.Call(uintptr(unsafe.Pointer(&kilobytes)))
	if ret == 0 {
		return 0
	}
	return kilobytes * 1024
}
