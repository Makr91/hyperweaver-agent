package loginitem

import (
	"errors"

	"golang.org/x/sys/windows/registry"
)

// Windows: the per-user Run key — no elevation needed, applies at every login
// of this user.
const runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`

// itemName is the Run-key value name.
const itemName = "HyperweaverAgent"

func register(exe string, args []string) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer func() {
		_ = key.Close()
	}()
	return key.SetStringValue(itemName, commandLine(exe, args))
}

func unregister() error {
	key, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}
	defer func() {
		_ = key.Close()
	}()
	err = key.DeleteValue(itemName)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	return err
}
