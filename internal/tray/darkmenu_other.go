//go:build !windows

package tray

// enableDarkMenus is Windows-only: the other platforms' native menus already
// follow the system theme.
func enableDarkMenus() {}
