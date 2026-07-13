// Package tray runs the agent's native system-tray icon and menu: the OS's
// real tray (Shell_NotifyIcon on Windows, NSStatusBar on macOS, StatusNotifier
// on Linux) via fyne.io/systray — never a custom floating UI.
package tray

import (
	"log/slog"

	"fyne.io/systray"
)

// Options configures the tray.
type Options struct {
	// Title is shown as the disabled first menu row (app name + version).
	Title string
	// Tooltip is the icon hover text.
	Tooltip string
	// OnOpen is invoked when the user clicks "Open".
	OnOpen func()
	// OnExit is invoked after the user clicks "Quit", once the tray has
	// shut down; use it for graceful server shutdown.
	OnExit func()
	// The Troubleshooting submenu's actions (the Spotify-style tray pattern,
	// Mark's ask 2026-07-09). The submenu renders only when all are wired.
	OnOpenLog       func()
	OnOpenConfigDir func()
	OnOpenDataDir   func()
	OnRestart       func()
}

// Run owns the process main goroutine until the user quits from the menu
// (systray requirement: on macOS the AppKit loop must run on the main
// thread). Start all other work on goroutines before calling Run.
func Run(opts *Options) {
	systray.Run(func() { onReady(opts) }, opts.OnExit)
}

// Quit dismisses the tray programmatically (server failure, OS signal),
// unblocking Run and firing OnExit.
func Quit() {
	systray.Quit()
}

func onReady(opts *Options) {
	// Before any menu exists: opt the popup menus into the OS app theme
	// (Windows-only mechanism; no-op elsewhere).
	enableDarkMenus()

	icon, err := iconBytes()
	if err != nil {
		slog.Error("prepare tray icon", "error", err)
	} else {
		systray.SetIcon(icon)
	}
	systray.SetTooltip(opts.Tooltip)

	// Primary/left click opens the app (Mark's ruling 2026-07-08 — the
	// Docker-Desktop convention); the context menu stays on right click.
	// Behavior can vary by Linux desktop environment (StatusNotifier hosts
	// may keep left-click on the menu) — the menu's Open item still covers it.
	if opts.OnOpen != nil {
		systray.SetOnTapped(opts.OnOpen)
	}

	title := systray.AddMenuItem(opts.Title, "")
	title.Disable()

	systray.AddSeparator()
	openItem := systray.AddMenuItem("Open", "Open the Hyperweaver UI in your browser")

	// Troubleshooting submenu: the click channels stay valid even when the
	// callbacks are nil (headless never gets here; guards keep it honest).
	var logItem, configItem, dataItem, restartItem *systray.MenuItem
	if opts.OnOpenLog != nil && opts.OnOpenConfigDir != nil &&
		opts.OnOpenDataDir != nil && opts.OnRestart != nil {
		troubleshooting := systray.AddMenuItem("Troubleshooting", "")
		logItem = troubleshooting.AddSubMenuItem("Open Log File", "Open the agent log in your default editor")
		configItem = troubleshooting.AddSubMenuItem("Open Config Folder", "Open the configuration directory")
		dataItem = troubleshooting.AddSubMenuItem("Open Data Folder", "Open the data directory (databases, machines, templates)")
		restartItem = troubleshooting.AddSubMenuItem("Restart Agent", "Restart the agent process")
	}

	quitItem := systray.AddMenuItem("Quit", "Stop the agent and exit")

	// Nil channels block forever in select — absent submenu items simply
	// never fire.
	clicked := func(item *systray.MenuItem) chan struct{} {
		if item == nil {
			return nil
		}
		return item.ClickedCh
	}

	go func() {
		for {
			select {
			case <-openItem.ClickedCh:
				opts.OnOpen()
			case <-clicked(logItem):
				opts.OnOpenLog()
			case <-clicked(configItem):
				opts.OnOpenConfigDir()
			case <-clicked(dataItem):
				opts.OnOpenDataDir()
			case <-clicked(restartItem):
				opts.OnRestart()
			case <-quitItem.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}
