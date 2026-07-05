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
}

// Run owns the process main goroutine until the user quits from the menu
// (systray requirement: on macOS the AppKit loop must run on the main
// thread). Start all other work on goroutines before calling Run.
func Run(opts Options) {
	systray.Run(func() { onReady(opts) }, opts.OnExit)
}

// Quit dismisses the tray programmatically (server failure, OS signal),
// unblocking Run and firing OnExit.
func Quit() {
	systray.Quit()
}

func onReady(opts Options) {
	icon, err := iconBytes()
	if err != nil {
		slog.Error("prepare tray icon", "error", err)
	} else {
		systray.SetIcon(icon)
	}
	systray.SetTooltip(opts.Tooltip)

	title := systray.AddMenuItem(opts.Title, "")
	title.Disable()

	systray.AddSeparator()
	openItem := systray.AddMenuItem("Open", "Open the Hyperweaver UI in your browser")
	quitItem := systray.AddMenuItem("Quit", "Stop the agent and exit")

	go func() {
		for {
			select {
			case <-openItem.ClickedCh:
				opts.OnOpen()
			case <-quitItem.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}
