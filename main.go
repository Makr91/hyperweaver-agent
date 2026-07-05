// Hyperweaver Agent — VirtualBox/Vagrant host-agent for the Hyperweaver
// control plane. Runs a local web server serving the Hyperweaver UI plus the
// Agent API, with a native system-tray icon (LedFx model: manage it from your
// own browser).
package main

//go:generate goversioninfo -platform-specific=true

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/config"
	"github.com/Makr91/hyperweaver-agent/internal/logging"
	"github.com/Makr91/hyperweaver-agent/internal/openbrowser"
	"github.com/Makr91/hyperweaver-agent/internal/server"
	"github.com/Makr91/hyperweaver-agent/internal/tray"
	"github.com/Makr91/hyperweaver-agent/internal/version"
)

// main stays defer-free so os.Exit cannot skip cleanup — all work (and all
// defers) live in run.
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err) //nolint:forbidigo // final error report before exit
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "", "path to config.yaml (default: per-user config dir)")
	headless := flag.Bool("headless", false, "run without the system-tray icon")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.Version) //nolint:forbidigo // --version output is the console contract
		return nil
	}

	cfg, resolvedPath, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	closeLog, err := logging.Setup(cfg)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := closeLog(); cerr != nil {
			fmt.Fprintln(os.Stderr, cerr) //nolint:forbidigo // logger is already closed
		}
	}()

	slog.Info("hyperweaver-agent starting",
		"version", version.Version,
		"config", resolvedPath,
		"headless", *headless,
	)

	srv, err := server.New(cfg)
	if err != nil {
		slog.Error("server setup failed", "error", err)
		return err
	}

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.Start()
	}()

	shutdown := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if serr := srv.Shutdown(ctx); serr != nil {
			slog.Error("server shutdown", "error", serr)
		}
		slog.Info("hyperweaver-agent stopped")
	}

	if *headless {
		return runHeadless(serverErr, shutdown)
	}

	// Quit the tray if the server dies or a signal arrives, so the process
	// never lingers as a dead icon.
	fatal := make(chan error, 1)
	go func() {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		select {
		case srvErr := <-serverErr:
			if srvErr != nil {
				slog.Error("http server failed", "error", srvErr)
				fatal <- srvErr
			}
		case <-ctx.Done():
			slog.Info("signal received, shutting down")
		}
		tray.Quit()
	}()

	// Blocks the main goroutine until Quit (macOS requires the tray's event
	// loop on the main thread).
	tray.Run(tray.Options{
		Title:   "Hyperweaver Agent v" + version.Version,
		Tooltip: "Hyperweaver Agent",
		OnOpen: func() {
			openbrowser.Open(cfg.LocalURL(), cfg.Browser.Path)
		},
		OnExit: shutdown,
	})

	select {
	case srvErr := <-fatal:
		return srvErr
	default:
		return nil
	}
}

func runHeadless(serverErr chan error, shutdown func()) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case srvErr := <-serverErr:
		if srvErr != nil {
			slog.Error("http server failed", "error", srvErr)
			shutdown()
			return srvErr
		}
	case <-ctx.Done():
		slog.Info("signal received, shutting down")
	}
	shutdown()
	return nil
}
