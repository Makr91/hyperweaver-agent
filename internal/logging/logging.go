// Package logging wires slog to a rotating log file and, optionally, the
// console. File logging is mandatory because the Windows GUI build
// (-H=windowsgui) has no console at all. One handler writes to all sinks via
// io.MultiWriter — no custom slog.Handler implementation to maintain.
package logging

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/Makr91/hyperweaver-agent/internal/config"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// Setup installs the default slog logger per the configuration and returns a
// closer for the log file sink.
func Setup(cfg *config.Config) (func() error, error) {
	level := parseLevel(cfg.Logging.Level)

	logPath, err := cfg.LogFilePath()
	if err != nil {
		return nil, err
	}
	logPath, err = safepath.CleanAbs(logPath)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return nil, err
	}

	fileSink := &lumberjack.Logger{
		Filename:   logPath,
		MaxSize:    cfg.Logging.MaxSizeMB,
		MaxBackups: cfg.Logging.MaxBackups,
	}

	sinks := []io.Writer{fileSink}
	if cfg.Logging.Console {
		sinks = append(sinks, os.Stderr)
	}

	handler := slog.NewTextHandler(io.MultiWriter(sinks...), &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
	return fileSink.Close, nil
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
