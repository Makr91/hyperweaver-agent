// Package logging wires slog to a rotating JSON file and, optionally, a
// human-readable console handler. File logging is mandatory because the
// Windows GUI build (-H=windowsgui) has no console at all.
package logging

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"

	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/Makr91/hyperweaver-agent/internal/config"
)

// Setup installs the default slog logger per the configuration and returns a
// closer for the log file sink.
func Setup(cfg *config.Config) (func() error, error) {
	level := parseLevel(cfg.Logging.Level)

	logPath, err := cfg.LogFilePath()
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

	handlers := []slog.Handler{
		slog.NewJSONHandler(fileSink, &slog.HandlerOptions{Level: level}),
	}
	if cfg.Logging.Console {
		handlers = append(handlers, slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	}

	slog.SetDefault(slog.New(fanout{handlers: handlers}))
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

// fanout duplicates records to every wrapped handler.
type fanout struct {
	handlers []slog.Handler
}

func (f fanout) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range f.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

//nolint:gocritic // hugeParam: the signature is fixed by the slog.Handler interface
func (f fanout) Handle(ctx context.Context, record slog.Record) error {
	var firstErr error
	for _, h := range f.handlers {
		if !h.Enabled(ctx, record.Level) {
			continue
		}
		if err := h.Handle(ctx, record.Clone()); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (f fanout) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := make([]slog.Handler, len(f.handlers))
	for i, h := range f.handlers {
		next[i] = h.WithAttrs(attrs)
	}
	return fanout{handlers: next}
}

func (f fanout) WithGroup(name string) slog.Handler {
	next := make([]slog.Handler, len(f.handlers))
	for i, h := range f.handlers {
		next[i] = h.WithGroup(name)
	}
	return fanout{handlers: next}
}
