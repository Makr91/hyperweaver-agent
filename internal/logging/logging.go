// Package logging wires slog to a rotating log file and, optionally, the
// console. File logging is mandatory because the Windows GUI build
// (-H=windowsgui) has no console at all. One writer feeds all sinks via
// io.MultiWriter; per-category loggers (the Node agent's lib/Logger.js
// createCategoryLogger model) share those sinks while carrying their own
// level — logging.categories overrides the global level per category — and a
// category field on every record.
package logging

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/Makr91/hyperweaver-agent/internal/config"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

var (
	catMu      sync.Mutex
	catSink    io.Writer
	catDefault slog.Level
	catLevels  map[string]slog.Level
	catLoggers map[string]*slog.Logger
)

// Setup installs the default slog logger per the configuration and returns a
// closer for the log file sink. The default logger is the "app" category
// (Node parity: the general application logger).
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
		// The Node agent's logging.enable_compression; lumberjack compresses
		// at rotation time rather than after an age threshold.
		Compress: cfg.Logging.Compression,
	}

	sinks := []io.Writer{fileSink}
	if cfg.Logging.Console {
		sinks = append(sinks, os.Stderr)
	}
	sink := io.MultiWriter(sinks...)

	handler := slog.NewTextHandler(sink, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler).With("category", "app"))

	catMu.Lock()
	catSink = sink
	catDefault = level
	catLevels = make(map[string]slog.Level, len(cfg.Logging.Categories))
	for name, categoryLevel := range cfg.Logging.Categories {
		catLevels[name] = parseLevel(categoryLevel)
	}
	catLoggers = map[string]*slog.Logger{}
	catMu.Unlock()

	return fileSink.Close, nil
}

// Category returns the named category's logger: same sinks as the default
// logger, its own level (logging.categories[name], else the global level),
// and a category field on every record — the Node agent's per-category
// winston loggers. Before Setup runs it falls back to the default logger.
func Category(name string) *slog.Logger {
	catMu.Lock()
	defer catMu.Unlock()

	if catSink == nil {
		return slog.Default()
	}
	if logger, ok := catLoggers[name]; ok {
		return logger
	}

	level := catDefault
	if categoryLevel, ok := catLevels[name]; ok {
		level = categoryLevel
	}
	logger := slog.New(slog.NewTextHandler(catSink, &slog.HandlerOptions{Level: level})).
		With("category", name)
	catLoggers[name] = logger
	return logger
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
