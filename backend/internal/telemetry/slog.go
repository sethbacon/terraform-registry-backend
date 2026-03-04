package telemetry

import (
	"log/slog"
	"os"
	"strings"
)

// SetupLogger configures the global slog default logger based on the supplied format and level
// strings read from application configuration.
//
// format: "json"  → JSONHandler (machine readable; recommended for production)
//
//	anything else → TextHandler (human readable; suitable for local development)
//
// level: "debug", "info", "warn", "error" (case-insensitive); defaults to "info".
//
// The configured logger is installed as the default so all slog.Info/Warn/Error calls elsewhere
// in the application automatically use it without needing to carry a *slog.Logger in context.
func SetupLogger(format, level string) {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level:     lvl,
		AddSource: lvl == slog.LevelDebug, // include file:line only when debugging
	}

	var handler slog.Handler
	if strings.ToLower(format) == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	slog.SetDefault(slog.New(handler))
	slog.Info("logger initialised", "format", format, "level", lvl.String())
}
