package logger

import (
	"log/slog"
	"os"
	"strings"
)

func Configure() {
	env := os.Getenv("LOG_LEVEL")
	var level slog.Level
	switch strings.ToLower(env) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))

	slog.SetDefault(logger)
}
