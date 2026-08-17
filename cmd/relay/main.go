package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"relay/internal/application"
	"relay/internal/infrastructure/duckdb"
	"relay/internal/interfaces/ws"
	"relay/pkg/logger"
)

// version is injected at build time via -ldflags "-X main.version=..."
var version = "dev"

func main() {
	backupDir := flag.String("backup", "", "export the database to this directory and exit")
	restoreDir := flag.String("restore", "", "import a backup created with -backup into a fresh database and exit")
	flag.Parse()

	logger.Configure()

	// Configuration is loaded before the -backup/-restore flags are handled:
	// both now read the database path from config rather than a hardcoded
	// constant, so a broken config.yaml blocks them too, consistently with
	// normal startup.
	cfg, err := ws.LoadConfig()
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	if *backupDir != "" {
		runBackup(cfg.Storage.DBPath, *backupDir)
		return
	}
	if *restoreDir != "" {
		runRestore(cfg.Storage.DBPath, *restoreDir)
		return
	}

	slog.Info("Starting relay", "version", version)

	// 3. Initialize Repository
	repo, err := duckdb.NewRepository(cfg.Storage.DBPath)
	if err != nil {
		slog.Error("failed to open storage", "error", err)
		os.Exit(1)
	}

	// 4. Initialize Services
	eventService := application.NewEventService(repo)
	moderationService := application.NewModerationService(repo)

	// 5. Initialize Handler
	relayHandler := ws.NewRelayHandlerFull(eventService, moderationService, cfg.RelayInfo, cfg.ResourceLimits, cfg.Auth, cfg.Moderation, cfg.Websocket, version)

	// 6. Setup Server
	server := &http.Server{
		Addr:    cfg.Server.ListenAddr,
		Handler: ws.NewMux(relayHandler, repo.Ping),
	}

	// 6a. Start the background maintenance worker (expired-event purge and
	// checkpoint), stopped alongside the server on shutdown.
	maintenanceCtx, stopMaintenance := context.WithCancel(context.Background())
	maintenance := application.NewMaintenanceService(repo, time.Duration(cfg.Retention.PurgeIntervalSeconds)*time.Second)
	go maintenance.Run(maintenanceCtx)

	// 6b. Graceful Shutdown Setup
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		slog.Info("Starting relay", "listen_addr", cfg.Server.ListenAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("failed to start server", "error", err)
			os.Exit(1)
		}
	}()

	// 7. Wait for termination signal
	<-done
	slog.Info("Shutting down relay...")

	// 8. Graceful Shutdown Execution
	stopMaintenance()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Server.ShutdownTimeoutSeconds)*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
	}

	if err := repo.Close(); err != nil {
		slog.Error("Error closing storage", "error", err)
	}

	slog.Info("Relay stopped")
}
