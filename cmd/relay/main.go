package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"relay/internal/relay/handler"
	"relay/internal/relay/repository"
	"relay/internal/relay/service"
	"relay/pkg/logger"
	"syscall"
	"time"
)

// version is injected at build time via -ldflags "-X main.version=..."
var version = "dev"

func main() {
	backupDir := flag.String("backup", "", "export the database to this directory and exit")
	restoreDir := flag.String("restore", "", "import a backup created with -backup into a fresh database and exit")
	flag.Parse()

	logger.Configure()

	if *backupDir != "" {
		runBackup(*backupDir)
		return
	}
	if *restoreDir != "" {
		runRestore(*restoreDir)
		return
	}

	slog.Info("Starting relay", "version", version)

	// 2. Load Configuration
	cfg, err := handler.LoadConfig()
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	// 3. Initialize Repository
	repo, err := repository.NewDuckDBRepository(dbPath)
	if err != nil {
		slog.Error("failed to open storage", "error", err)
		os.Exit(1)
	}

	// 4. Initialize Service
	relayService := service.NewRelayService(repo)

	// 5. Initialize Handler
	relayHandler := handler.NewRelayHandlerFull(relayService, cfg.RelayInfo, cfg.ResourceLimits, cfg.Auth, cfg.Websocket, version)

	// 6. Setup Server
	server := &http.Server{
		Addr:    ":8080",
		Handler: relayHandler,
	}

	// 6a. Start the background maintenance worker (expired-event purge and
	// checkpoint), stopped alongside the server on shutdown.
	maintenanceCtx, stopMaintenance := context.WithCancel(context.Background())
	maintenance := service.NewMaintenanceService(repo, time.Duration(cfg.Retention.PurgeIntervalSeconds)*time.Second)
	go maintenance.Run(maintenanceCtx)

	// 6b. Graceful Shutdown Setup
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		slog.Info("Starting relay on :8080")
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
	}

	if err := repo.Close(); err != nil {
		slog.Error("Error closing storage", "error", err)
	}

	slog.Info("Relay stopped")
}
