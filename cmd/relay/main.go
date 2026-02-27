package main

import (
	"context"
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

func main() {
	// 1. Configure Logger
	logger.Configure()

	// 2. Load Configuration
	cfg, err := handler.LoadConfig()
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	// 3. Initialize Repository
	repo, err := repository.NewDuckDBRepository("db/relay.db")
	if err != nil {
		slog.Error("failed to open storage", "error", err)
		os.Exit(1)
	}

	// 4. Initialize Service
	relayService := service.NewRelayService(repo)

	// 5. Initialize Handler
	relayHandler := handler.NewRelayHandler(relayService, cfg.RelayInfo)

	// 6. Setup Server
	server := &http.Server{
		Addr:    ":8080",
		Handler: relayHandler,
	}

	// 6. Graceful Shutdown Setup
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
