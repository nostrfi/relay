package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"relay/internal/application"
	"relay/internal/infrastructure/duckdb"
	"relay/internal/interfaces/ws"
	"relay/pkg/logger"
)

// version is injected at build time via -ldflags "-X main.version=..."
var version = "dev"

// storageCountTimeout bounds the startup event count, so a slow or huge
// database delays the log line rather than the relay.
const storageCountTimeout = 5 * time.Second

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

	// Only a run that will actually bind the listener warns about it; a
	// -backup/-restore run has already returned above.
	cfg.WarnOnPermissivePublicListener()

	slog.Info("Starting relay", "version", version)

	// 3. Initialize Repository
	repo, err := duckdb.NewRepository(cfg.Storage.DBPath)
	if err != nil {
		slog.Error("failed to open storage", "error", err)
		os.Exit(1)
	}
	logOpenedStorage(cfg.Storage.DBPath, repo)

	// 4. Initialize Services
	eventService := application.NewEventService(repo)
	moderationService := application.NewModerationService(repo)

	// 5. Initialize Handler
	relayHandler := ws.NewRelayHandlerFull(eventService, moderationService, cfg.RelayInfo, cfg.ResourceLimits, cfg.Auth, cfg.Moderation, cfg.Websocket, version)

	// 6. Setup Server
	server := &http.Server{
		Addr:    cfg.Server.ListenAddr,
		Handler: ws.NewMux(relayHandler, repo.Ping, ws.WithAdminAPI(*cfg), ws.WithEventsAPI(*cfg, eventService)),
	}

	// The metrics listener is a second server rather than another route on
	// the first, because the address is the access control: /metrics is
	// readable by whoever can reach cfg.Server.MetricsListenAddr, which
	// defaults to loopback (nostrfi/workspace#53).
	metricsServer := &http.Server{
		Addr:    cfg.Server.MetricsListenAddr,
		Handler: ws.NewMetricsMux(),
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

	// Fatal on failure, like the listener above: a relay that came up
	// without its metrics listener looks healthy and answers every scrape
	// with a connection refused, which is a misconfiguration best found at
	// startup rather than from a gap in a graph.
	go func() {
		slog.Info("Starting metrics listener", "metrics_listen_addr", cfg.Server.MetricsListenAddr)
		if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("failed to start metrics listener", "error", err, "metrics_listen_addr", cfg.Server.MetricsListenAddr)
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

	// Same deadline as the relay's: the two share the context, and metrics
	// has nothing to drain.
	if err := metricsServer.Shutdown(ctx); err != nil {
		slog.Error("Metrics listener forced to shutdown", "error", err)
	}

	if err := repo.Close(); err != nil {
		slog.Error("Error closing storage", "error", err)
	}

	slog.Info("Relay stopped")
}

// logOpenedStorage names the database this process is actually reading, and
// how many events are in it.
//
// The relay already says which configuration file it loaded; it said nothing
// about which database that configuration pointed it at. An operator whose
// dashboard shows no events cannot otherwise tell an empty relay from one
// reading a different file than the one they filled — a relative db_path
// resolves against the configuration file, so starting the relay a different
// way can silently open a different database (nostrfi/workspace#49).
//
// The count is a startup-only query, and deliberately counts every row,
// including expired and banned events: it answers "is this the database I
// filled", which a filtered count would not.
func logOpenedStorage(dbPath string, repo *duckdb.Repository) {
	absolute := dbPath
	if resolved, err := filepath.Abs(dbPath); err == nil {
		absolute = resolved
	}

	ctx, cancel := context.WithTimeout(context.Background(), storageCountTimeout)
	defer cancel()

	count, err := repo.CountEvents(ctx)
	if err != nil {
		// Not fatal: the relay is open and serving either way.
		slog.Info("storage opened", "db_path", absolute, "events", "unknown", "count_error", err)
		return
	}
	slog.Info("storage opened", "db_path", absolute, "events", count)
}
