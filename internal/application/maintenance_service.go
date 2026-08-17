package application

import (
	"context"
	"log/slog"
	"time"

	"relay/internal/domain/event"
)

// MaintenanceService periodically purges expired events and runs DuckDB
// checkpoint/vacuum maintenance in the background. It only depends on
// event.Repository (not the moderation port), since purge and checkpoint
// are its only two operations.
type MaintenanceService struct {
	repo     event.Repository
	interval time.Duration
}

func NewMaintenanceService(repo event.Repository, interval time.Duration) *MaintenanceService {
	return &MaintenanceService{repo: repo, interval: interval}
}

// Run executes purge-and-checkpoint sweeps on the configured interval until
// ctx is canceled. A non-positive interval disables the worker entirely.
// Intended to be launched in its own goroutine.
func (m *MaintenanceService) Run(ctx context.Context) {
	if m.interval <= 0 {
		return
	}

	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.sweep(ctx)
		}
	}
}

func (m *MaintenanceService) sweep(ctx context.Context) {
	start := time.Now()

	purged, err := m.repo.PurgeExpired(ctx)
	if err != nil {
		slog.Error("maintenance sweep: purge failed", "error", err)
		return
	}

	if err := m.repo.Checkpoint(ctx); err != nil {
		slog.Error("maintenance sweep: checkpoint failed", "error", err)
		return
	}

	slog.Info("maintenance sweep complete", "purged_events", purged, "duration", time.Since(start))
}
