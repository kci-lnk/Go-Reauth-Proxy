package gatewaylog

import (
	"context"
	"time"
)

// Reading logs may queue behind a long scan. Cancellation must cover the lock
// wait too, not only the eventual file scan.
func (w *DailyFileWriter) lockContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if w.mu.TryLock() {
		return nil
	}
	timer := time.NewTicker(5 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			if err := ctx.Err(); err != nil {
				return err
			}
			if w.mu.TryLock() {
				return nil
			}
		}
	}
}
