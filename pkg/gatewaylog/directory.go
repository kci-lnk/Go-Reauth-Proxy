package gatewaylog

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sync/semaphore"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ValidateLogsDirectory checks access as the gateway user, on the gateway OS.
func ValidateLogsDirectory(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("log directory must be an absolute path: %q", path)
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return fmt.Errorf("create log directory: %w", err)
	}
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("read log directory: %w", err)
	}
	_, readErr := dir.Readdirnames(1)
	_ = dir.Close()
	if readErr != nil && readErr != io.EOF {
		return fmt.Errorf("read log directory: %w", readErr)
	}
	file, err := os.CreateTemp(path, ".fn-knock-log-probe-*")
	if err != nil {
		return fmt.Errorf("write log directory: %w", err)
	}
	name := file.Name()
	_, writeErr := file.Write([]byte("log directory probe\n"))
	syncErr := file.Sync()
	closeErr := file.Close()
	removeErr := os.Remove(name)
	if err := errors.Join(writeErr, syncErr, closeErr, removeErr); err != nil {
		return err
	}
	// A writable directory does not imply an existing daily log is writable.
	daily, err := os.OpenFile(filepath.Join(path, time.Now().Format(dateLayout)+fileExtension), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open daily request log: %w", err)
	}
	return daily.Close()
}

// directoryLock supports cancellation while a long-running read owns storage.
// A pending writer also prevents newer readers from starving a directory switch.
type directoryLock struct {
	once      sync.Once
	semaphore *semaphore.Weighted
}

const directoryLockWeight int64 = 1 << 30

func (l *directoryLock) acquire(ctx context.Context, weight int64) error {
	l.once.Do(func() { l.semaphore = semaphore.NewWeighted(directoryLockWeight) })
	return l.semaphore.Acquire(ctx, weight)
}
func (l *directoryLock) LockContext(ctx context.Context) error {
	return l.acquire(ctx, directoryLockWeight)
}
func (l *directoryLock) RLockContext(ctx context.Context) error { return l.acquire(ctx, 1) }
func (l *directoryLock) Lock()                                  { _ = l.LockContext(context.Background()) }
func (l *directoryLock) RLock()                                 { _ = l.RLockContext(context.Background()) }
func (l *directoryLock) Unlock()                                { l.semaphore.Release(directoryLockWeight) }
func (l *directoryLock) RUnlock()                               { l.semaphore.Release(1) }
