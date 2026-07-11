//go:build windows

package main

import (
	"context"
	"os"
	"os/signal"
)

func processSignalContext(parent context.Context) (context.Context, context.CancelFunc) {
	// The Windows service supervisor stops the sidecar through RequestShutdown.
	// os.Interrupt keeps console/debug runs graceful as well.
	return signal.NotifyContext(parent, os.Interrupt)
}
