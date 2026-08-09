package admin

import (
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/stream"
)

type streamRuntimeSnapshot struct {
	rules        []models.StreamRule
	availability *models.StreamAvailability
}

func captureStreamRuntime(manager *stream.Manager) streamRuntimeSnapshot {
	if manager == nil {
		return streamRuntimeSnapshot{}
	}
	rules, availability := manager.ConfigSnapshot()
	return streamRuntimeSnapshot{rules: rules, availability: availability}
}

func restoreStreamRuntime(
	manager *stream.Manager,
	snapshot streamRuntimeSnapshot,
) error {
	if manager == nil {
		return nil
	}
	return manager.ReconcileConfig(snapshot.rules, snapshot.availability)
}
