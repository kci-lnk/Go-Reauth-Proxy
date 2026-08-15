package admin

import (
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/stream"
)

type streamRuntimeSnapshot struct {
	rules        []models.StreamRule
	availability *models.StreamAvailability
	policies     map[string]models.CompiledIPSet
}

func captureStreamRuntime(manager *stream.Manager) streamRuntimeSnapshot {
	if manager == nil {
		return streamRuntimeSnapshot{}
	}
	rules, availability, policies := manager.ConfigSnapshotBundle()
	return streamRuntimeSnapshot{rules: rules, availability: availability, policies: policies}
}

func restoreStreamRuntime(
	manager *stream.Manager,
	snapshot streamRuntimeSnapshot,
) error {
	if manager == nil {
		return nil
	}
	return manager.ReconcileConfigBundle(snapshot.rules, snapshot.availability, snapshot.policies)
}
