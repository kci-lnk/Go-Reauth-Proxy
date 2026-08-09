package proxy

import (
	"errors"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/gatewaylog"
	"go-reauth-proxy/pkg/models"
)

func TestSetProxyProtocolForceInvokesHookWhenChanged(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	calls := 0
	handler.SetProxyProtocolForceChangeHook(func() { calls++ })
	if err := handler.SetProxyProtocolForce(true); err != nil {
		t.Fatalf("SetProxyProtocolForce() returned error: %v", err)
	}
	if calls != 1 || !handler.GetProxyProtocolForce() {
		t.Fatalf("calls=%d force=%v, want one hook and enabled", calls, handler.GetProxyProtocolForce())
	}
}

func TestRouteUpdatesClearAuthenticationCaches(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	storeEntries := func() {
		now := time.Now()
		handler.authCacheStore("stale-auth", authCacheEntry{
			expiresAt:   now.Add(time.Minute),
			identityKey: "identity",
		}, now)
		handler.preflightCacheStore("stale-preflight", preflightCacheEntry{
			expiresAt:   now.Add(time.Minute),
			identityKey: "identity",
		}, now)
	}
	assertEmpty := func() {
		t.Helper()
		handler.authCache.mu.RLock()
		authCount := len(handler.authCache.entries)
		handler.authCache.mu.RUnlock()
		handler.preflightCache.mu.RLock()
		preflightCount := len(handler.preflightCache.entries)
		handler.preflightCache.mu.RUnlock()
		if authCount != 0 || preflightCount != 0 {
			t.Fatalf("cache entries after route update = auth:%d preflight:%d", authCount, preflightCount)
		}
	}

	storeEntries()
	if err := handler.SetRules([]models.Rule{{
		Path:   "/app",
		Target: "http://127.0.0.1:8080",
	}}); err != nil {
		t.Fatalf("SetRules() returned error: %v", err)
	}
	assertEmpty()

	storeEntries()
	if err := handler.SetHostRules([]models.HostRule{{
		Host:   "app.example.test",
		Target: "http://127.0.0.1:8080",
	}}); err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}
	assertEmpty()
}

func TestFnosRouteIdentityTracksPortDeleteAndReAddLifecycle(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	request := httptest.NewRequest("GET", "https://nas.example.test/s/share", nil)
	hostRule := models.HostRule{
		Host:         "nas.example.test",
		Target:       "http://127.0.0.1:5666",
		PreserveHost: true,
	}

	if err := handler.SetHostRules([]models.HostRule{hostRule}); err != nil {
		t.Fatalf("SetHostRules(initial) returned error: %v", err)
	}
	initialSnapshot := handler.snapshotForRequest()
	initialRule := matchHostRule(request, initialSnapshot)
	initialBackend := handler.routedBackendForRequest(
		request,
		initialSnapshot,
		initialRule,
		nil,
		nil,
	)
	if initialBackend == nil || initialBackend.routeID == nil || *initialBackend.routeID == "" {
		t.Fatalf("initial routed backend = %#v, want non-empty route identity", initialBackend)
	}

	if err := handler.SetHostRules([]models.HostRule{hostRule}); err != nil {
		t.Fatalf("SetHostRules(unchanged) returned error: %v", err)
	}
	unchangedSnapshot := handler.snapshotForRequest()
	unchangedRule := matchHostRule(request, unchangedSnapshot)
	unchangedBackend := handler.routedBackendForRequest(
		request,
		unchangedSnapshot,
		unchangedRule,
		nil,
		nil,
	)
	if unchangedBackend == nil || unchangedBackend.routeID == nil {
		t.Fatalf("unchanged routed backend = %#v", unchangedBackend)
	}
	if *unchangedBackend.routeID != *initialBackend.routeID {
		t.Fatal("unchanged route synchronization rotated the route identity")
	}

	if err := handler.SetHostRules([]models.HostRule{
		hostRule,
		{
			Host:   "unrelated.example.test",
			Target: "http://127.0.0.1:8080",
		},
	}); err != nil {
		t.Fatalf("SetHostRules(unrelated add) returned error: %v", err)
	}
	unrelatedSnapshot := handler.snapshotForRequest()
	unrelatedRule := matchHostRule(request, unrelatedSnapshot)
	unrelatedBackend := handler.routedBackendForRequest(
		request,
		unrelatedSnapshot,
		unrelatedRule,
		nil,
		nil,
	)
	if unrelatedBackend == nil || unrelatedBackend.routeID == nil {
		t.Fatalf("routed backend after unrelated edit = %#v", unrelatedBackend)
	}
	if *unrelatedBackend.routeID != *initialBackend.routeID {
		t.Fatal("unrelated route edit rotated the FNOS route identity")
	}

	hostRule.Target = "http://127.0.0.1:5667"
	if err := handler.SetHostRules([]models.HostRule{hostRule}); err != nil {
		t.Fatalf("SetHostRules(port change) returned error: %v", err)
	}
	changedSnapshot := handler.snapshotForRequest()
	changedRule := matchHostRule(request, changedSnapshot)
	changedBackend := handler.routedBackendForRequest(
		request,
		changedSnapshot,
		changedRule,
		nil,
		nil,
	)
	if changedBackend == nil || changedBackend.routeID == nil {
		t.Fatalf("changed routed backend = %#v", changedBackend)
	}
	if *changedBackend.routeID == *initialBackend.routeID {
		t.Fatal("port change reused the previous route identity")
	}
	if got := *changedBackend.target; got != "http://127.0.0.1:5667" {
		t.Fatalf("port-changed target = %q", got)
	}

	if err := handler.FlushHostRules(); err != nil {
		t.Fatalf("FlushHostRules() returned error: %v", err)
	}
	deletedSnapshot := handler.snapshotForRequest()
	if deletedRule := matchHostRule(request, deletedSnapshot); deletedRule != nil {
		t.Fatalf("deleted mapping still matched: %#v", deletedRule)
	}
	if deletedBackend := handler.routedBackendForRequest(
		request,
		deletedSnapshot,
		nil,
		nil,
		nil,
	); deletedBackend != nil {
		t.Fatalf("deleted mapping routed backend = %#v, want nil", deletedBackend)
	}

	if err := handler.SetHostRules([]models.HostRule{hostRule}); err != nil {
		t.Fatalf("SetHostRules(re-add) returned error: %v", err)
	}
	readdedSnapshot := handler.snapshotForRequest()
	readdedRule := matchHostRule(request, readdedSnapshot)
	readdedBackend := handler.routedBackendForRequest(
		request,
		readdedSnapshot,
		readdedRule,
		nil,
		nil,
	)
	if readdedBackend == nil || readdedBackend.routeID == nil {
		t.Fatalf("re-added routed backend = %#v", readdedBackend)
	}
	if *readdedBackend.routeID == *changedBackend.routeID {
		t.Fatal("re-added mapping reused the deleted mapping identity")
	}
	if readdedBackend.cacheIdentity() == changedBackend.cacheIdentity() {
		t.Fatal("re-added mapping reused the deleted mapping authentication cache identity")
	}
}

func TestSetProxyProtocolForceSkipsHookWhenUnchanged(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetProxyProtocolForce(false); err != nil {
		t.Fatalf("SetProxyProtocolForce() returned error: %v", err)
	}
	calls := 0
	handler.SetProxyProtocolForceChangeHook(func() { calls++ })
	if err := handler.SetProxyProtocolForce(false); err != nil {
		t.Fatalf("SetProxyProtocolForce() returned error: %v", err)
	}
	if calls != 0 {
		t.Fatalf("hook calls = %d, want 0", calls)
	}
}

func TestSetProxyProtocolForceRollsBackOnSaveFailure(t *testing.T) {
	handler, manager := newAdditionalProxyTestHandler(t)
	before := handler.GetProxyProtocolForce()
	beforeSnapshot := handler.snapshotForRequest().proxyProtocolForce
	calls := 0
	handler.SetProxyProtocolForceChangeHook(func() { calls++ })
	breakConfigPersistence(t, manager)

	if err := handler.SetProxyProtocolForce(!before); err == nil {
		t.Fatal("SetProxyProtocolForce() returned nil error")
	}
	if got := handler.GetProxyProtocolForce(); got != before {
		t.Fatalf("configured proxy protocol force = %v, want %v", got, before)
	}
	if got := handler.snapshotForRequest().proxyProtocolForce; got != beforeSnapshot {
		t.Fatalf("snapshot proxy protocol force = %v, want %v", got, beforeSnapshot)
	}
	if calls != 0 {
		t.Fatalf("hook calls = %d, want 0", calls)
	}
}

func TestSetSSLDeploymentDoesNotPublishOnSaveFailure(t *testing.T) {
	handler, manager := newAdditionalProxyTestHandler(t)
	before := handler.GetSSLDeployment()
	beforeInfo := handler.GetSSLInfo()
	calls := 0
	handler.SetSSLChangeHook(func() { calls++ })
	certPEM, keyPEM := makeTestCertificatePEM(t, []string{"save-failure.example.test"}, nil)
	breakConfigPersistence(t, manager)

	err := handler.SetSSLDeployment(models.SSLConfig{
		Certificates: []models.SSLDeployedCertificate{{
			ID:        "save-failure",
			Cert:      certPEM,
			Key:       keyPEM,
			IsDefault: true,
		}},
	})
	if err == nil {
		t.Fatal("SetSSLDeployment() returned nil error")
	}
	after := handler.GetSSLDeployment()
	if after.DeploymentMode != before.DeploymentMode ||
		len(after.Certificates) != len(before.Certificates) {
		t.Fatalf("SSL deployment after failure = %#v, want %#v", after, before)
	}
	afterInfo := handler.GetSSLInfo()
	if afterInfo.Enabled != beforeInfo.Enabled ||
		afterInfo.DeploymentMode != beforeInfo.DeploymentMode ||
		len(afterInfo.Certificates) != len(beforeInfo.Certificates) {
		t.Fatalf("SSL runtime after failure = %#v, want %#v", afterInfo, beforeInfo)
	}
	if calls != 0 {
		t.Fatalf("SSL hook calls = %d, want 0", calls)
	}
}

func TestSetGatewayListenerConfigDoesNotPersistWhenRuntimeApplyFails(t *testing.T) {
	handler, manager := newAdditionalProxyTestHandler(t)
	previous := handler.GetGatewayListenerConfig()
	nextScope := models.GatewayListenerScopeLoopback
	if previous.Scope == nextScope {
		nextScope = models.GatewayListenerScopeAll
	}

	var applied models.GatewayListenerConfig
	handler.SetGatewayListenerConfigChangeHook(func(candidate models.GatewayListenerConfig) error {
		applied = candidate
		if got := handler.GetGatewayListenerConfig(); got != previous {
			t.Fatalf("runtime hook observed listener config %#v, want previous %#v", got, previous)
		}
		return errors.New("listener port is unavailable")
	})

	err := handler.SetGatewayListenerConfig(models.GatewayListenerConfig{Scope: nextScope})
	if err == nil {
		t.Fatal("SetGatewayListenerConfig() succeeded after a failed runtime apply")
	}
	if applied.Scope != nextScope {
		t.Fatalf("runtime hook candidate = %#v, want scope %q", applied, nextScope)
	}
	if got := handler.GetGatewayListenerConfig(); got != previous {
		t.Fatalf("listener config after failed runtime apply = %#v, want %#v", got, previous)
	}
	stored, loadErr := manager.Load()
	if loadErr != nil {
		t.Fatalf("Load() returned error: %v", loadErr)
	}
	if got := stored.GatewayListener; got != previous {
		t.Fatalf("persisted listener config after failed runtime apply = %#v, want %#v", got, previous)
	}
}

func TestSetGatewayListenerConfigPersistsOnlyAfterRuntimeApplySucceeds(t *testing.T) {
	handler, manager := newAdditionalProxyTestHandler(t)
	previous := handler.GetGatewayListenerConfig()
	nextScope := models.GatewayListenerScopeLoopback
	if previous.Scope == nextScope {
		nextScope = models.GatewayListenerScopeAll
	}

	calls := 0
	handler.SetGatewayListenerConfigChangeHook(func(candidate models.GatewayListenerConfig) error {
		calls++
		if candidate.Scope != nextScope {
			t.Fatalf("runtime hook candidate = %#v, want scope %q", candidate, nextScope)
		}
		if got := handler.GetGatewayListenerConfig(); got != previous {
			t.Fatalf("runtime hook observed listener config %#v, want previous %#v", got, previous)
		}
		return nil
	})

	if err := handler.SetGatewayListenerConfig(models.GatewayListenerConfig{Scope: nextScope}); err != nil {
		t.Fatalf("SetGatewayListenerConfig() returned error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("runtime hook calls = %d, want 1", calls)
	}
	if got := handler.GetGatewayListenerConfig().Scope; got != nextScope {
		t.Fatalf("listener scope = %q, want %q", got, nextScope)
	}
	stored, loadErr := manager.Load()
	if loadErr != nil {
		t.Fatalf("Load() returned error: %v", loadErr)
	}
	if got := stored.GatewayListener.Scope; got != nextScope {
		t.Fatalf("persisted listener scope = %q, want %q", got, nextScope)
	}
}

func TestSetDefaultRouteEmptyResetsToSelect(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetDefaultRoute(""); err != nil {
		t.Fatalf("SetDefaultRoute() returned error: %v", err)
	}
	if got := handler.GetDefaultRoute(); got != "/__select__" {
		t.Fatalf("DefaultRoute = %q", got)
	}
}

func TestSetDefaultRoutePersistsToConfig(t *testing.T) {
	handler, manager := newAdditionalProxyTestHandler(t)
	if err := handler.SetRules([]models.Rule{{Path: "/app", Target: "http://127.0.0.1:8080"}}); err != nil {
		t.Fatalf("SetRules() returned error: %v", err)
	}
	if err := handler.SetDefaultRoute("/app"); err != nil {
		t.Fatalf("SetDefaultRoute() returned error: %v", err)
	}
	cfg, err := manager.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.DefaultRoute != "/app" {
		t.Fatalf("persisted DefaultRoute = %q", cfg.DefaultRoute)
	}
}

func TestSetAuthConfigNormalizesDefaultsAndTrimmedFields(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	err := handler.SetAuthConfig(models.AuthConfig{
		PublicAuthBaseURL:     " https://auth.example.test/// ",
		AuthHost:              " App.Example.Test:443 ",
		AuthCacheTTL:          -1,
		AuthCacheFailTTL:      -1,
		PublicHTTPPort:        -80,
		PublicHTTPSPort:       -443,
		EdgeClientIPEnabled:   true,
		AliyunESAEnabled:      true,
		TencentEdgeOneEnabled: true,
	})
	if err != nil {
		t.Fatalf("SetAuthConfig() returned error: %v", err)
	}
	got := handler.GetAuthConfig()
	if got.AuthPort != 7997 || got.AuthURL != "/api/auth/verify" || got.LoginURL != "/login" || got.PreflightURL != "/api/auth/preflight" {
		t.Fatalf("auth defaults not applied: %#v", got)
	}
	if got.PublicAuthBaseURL != "https://auth.example.test///" || got.AuthHost != "app.example.test" {
		t.Fatalf("auth fields not normalized: %#v", got)
	}
	if got.AuthCacheTTL != 0 || got.AuthCacheFailTTL != 0 || got.PublicHTTPPort != 0 || got.PublicHTTPSPort != 0 {
		t.Fatalf("negative auth values not clamped: %#v", got)
	}
	if got.AliyunESAEnabled || !got.TencentEdgeOneEnabled {
		t.Fatalf("edge vendor mutual exclusion not applied: %#v", got)
	}
}

func TestSetReverseProxyThrottleNormalizesInvalidEnabledValues(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	err := handler.SetReverseProxyThrottle(models.ReverseProxyThrottleConfig{Enabled: true})
	if err != nil {
		t.Fatalf("SetReverseProxyThrottle() returned error: %v", err)
	}
	got := handler.GetReverseProxyThrottle()
	if !got.Enabled || got.RequestsPerSecond <= 0 || got.Burst <= 0 || got.BlockSeconds <= 0 {
		t.Fatalf("throttle config = %#v", got)
	}
}

func TestSetGatewayVisibilityStoresCopy(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{Enabled: true, CIDRs: []string{"192.168.0.0/16"}}); err != nil {
		t.Fatalf("SetGatewayVisibility() returned error: %v", err)
	}
	got := handler.GetGatewayVisibility()
	got.CIDRs[0] = "10.0.0.0/8"
	if handler.GetGatewayVisibility().CIDRs[0] != "192.168.0.0/16" {
		t.Fatal("GetGatewayVisibility() did not return a defensive copy")
	}
}

func TestConcurrentGatewayVisibilitySettersPublishTheSameFinalConfig(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	const setters = 32
	start := make(chan struct{})
	errors := make(chan error, setters)
	var wait sync.WaitGroup
	for index := range setters {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errors <- handler.SetGatewayVisibility(models.GatewayVisibilityConfig{
				Enabled: true,
				CIDRs:   []string{fmt.Sprintf("10.%d.0.0/16", index)},
			})
		}()
	}
	close(start)
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("SetGatewayVisibility() returned error: %v", err)
		}
	}

	persisted := handler.GetGatewayVisibility()
	runtime := handler.gatewayVisibility.getConfig()
	if runtime.Enabled != persisted.Enabled ||
		runtime.UpdatedAt != persisted.UpdatedAt ||
		runtime.PolicyID != persisted.PolicyID ||
		!slices.Equal(runtime.CIDRs, persisted.CIDRs) {
		t.Fatalf("runtime visibility = %#v, persisted visibility = %#v", runtime, persisted)
	}
}

func TestConcurrentRuntimeConfigSettersPublishThePersistedFinalConfig(t *testing.T) {
	t.Run("reverse proxy throttle", func(t *testing.T) {
		handler, manager := newAdditionalProxyTestHandler(t)
		const setters = 32
		start := make(chan struct{})
		errors := make(chan error, setters)
		var wait sync.WaitGroup
		for index := range setters {
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				errors <- handler.SetReverseProxyThrottle(models.ReverseProxyThrottleConfig{
					Enabled:           true,
					RequestsPerSecond: index + 1,
					Burst:             index + 101,
					BlockSeconds:      index + 201,
				})
			}()
		}
		close(start)
		wait.Wait()
		close(errors)
		for err := range errors {
			if err != nil {
				t.Fatalf("SetReverseProxyThrottle() returned error: %v", err)
			}
		}
		configured := handler.GetReverseProxyThrottle()
		if runtime := handler.reverseProxyThrottle.getConfig(); runtime != configured {
			t.Fatalf("runtime throttle = %#v, configured throttle = %#v", runtime, configured)
		}
		persisted, err := manager.Load()
		if err != nil {
			t.Fatalf("Load() returned error: %v", err)
		}
		if persisted.ReverseProxyThrottle != configured {
			t.Fatalf("persisted throttle = %#v, configured throttle = %#v", persisted.ReverseProxyThrottle, configured)
		}
	})

	t.Run("forwarded headers", func(t *testing.T) {
		handler, manager := newAdditionalProxyTestHandler(t)
		const setters = 32
		start := make(chan struct{})
		errors := make(chan error, setters)
		var wait sync.WaitGroup
		for index := range setters {
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				errors <- handler.SetForwardedHeadersConfig(models.ForwardedHeadersConfig{
					Enabled:     true,
					OmitTargets: []string{fmt.Sprintf("http://127.0.0.1:%d", 8000+index)},
					UpdatedAt:   fmt.Sprintf("forwarded-%d", index),
				})
			}()
		}
		close(start)
		wait.Wait()
		close(errors)
		for err := range errors {
			if err != nil {
				t.Fatalf("SetForwardedHeadersConfig() returned error: %v", err)
			}
		}
		configured := handler.GetForwardedHeadersConfig()
		runtime := handler.forwardedHeaders.getConfig()
		if runtime.Enabled != configured.Enabled ||
			runtime.UpdatedAt != configured.UpdatedAt ||
			!slices.Equal(runtime.OmitTargets, configured.OmitTargets) {
			t.Fatalf("runtime forwarded headers = %#v, configured = %#v", runtime, configured)
		}
		persisted, err := manager.Load()
		if err != nil {
			t.Fatalf("Load() returned error: %v", err)
		}
		if persisted.ForwardedHeaders.Enabled != configured.Enabled ||
			persisted.ForwardedHeaders.UpdatedAt != configured.UpdatedAt ||
			!slices.Equal(persisted.ForwardedHeaders.OmitTargets, configured.OmitTargets) {
			t.Fatalf("persisted forwarded headers = %#v, configured = %#v", persisted.ForwardedHeaders, configured)
		}
	})

	t.Run("preserve host", func(t *testing.T) {
		handler, manager := newAdditionalProxyTestHandler(t)
		const setters = 32
		start := make(chan struct{})
		errors := make(chan error, setters)
		var wait sync.WaitGroup
		for index := range setters {
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				errors <- handler.SetPreserveHostConfig(models.PreserveHostConfig{
					Enabled:     index%2 == 0,
					OmitTargets: []string{fmt.Sprintf("http://127.0.0.1:%d", 9000+index)},
					UpdatedAt:   fmt.Sprintf("preserve-%d", index),
				})
			}()
		}
		close(start)
		wait.Wait()
		close(errors)
		for err := range errors {
			if err != nil {
				t.Fatalf("SetPreserveHostConfig() returned error: %v", err)
			}
		}
		configured := handler.GetPreserveHostConfig()
		runtime := handler.preserveHost.getConfig()
		if runtime.Enabled != configured.Enabled ||
			runtime.UpdatedAt != configured.UpdatedAt ||
			!slices.Equal(runtime.OmitTargets, configured.OmitTargets) {
			t.Fatalf("runtime preserve host = %#v, configured = %#v", runtime, configured)
		}
		persisted, err := manager.Load()
		if err != nil {
			t.Fatalf("Load() returned error: %v", err)
		}
		if persisted.PreserveHost.Enabled != configured.Enabled ||
			persisted.PreserveHost.UpdatedAt != configured.UpdatedAt ||
			!slices.Equal(persisted.PreserveHost.OmitTargets, configured.OmitTargets) {
			t.Fatalf("persisted preserve host = %#v, configured = %#v", persisted.PreserveHost, configured)
		}
	})
}

func TestRuntimeConfigSettersRollbackOnSaveFailure(t *testing.T) {
	t.Run("reverse proxy throttle", func(t *testing.T) {
		handler, manager := newAdditionalProxyTestHandler(t)
		beforeConfigured := handler.GetReverseProxyThrottle()
		beforeRuntime := handler.reverseProxyThrottle.getConfig()
		breakConfigPersistence(t, manager)

		err := handler.SetReverseProxyThrottle(models.ReverseProxyThrottleConfig{
			Enabled:           true,
			RequestsPerSecond: 1,
			Burst:             2,
			BlockSeconds:      3,
		})
		if err == nil {
			t.Fatal("SetReverseProxyThrottle() returned nil error")
		}
		if configured := handler.GetReverseProxyThrottle(); configured != beforeConfigured {
			t.Fatalf("configured throttle after failure = %#v, want %#v", configured, beforeConfigured)
		}
		if runtime := handler.reverseProxyThrottle.getConfig(); runtime != beforeRuntime {
			t.Fatalf("runtime throttle after failure = %#v, want %#v", runtime, beforeRuntime)
		}
	})

	t.Run("forwarded headers", func(t *testing.T) {
		handler, manager := newAdditionalProxyTestHandler(t)
		beforeConfigured := handler.GetForwardedHeadersConfig()
		beforeRuntime := handler.forwardedHeaders.getConfig()
		breakConfigPersistence(t, manager)

		err := handler.SetForwardedHeadersConfig(models.ForwardedHeadersConfig{
			Enabled:     true,
			OmitTargets: []string{"http://127.0.0.1:8080"},
			UpdatedAt:   "changed",
		})
		if err == nil {
			t.Fatal("SetForwardedHeadersConfig() returned nil error")
		}
		configured := handler.GetForwardedHeadersConfig()
		if configured.Enabled != beforeConfigured.Enabled ||
			configured.UpdatedAt != beforeConfigured.UpdatedAt ||
			!slices.Equal(configured.OmitTargets, beforeConfigured.OmitTargets) {
			t.Fatalf("configured forwarded headers after failure = %#v, want %#v", configured, beforeConfigured)
		}
		runtime := handler.forwardedHeaders.getConfig()
		if runtime.Enabled != beforeRuntime.Enabled ||
			runtime.UpdatedAt != beforeRuntime.UpdatedAt ||
			!slices.Equal(runtime.OmitTargets, beforeRuntime.OmitTargets) {
			t.Fatalf("runtime forwarded headers after failure = %#v, want %#v", runtime, beforeRuntime)
		}
	})

	t.Run("preserve host", func(t *testing.T) {
		handler, manager := newAdditionalProxyTestHandler(t)
		beforeConfigured := handler.GetPreserveHostConfig()
		beforeRuntime := handler.preserveHost.getConfig()
		breakConfigPersistence(t, manager)

		err := handler.SetPreserveHostConfig(models.PreserveHostConfig{
			Enabled:     false,
			OmitTargets: []string{"http://127.0.0.1:8080"},
			UpdatedAt:   "changed",
		})
		if err == nil {
			t.Fatal("SetPreserveHostConfig() returned nil error")
		}
		configured := handler.GetPreserveHostConfig()
		if configured.Enabled != beforeConfigured.Enabled ||
			configured.UpdatedAt != beforeConfigured.UpdatedAt ||
			!slices.Equal(configured.OmitTargets, beforeConfigured.OmitTargets) {
			t.Fatalf("configured preserve host after failure = %#v, want %#v", configured, beforeConfigured)
		}
		runtime := handler.preserveHost.getConfig()
		if runtime.Enabled != beforeRuntime.Enabled ||
			runtime.UpdatedAt != beforeRuntime.UpdatedAt ||
			!slices.Equal(runtime.OmitTargets, beforeRuntime.OmitTargets) {
			t.Fatalf("runtime preserve host after failure = %#v, want %#v", runtime, beforeRuntime)
		}
	})
}

func TestPersistedHandlerSettingsRollbackOnSaveFailure(t *testing.T) {
	t.Run("path rules", func(t *testing.T) {
		handler, manager := newAdditionalProxyTestHandler(t)
		beforeSnapshot := handler.snapshotForRequest()
		breakConfigPersistence(t, manager)

		err := handler.SetRules([]models.Rule{{
			Path:   "/rollback",
			Target: "http://127.0.0.1:8080",
		}})
		if err == nil {
			t.Fatal("SetRules() returned nil error")
		}
		if got := handler.GetRules(); len(got) != 0 {
			t.Fatalf("configured rules after failure = %#v", got)
		}
		afterSnapshot := handler.snapshotForRequest()
		if len(afterSnapshot.rules) != len(beforeSnapshot.rules) ||
			afterSnapshot.routeGeneration != beforeSnapshot.routeGeneration {
			t.Fatalf("request snapshot changed after failed rule update")
		}
	})

	t.Run("stream rules", func(t *testing.T) {
		handler, manager := newAdditionalProxyTestHandler(t)
		initialAvailability := &models.StreamAvailability{
			Enabled: true, StartTime: "09:00", EndTime: "18:00",
		}
		if err := handler.SetStreamRulesConfig(nil, initialAvailability); err != nil {
			t.Fatalf("set initial availability: %v", err)
		}
		breakConfigPersistence(t, manager)

		err := handler.SetStreamRulesConfig([]models.StreamRule{{
			Protocol:   models.StreamProtocolTCP,
			ListenPort: 10001,
			Target:     "127.0.0.1:10002",
		}}, &models.StreamAvailability{
			Enabled: true, StartTime: "22:00", EndTime: "06:00",
		})
		if err == nil {
			t.Fatal("SetStreamRules() returned nil error")
		}
		if got := handler.GetStreamRules(); len(got) != 0 {
			t.Fatalf("configured stream rules after failure = %#v", got)
		}
		if got := handler.GetStreamAvailability(); !reflect.DeepEqual(got, initialAvailability) {
			t.Fatalf("configured stream availability after failure = %#v, want %#v", got, initialAvailability)
		}
	})

	t.Run("default route", func(t *testing.T) {
		handler, manager := newAdditionalProxyTestHandler(t)
		before := handler.GetDefaultRoute()
		beforeSnapshot := handler.snapshotForRequest().defaultRoute
		breakConfigPersistence(t, manager)

		if err := handler.SetDefaultRoute("/changed"); err == nil {
			t.Fatal("SetDefaultRoute() returned nil error")
		}
		if got := handler.GetDefaultRoute(); got != before {
			t.Fatalf("configured default route = %q, want %q", got, before)
		}
		if got := handler.snapshotForRequest().defaultRoute; got != beforeSnapshot {
			t.Fatalf("snapshot default route = %q, want %q", got, beforeSnapshot)
		}
	})

	t.Run("auth config", func(t *testing.T) {
		handler, manager := newAdditionalProxyTestHandler(t)
		before := handler.GetAuthConfig()
		beforeSnapshot := handler.snapshotForRequest().authConfig
		breakConfigPersistence(t, manager)
		next := before
		next.AuthPort++

		if err := handler.SetAuthConfig(next); err == nil {
			t.Fatal("SetAuthConfig() returned nil error")
		}
		if got := handler.GetAuthConfig(); got != before {
			t.Fatalf("configured auth config = %#v, want %#v", got, before)
		}
		if got := handler.snapshotForRequest().authConfig; got != beforeSnapshot {
			t.Fatalf("snapshot auth config = %#v, want %#v", got, beforeSnapshot)
		}
	})

	t.Run("logging", func(t *testing.T) {
		handler, manager := newAdditionalProxyTestHandler(t)
		before := handler.GetLoggingConfig()
		breakConfigPersistence(t, manager)

		if _, err := handler.SetLoggingConfig(models.LoggingConfig{
			Enabled:         !before.Enabled,
			RecordLocalhost: !before.RecordLocalhost,
			MaxDays:         before.MaxDays + 1,
		}); err == nil {
			t.Fatal("SetLoggingConfig() returned nil error")
		}
		if got := handler.GetLoggingConfig(); got != before {
			t.Fatalf("runtime logging config = %#v, want %#v", got, before)
		}
	})

	t.Run("WAF", func(t *testing.T) {
		handler, manager := newAdditionalProxyTestHandler(t)
		beforeConfig := handler.GetWAFConfig()
		beforeStatus := handler.GetWAFStatus()
		next := beforeConfig
		next.Enabled = !next.Enabled
		if next.Mode == "" || next.Mode == "off" {
			next.Mode = "blocking"
		}
		breakConfigPersistence(t, manager)

		if _, err := handler.SetWAFConfig(next); err == nil {
			t.Fatal("SetWAFConfig() returned nil error")
		}
		afterConfig := handler.GetWAFConfig()
		if afterConfig.Enabled != beforeConfig.Enabled ||
			afterConfig.Mode != beforeConfig.Mode ||
			afterConfig.RulesDir != beforeConfig.RulesDir {
			t.Fatalf("configured WAF after failure = %#v, want %#v", afterConfig, beforeConfig)
		}
		afterStatus := handler.GetWAFStatus()
		if afterStatus.Enabled != beforeStatus.Enabled ||
			afterStatus.Mode != beforeStatus.Mode ||
			afterStatus.Loaded != beforeStatus.Loaded ||
			afterStatus.BundleID != beforeStatus.BundleID {
			t.Fatalf("runtime WAF after failure = %#v, want %#v", afterStatus, beforeStatus)
		}
	})

	t.Run("crawler blocker", func(t *testing.T) {
		handler, manager := newAdditionalProxyTestHandler(t)
		before := handler.GetCrawlerBlockerConfig()
		breakConfigPersistence(t, manager)

		if _, err := handler.SetCrawlerBlockerConfig(models.CrawlerBlockerConfig{
			Enabled:   !before.Enabled,
			UpdatedAt: "changed",
		}); err == nil {
			t.Fatal("SetCrawlerBlockerConfig() returned nil error")
		}
		if got := handler.GetCrawlerBlockerConfig(); got != before {
			t.Fatalf("crawler blocker config = %#v, want %#v", got, before)
		}
	})

	t.Run("gateway portal", func(t *testing.T) {
		handler, manager := newAdditionalProxyTestHandler(t)
		before := handler.GetGatewayPortalConfig()
		beforeSnapshot := handler.snapshotForRequest().gatewayPortal
		breakConfigPersistence(t, manager)
		next := before
		next.ShowAppIcon = !next.ShowAppIcon

		if _, err := handler.SetGatewayPortalConfig(next); err == nil {
			t.Fatal("SetGatewayPortalConfig() returned nil error")
		}
		if got := handler.GetGatewayPortalConfig(); got != before {
			t.Fatalf("gateway portal config = %#v, want %#v", got, before)
		}
		if got := handler.snapshotForRequest().gatewayPortal; got != beforeSnapshot {
			t.Fatalf("snapshot gateway portal = %#v, want %#v", got, beforeSnapshot)
		}
	})

	t.Run("gateway unmatched route", func(t *testing.T) {
		handler, manager := newAdditionalProxyTestHandler(t)
		before := handler.GetGatewayUnmatchedRouteConfig()
		beforeSnapshot := handler.snapshotForRequest().unmatchedRoute
		breakConfigPersistence(t, manager)
		next := before
		next.Behavior = models.GatewayUnmatchedRouteBehaviorResetConnection

		if _, err := handler.SetGatewayUnmatchedRouteConfig(next); err == nil {
			t.Fatal("SetGatewayUnmatchedRouteConfig() returned nil error")
		}
		if got := handler.GetGatewayUnmatchedRouteConfig(); got != before {
			t.Fatalf("gateway unmatched route config = %#v, want %#v", got, before)
		}
		if got := handler.snapshotForRequest().unmatchedRoute; got != beforeSnapshot {
			t.Fatalf("snapshot gateway unmatched route = %#v, want %#v", got, beforeSnapshot)
		}
	})

	t.Run("fnos port icon hijack", func(t *testing.T) {
		handler, manager := newAdditionalProxyTestHandler(t)
		before := handler.GetFnosPortIconHijackConfig()
		breakConfigPersistence(t, manager)

		if _, err := handler.SetFnosPortIconHijackConfig(models.FnosPortIconHijackConfig{
			Enabled:   !before.Enabled,
			UpdatedAt: "changed",
		}); err == nil {
			t.Fatal("SetFnosPortIconHijackConfig() returned nil error")
		}
		if got := handler.GetFnosPortIconHijackConfig(); got != before {
			t.Fatalf("fnOS port icon hijack config = %#v, want %#v", got, before)
		}
	})
}

func TestSetForwardedHeadersConfigStoresCopy(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetForwardedHeadersConfig(models.ForwardedHeadersConfig{Enabled: true, OmitTargets: []string{"http://127.0.0.1:8080"}}); err != nil {
		t.Fatalf("SetForwardedHeadersConfig() returned error: %v", err)
	}
	got := handler.GetForwardedHeadersConfig()
	got.OmitTargets[0] = "http://127.0.0.1:9090"
	if handler.GetForwardedHeadersConfig().OmitTargets[0] == "http://127.0.0.1:9090" {
		t.Fatal("GetForwardedHeadersConfig() did not return a defensive copy")
	}
}

func TestSetPreserveHostConfigStoresCopy(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetPreserveHostConfig(models.PreserveHostConfig{Enabled: true, OmitTargets: []string{"http://127.0.0.1:8080"}}); err != nil {
		t.Fatalf("SetPreserveHostConfig() returned error: %v", err)
	}
	got := handler.GetPreserveHostConfig()
	got.OmitTargets[0] = "http://127.0.0.1:9090"
	if handler.GetPreserveHostConfig().OmitTargets[0] == "http://127.0.0.1:9090" {
		t.Fatal("GetPreserveHostConfig() did not return a defensive copy")
	}
}

func TestGetWAFConfigReturnsDefensiveCopy(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.DisabledHosts = []string{"app.example.test"}
	cfg.WAF.DisabledPathPrefixes = []string{"/private"}
	handler := NewHandler(
		7996,
		7999,
		nil,
		cfg,
		filepath.Join(t.TempDir(), "logs"),
		nil,
	)
	t.Cleanup(handler.gatewayLogManager.Close)

	copy := handler.GetWAFConfig()
	copy.DisabledHosts[0] = "changed.example.test"
	copy.DisabledPathPrefixes[0] = "/changed"

	stored := handler.GetWAFConfig()
	if stored.DisabledHosts[0] != "app.example.test" ||
		stored.DisabledPathPrefixes[0] != "/private" {
		t.Fatalf("stored WAF config was mutated through a returned copy: %#v", stored)
	}
}

func TestSetCrawlerBlockerConfigTrimsUpdatedAt(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	got, err := handler.SetCrawlerBlockerConfig(models.CrawlerBlockerConfig{Enabled: true, UpdatedAt: " now "})
	if err != nil {
		t.Fatalf("SetCrawlerBlockerConfig() returned error: %v", err)
	}
	if !got.Enabled || got.UpdatedAt != "now" {
		t.Fatalf("crawler blocker config = %#v", got)
	}
}

func TestSetGatewayPortalConfigNormalizesInvalidValues(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	got, err := handler.SetGatewayPortalConfig(models.GatewayPortalConfig{DisplayStyle: "bad", IconDragMode: "bad"})
	if err != nil {
		t.Fatalf("SetGatewayPortalConfig() returned error: %v", err)
	}
	if !got.Enabled || got.DisplayStyle != models.GatewayPortalDisplayStyleDomain || got.IconDragMode != models.GatewayPortalIconDragModeCorners {
		t.Fatalf("gateway portal config = %#v", got)
	}
}

func TestSetFnosPortIconHijackConfigTrimsUpdatedAt(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	got, err := handler.SetFnosPortIconHijackConfig(models.FnosPortIconHijackConfig{Enabled: true, UpdatedAt: " t "})
	if err != nil {
		t.Fatalf("SetFnosPortIconHijackConfig() returned error: %v", err)
	}
	if !got.Enabled || got.UpdatedAt != "t" {
		t.Fatalf("fnos hijack config = %#v", got)
	}
}

func TestSetReverseProxyThrottleExemptIPsNormalizesRuntime(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	handler.SetReverseProxyThrottleExemptIPs(models.ReverseProxyThrottleExemptIPsRuntime{
		Enabled: true,
		IPs:     []string{" 198.51.100.7 ", "bad"},
		CIDRs:   []string{"192.168.0.0/16"},
	})
	got := handler.GetReverseProxyThrottleExemptIPs()
	if !got.Enabled || len(got.IPs) != 1 || got.IPs[0] != "198.51.100.7" ||
		len(got.CIDRs) != 0 || got.Policy == nil || got.PolicyID == "" {
		t.Fatalf("exempt IP runtime = %#v", got)
	}
}

func TestSetCommonLocationExemptionsNormalizesRuntime(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	handler.SetCommonLocationExemptions(models.CommonLocationExemptionsRuntime{
		Enabled: true,
		CIDRs:   []string{"192.168.0.0/16", "bad"},
	})
	got := handler.GetCommonLocationExemptions()
	if !got.Enabled || len(got.CIDRs) != 0 || got.Policy == nil || got.PolicyID == "" {
		t.Fatalf("common location exemptions = %#v", got)
	}
}

func TestAddRuleAppendsPathRule(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.AddRule(models.Rule{Path: "/app", Target: "http://127.0.0.1:8080"}); err != nil {
		t.Fatalf("AddRule() returned error: %v", err)
	}
	rules := handler.GetRules()
	if len(rules) != 1 || rules[0].Path != "/app" {
		t.Fatalf("rules = %#v", rules)
	}
}

func TestAddRuleUpdatesExistingPathRule(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.AddRule(models.Rule{Path: "/app", Target: "http://127.0.0.1:8080"}); err != nil {
		t.Fatalf("AddRule() returned error: %v", err)
	}
	if err := handler.AddRule(models.Rule{Path: "/app", Target: "http://127.0.0.1:8081"}); err != nil {
		t.Fatalf("AddRule(update) returned error: %v", err)
	}
	rules := handler.GetRules()
	if len(rules) != 1 || rules[0].Target != "http://127.0.0.1:8081" {
		t.Fatalf("rules = %#v", rules)
	}
}

func TestSetRulesDeduplicatesByPathKeepingLast(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	err := handler.SetRules([]models.Rule{
		{Path: "/app", Target: "http://127.0.0.1:8080"},
		{Path: "/app", Target: "http://127.0.0.1:8081"},
	})
	if err != nil {
		t.Fatalf("SetRules() returned error: %v", err)
	}
	rules := handler.GetRules()
	if len(rules) != 1 || rules[0].Target != "http://127.0.0.1:8081" {
		t.Fatalf("rules = %#v", rules)
	}
}

func TestRemoveRuleDeletesMatchingPath(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetRules([]models.Rule{{Path: "/app", Target: "http://127.0.0.1:8080"}}); err != nil {
		t.Fatalf("SetRules() returned error: %v", err)
	}
	handler.RemoveRule("/app")
	if got := handler.GetRules(); len(got) != 0 {
		t.Fatalf("rules after remove = %#v", got)
	}
}

func TestFlushRulesClearsPathRules(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetRules([]models.Rule{{Path: "/app", Target: "http://127.0.0.1:8080"}}); err != nil {
		t.Fatalf("SetRules() returned error: %v", err)
	}
	if err := handler.FlushRules(); err != nil {
		t.Fatalf("FlushRules() returned error: %v", err)
	}
	if got := handler.GetRules(); len(got) != 0 {
		t.Fatalf("rules after flush = %#v", got)
	}
}

func TestAddHostRuleNormalizesHostAndAppends(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	err := handler.AddHostRule(models.HostRule{Host: " App.Example.Test:443 ", Target: "http://127.0.0.1:8080"})
	if err != nil {
		t.Fatalf("AddHostRule() returned error: %v", err)
	}
	rules := handler.GetHostRules()
	if len(rules) != 1 || rules[0].Host != "app.example.test" {
		t.Fatalf("host rules = %#v", rules)
	}
}

func TestSetHostRulesKeepsOnlyFirstDefault(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	err := handler.SetHostRules([]models.HostRule{
		{Host: "a.example.test", Target: "http://127.0.0.1:8080", IsDefault: true},
		{Host: "b.example.test", Target: "http://127.0.0.1:8081", IsDefault: true},
	})
	if err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}
	rules := handler.GetHostRules()
	if len(rules) != 2 || !rules[0].IsDefault || rules[1].IsDefault {
		t.Fatalf("host rules = %#v", rules)
	}
}

func TestGetHostRulesDeepCopiesLocations(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	err := handler.SetHostRules([]models.HostRule{{
		Host:   "app.example.test",
		Target: "http://127.0.0.1:8080",
		Locations: []models.HostLocation{{
			Path: "/api", Action: models.HostLocationActionResponse, Response: models.HostLocationResponse{Status: 200, Headers: map[string]string{"X-Test": "a"}},
		}},
	}})
	if err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}
	got := handler.GetHostRules()
	got[0].Locations[0].Response.Headers["X-Test"] = "b"
	if handler.GetHostRules()[0].Locations[0].Response.Headers["X-Test"] != "a" {
		t.Fatal("GetHostRules() did not deep-copy location response headers")
	}
}

func TestFlushHostRulesClearsHostRules(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetHostRules([]models.HostRule{{Host: "app.example.test", Target: "http://127.0.0.1:8080"}}); err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}
	if err := handler.FlushHostRules(); err != nil {
		t.Fatalf("FlushHostRules() returned error: %v", err)
	}
	if got := handler.GetHostRules(); len(got) != 0 {
		t.Fatalf("host rules after flush = %#v", got)
	}
}

func TestValidateStreamRulesDefaultsProtocolToTCP(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	rules, err := handler.ValidateStreamRules([]models.StreamRule{{ListenPort: 3306, Target: "127.0.0.1:3307"}})
	if err != nil {
		t.Fatalf("ValidateStreamRules() returned error: %v", err)
	}
	if rules[0].Protocol != models.StreamProtocolTCP {
		t.Fatalf("protocol = %q", rules[0].Protocol)
	}
}

func TestValidateStreamRulesRejectsReservedAdminPort(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	_, err := handler.ValidateStreamRules([]models.StreamRule{{Protocol: "tcp", ListenPort: 7996, Target: "127.0.0.1:3307"}})
	if err == nil {
		t.Fatal("ValidateStreamRules() accepted admin port")
	}
}

func TestValidateStreamRulesRejectsSameLocalTargetPort(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	_, err := handler.ValidateStreamRules([]models.StreamRule{{Protocol: "tcp", ListenPort: 3306, Target: "127.0.0.1:3306"}})
	if err == nil {
		t.Fatal("ValidateStreamRules() accepted same local target port")
	}
}

func TestSetStreamRulesPersistsNormalizedRules(t *testing.T) {
	handler, manager := newAdditionalProxyTestHandler(t)
	err := handler.SetStreamRules([]models.StreamRule{{ListenPort: 3306, Target: "127.0.0.1:3307"}})
	if err != nil {
		t.Fatalf("SetStreamRules() returned error: %v", err)
	}
	cfg, err := manager.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if len(cfg.StreamRules) != 1 || cfg.StreamRules[0].Protocol != models.StreamProtocolTCP {
		t.Fatalf("persisted stream rules = %#v", cfg.StreamRules)
	}
}

func TestSetStreamRulesPreservesAvailability(t *testing.T) {
	handler, manager := newAdditionalProxyTestHandler(t)
	availability := &models.StreamAvailability{
		Enabled: true, StartTime: "22:00", EndTime: "06:00",
	}
	if err := handler.SetStreamRulesConfig(nil, availability); err != nil {
		t.Fatalf("SetStreamRulesConfig() returned error: %v", err)
	}
	if err := handler.SetStreamRules([]models.StreamRule{{
		Protocol: models.StreamProtocolTCP, ListenPort: 3306, Target: "127.0.0.1:3307",
	}}); err != nil {
		t.Fatalf("SetStreamRules() returned error: %v", err)
	}
	if got := handler.GetStreamAvailability(); !reflect.DeepEqual(got, availability) {
		t.Fatalf("handler availability = %#v, want %#v", got, availability)
	}
	cfg, err := manager.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if !reflect.DeepEqual(cfg.StreamAvailability, availability) {
		t.Fatalf("persisted availability = %#v, want %#v", cfg.StreamAvailability, availability)
	}
}

func TestFlushStreamRulesClearsStreamRules(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetStreamRules([]models.StreamRule{{Protocol: "udp", ListenPort: 5353, Target: "127.0.0.1:5354"}}); err != nil {
		t.Fatalf("SetStreamRules() returned error: %v", err)
	}
	if err := handler.FlushStreamRules(); err != nil {
		t.Fatalf("FlushStreamRules() returned error: %v", err)
	}
	if got := handler.GetStreamRules(); len(got) != 0 {
		t.Fatalf("stream rules after flush = %#v", got)
	}
}

func TestSetLoggingConfigDefaultsMaxDays(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	info, err := handler.SetLoggingConfig(models.LoggingConfig{Enabled: true})
	if err != nil {
		t.Fatalf("SetLoggingConfig() returned error: %v", err)
	}
	if !info.Enabled || info.MaxDays != gatewaylog.DefaultMaxDays {
		t.Fatalf("logging info = %#v", info)
	}
}

func TestLoggingConfigFallbackPreservesLocalhostSetting(t *testing.T) {
	handler := &Handler{
		LoggingConfig: models.LoggingConfig{
			Enabled:         true,
			RecordLocalhost: true,
			MaxDays:         3,
		},
	}

	info := handler.GetLoggingConfig()
	if !info.Enabled || !info.RecordLocalhost || info.MaxDays != 3 {
		t.Fatalf("GetLoggingConfig() = %#v", info)
	}

	info, err := handler.SetLoggingConfig(models.LoggingConfig{
		Enabled:         true,
		RecordLocalhost: true,
		MaxDays:         5,
	})
	if err != nil {
		t.Fatalf("SetLoggingConfig() returned error: %v", err)
	}
	if !info.Enabled || !info.RecordLocalhost || info.MaxDays != 5 {
		t.Fatalf("SetLoggingConfig() = %#v", info)
	}
}

func TestGetLoggingDirectoryReturnsLogsDir(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if got := handler.GetLoggingDirectory(); got.LogsDir == "" {
		t.Fatalf("GetLoggingDirectory() = %#v", got)
	}
}

func TestAddStreamTrafficUpdatesTotalsAnd5xx(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	handler.AddStreamTraffic(10, 20, 502)
	stats := handler.GetTrafficStats(time.Now())
	if stats.TotalIn != 10 || stats.TotalOut != 20 || stats.Error5xx != 1 {
		t.Fatalf("traffic stats = %#v", stats)
	}
}

func TestIsClientIPVisibleUsesGatewayVisibility(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{Enabled: true, CIDRs: []string{"198.51.100.0/24"}}); err != nil {
		t.Fatalf("SetGatewayVisibility() returned error: %v", err)
	}
	if !handler.IsClientIPVisible("198.51.100.7") || handler.IsClientIPVisible("203.0.113.7") {
		t.Fatalf("visibility mismatch")
	}
}

func TestLogGatewayEntryWritesWhenLoggingEnabled(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if _, err := handler.SetLoggingConfig(models.LoggingConfig{Enabled: true}); err != nil {
		t.Fatalf("SetLoggingConfig() returned error: %v", err)
	}
	handler.LogGatewayEntry(gatewaylog.Entry{Method: "GET", Path: "/logged", Status: 200})
	result, err := handler.QueryLogEntries("", 1, 20, "/logged", "200", "", "", "", "page")
	if err != nil {
		t.Fatalf("QueryLogEntries() returned error: %v", err)
	}
	if result.Total != 1 {
		t.Fatalf("query result = %#v", result)
	}
}

func TestDrainWAFEventsReturnsEmptyWhenNoEvents(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	result := handler.DrainWAFEvents(10)
	if len(result.Events) != 0 {
		t.Fatalf("DrainWAFEvents() = %#v", result)
	}
}

func newAdditionalProxyTestHandler(t *testing.T) (*Handler, *config.Manager) {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "config.json")
	manager := config.NewManager(configPath)
	initialCfg, err := manager.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	handler := NewHandler(7996, 7999, manager, initialCfg, filepath.Join(t.TempDir(), "logs"), nil)
	t.Cleanup(handler.gatewayLogManager.Close)
	return handler, manager
}
