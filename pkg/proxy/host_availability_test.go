package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go-reauth-proxy/pkg/gatewaylog"
	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/models"
)

func TestEvaluateHostRuleAvailability(t *testing.T) {
	t.Run("legacy default is available", func(t *testing.T) {
		decision := evaluateHostRuleAvailability(&models.HostRule{}, time.Date(2026, 1, 1, 12, 0, 0, 0, time.Local))
		if !decision.Available {
			t.Fatalf("available = false, want true")
		}
	})

	t.Run("manual disabled wins", func(t *testing.T) {
		decision := evaluateHostRuleAvailability(&models.HostRule{
			Disabled: true,
			Availability: &models.HostRuleAvailability{
				Enabled:   true,
				StartTime: "09:00",
				EndTime:   "18:00",
			},
		}, time.Date(2026, 1, 1, 10, 0, 0, 0, time.Local))
		if decision.Available || decision.Reason != hostUnavailableReasonDisabled {
			t.Fatalf("decision = %#v, want disabled unavailable", decision)
		}
	})

	t.Run("same day window", func(t *testing.T) {
		rule := &models.HostRule{Availability: &models.HostRuleAvailability{
			Enabled:   true,
			StartTime: "09:00",
			EndTime:   "18:00",
		}}
		if !evaluateHostRuleAvailability(rule, time.Date(2026, 1, 1, 9, 0, 0, 0, time.Local)).Available {
			t.Fatalf("09:00 should be inside window")
		}
		if evaluateHostRuleAvailability(rule, time.Date(2026, 1, 1, 18, 0, 0, 0, time.Local)).Available {
			t.Fatalf("18:00 should be outside window")
		}
	})

	t.Run("overnight window", func(t *testing.T) {
		rule := &models.HostRule{Availability: &models.HostRuleAvailability{
			Enabled:   true,
			StartTime: "22:00",
			EndTime:   "06:00",
		}}
		if !evaluateHostRuleAvailability(rule, time.Date(2026, 1, 1, 23, 0, 0, 0, time.Local)).Available {
			t.Fatalf("23:00 should be inside overnight window")
		}
		if !evaluateHostRuleAvailability(rule, time.Date(2026, 1, 1, 2, 0, 0, 0, time.Local)).Available {
			t.Fatalf("02:00 should be inside overnight window")
		}
		if evaluateHostRuleAvailability(rule, time.Date(2026, 1, 1, 12, 0, 0, 0, time.Local)).Available {
			t.Fatalf("12:00 should be outside overnight window")
		}
	})
}

func TestSetHostRulesRejectsInvalidAvailability(t *testing.T) {
	handler := &Handler{}
	err := handler.SetHostRules([]models.HostRule{{
		Host:   "app.example.com",
		Target: "http://127.0.0.1:8080",
		Availability: &models.HostRuleAvailability{
			Enabled:   true,
			StartTime: "09:00",
			EndTime:   "09:00",
		},
	}})
	if err == nil {
		t.Fatal("SetHostRules returned nil error, want availability validation error")
	}
}

func TestDisabledHostRuleReturnsUnavailableJSONWithoutProxying(t *testing.T) {
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler := &Handler{
		HostRules: []models.HostRule{{
			Host:     "app.example.com",
			Target:   upstream.URL,
			Disabled: true,
		}},
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/dashboard", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if upstreamHit {
		t.Fatal("disabled host proxied to upstream")
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"code":"HOST_UNAVAILABLE"`) || !strings.Contains(body, `"reason":"disabled"`) {
		t.Fatalf("body = %s, want HOST_UNAVAILABLE disabled JSON", body)
	}
}

func TestOutsideAvailabilityWindowReturnsUnavailableAndLogsHost(t *testing.T) {
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	logManager := gatewaylog.NewManager(t.TempDir(), models.LoggingConfig{
		Enabled: true,
		MaxDays: 1,
	})
	defer logManager.Close()

	now := time.Now().Local()
	startMinute := (now.Hour()*60 + now.Minute() + 2) % (24 * 60)
	endMinute := (startMinute + 1) % (24 * 60)
	startTime := formatAvailabilityTestMinute(startMinute)
	endTime := formatAvailabilityTestMinute(endMinute)
	handler := &Handler{
		HostRules: []models.HostRule{{
			Host:   "app.example.com",
			Target: upstream.URL,
			Availability: &models.HostRuleAvailability{
				Enabled:   true,
				StartTime: startTime,
				EndTime:   endTime,
			},
		}},
		gatewayLogManager: logManager,
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/dashboard", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	logManager.Flush()

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if upstreamHit {
		t.Fatal("outside-window host proxied to upstream")
	}
	body := rec.Body.String()
	wantWindow := startTime + "-" + endTime
	if !strings.Contains(body, `"reason":"outside_window"`) || !strings.Contains(body, `"window":"`+wantWindow+`"`) {
		t.Fatalf("body = %s, want outside_window JSON with window", body)
	}

	stats := handler.GetTrafficStats(time.Now())
	if len(stats.ByHost) != 1 ||
		stats.ByHost[0].Host != "app.example.com" ||
		stats.ByHost[0].Error5xx != 1 {
		t.Fatalf("traffic stats = %#v, want app.example.com 5xx host stat", stats.ByHost)
	}

	result, err := handler.QueryLogEntries("", 1, 20, "outside_window", "", "", "", "", "page")
	if err != nil {
		t.Fatalf("QueryLogEntries failed: %v", err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("logged items = %d, want 1", len(result.Items))
	}
	entry := result.Items[0]
	if entry.RouteType != "host_unavailable" ||
		entry.RouteKey != "app.example.com" ||
		entry.AuthDecision != "outside_window" ||
		entry.Status != http.StatusServiceUnavailable {
		t.Fatalf("log entry = %#v, want host_unavailable outside_window", entry)
	}
}

func formatAvailabilityTestMinute(minute int) string {
	minute = ((minute % (24 * 60)) + (24 * 60)) % (24 * 60)
	return time.Date(2026, 1, 1, minute/60, minute%60, 0, 0, time.Local).Format("15:04")
}

func TestDefaultHostRuleSkipsUnavailableRule(t *testing.T) {
	handler := &Handler{
		HostRules: []models.HostRule{{
			Host:      "app.example.com",
			Target:    "http://127.0.0.1:8080",
			IsDefault: true,
			Disabled:  true,
		}},
		DefaultRoute: "/__select__",
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://root.example.com/path", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusFound || rec.Header().Get("Location") != "" {
		t.Fatalf("disabled default host redirected: status=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestSelectRouteFiltersUnavailableHostRules(t *testing.T) {
	handler := &Handler{
		HostRules: []models.HostRule{
			{Host: "active.example.com", Target: "http://127.0.0.1:8080"},
			{Host: "disabled.example.com", Target: "http://127.0.0.1:8081", Disabled: true},
		},
		AuthConfig: models.AuthConfig{
			AuthURL:      "/api/auth/verify",
			PreflightURL: "/api/auth/preflight",
		},
		authBridge: testAuthBridge{
			verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
				return &pb.VerifyAuthResponse{Success: true, Status: http.StatusOK}, nil
			},
		},
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.com/__select__", nil)
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "ok"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "active.example.com") {
		t.Fatalf("body did not include active host: %s", body)
	}
	if strings.Contains(body, "disabled.example.com") {
		t.Fatalf("body included disabled host: %s", body)
	}
}
