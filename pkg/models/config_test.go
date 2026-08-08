package models

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGatewayPortalConfigDefaultsLegacyValuesToEnabled(t *testing.T) {
	var cfg GatewayPortalConfig
	if err := json.Unmarshal([]byte(`{"display_style":"title","show_app_icon":true}`), &cfg); err != nil {
		t.Fatalf("unmarshal gateway portal config: %v", err)
	}

	normalized := NormalizeGatewayPortalConfig(cfg)
	if !normalized.Enabled {
		t.Fatalf("legacy gateway portal config normalized to disabled: %+v", normalized)
	}
	if normalized.DisplayStyle != GatewayPortalDisplayStyleTitle {
		t.Fatalf("display style = %q, want title", normalized.DisplayStyle)
	}
	if !normalized.ShowAppIcon {
		t.Fatalf("show app icon = false, want true")
	}
	if normalized.IconDragMode != GatewayPortalIconDragModeCorners {
		t.Fatalf("icon drag mode = %q, want corners", normalized.IconDragMode)
	}
}

func TestGatewayPortalConfigPreservesExplicitDisabledValue(t *testing.T) {
	var cfg GatewayPortalConfig
	if err := json.Unmarshal([]byte(`{"enabled":false,"display_style":"title","show_app_icon":true}`), &cfg); err != nil {
		t.Fatalf("unmarshal gateway portal config: %v", err)
	}

	normalized := NormalizeGatewayPortalConfig(cfg)
	if normalized.Enabled {
		t.Fatalf("explicitly disabled gateway portal config normalized to enabled: %+v", normalized)
	}

	payload, err := json.Marshal(normalized)
	if err != nil {
		t.Fatalf("marshal gateway portal config: %v", err)
	}
	if !strings.Contains(string(payload), `"enabled":false`) {
		t.Fatalf("disabled gateway portal config did not marshal explicit false: %s", payload)
	}
}

func TestNewGatewayPortalConfigPreservesExplicitDisabledValue(t *testing.T) {
	cfg := NewGatewayPortalConfig(false, GatewayPortalDisplayStyleTitle, true, GatewayPortalIconDragModeFree, GatewayPortalVersionV2, false)

	normalized := NormalizeGatewayPortalConfig(cfg)
	if normalized.Enabled {
		t.Fatalf("explicitly disabled gateway portal config normalized to enabled: %+v", normalized)
	}
	if normalized.DisplayStyle != GatewayPortalDisplayStyleTitle ||
		!normalized.ShowAppIcon ||
		normalized.IconDragMode != GatewayPortalIconDragModeFree ||
		normalized.Version != GatewayPortalVersionV2 {
		t.Fatalf("gateway portal fields were not preserved: %+v", normalized)
	}
}

func TestGatewayPortalConfigVersionDefaultsToV1AndPreservesV2(t *testing.T) {
	var legacy GatewayPortalConfig
	if err := json.Unmarshal([]byte(`{"display_style":"title"}`), &legacy); err != nil {
		t.Fatalf("unmarshal legacy gateway portal config: %v", err)
	}
	if got := NormalizeGatewayPortalConfig(legacy).Version; got != GatewayPortalVersionV1 {
		t.Fatalf("legacy version = %q, want v1", got)
	}
	if got := NormalizeGatewayPortalConfig(GatewayPortalConfig{Version: "future"}).Version; got != GatewayPortalVersionV1 {
		t.Fatalf("invalid version = %q, want v1", got)
	}
	if got := NormalizeGatewayPortalConfig(GatewayPortalConfig{Version: GatewayPortalVersionV2}).Version; got != GatewayPortalVersionV2 {
		t.Fatalf("v2 version = %q, want v2", got)
	}
}

func TestGatewayPortalConfigPreservesFreeIconDragMode(t *testing.T) {
	var cfg GatewayPortalConfig
	if err := json.Unmarshal([]byte(`{"icon_drag_mode":"free"}`), &cfg); err != nil {
		t.Fatalf("unmarshal gateway portal config: %v", err)
	}

	normalized := NormalizeGatewayPortalConfig(cfg)
	if normalized.IconDragMode != GatewayPortalIconDragModeFree {
		t.Fatalf("icon drag mode = %q, want free", normalized.IconDragMode)
	}
}

func TestGatewayPortalConfigNormalizesInvalidIconDragModeToCorners(t *testing.T) {
	var cfg GatewayPortalConfig
	if err := json.Unmarshal([]byte(`{"icon_drag_mode":"<script>"}`), &cfg); err != nil {
		t.Fatalf("unmarshal gateway portal config: %v", err)
	}

	normalized := NormalizeGatewayPortalConfig(cfg)
	if normalized.IconDragMode != GatewayPortalIconDragModeCorners {
		t.Fatalf("icon drag mode = %q, want corners", normalized.IconDragMode)
	}
}
