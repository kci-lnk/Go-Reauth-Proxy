package models

import (
	"encoding/json"
	"testing"
)

func TestSelectPageConfigLegacyAndExplicitValues(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want bool
	}{
		{`{}`, true}, {`{"enabled":false}`, true}, {`{"select_page_enabled":true}`, true}, {`{"select_page_enabled":false}`, false},
	} {
		var cfg GatewayPortalConfig
		if err := json.Unmarshal([]byte(tc.raw), &cfg); err != nil {
			t.Fatal(err)
		}
		cfg = NormalizeGatewayPortalConfig(cfg)
		if cfg.IsSelectPageEnabled() != tc.want {
			t.Fatalf("%s: got %v", tc.raw, cfg.IsSelectPageEnabled())
		}
		raw, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		var restored GatewayPortalConfig
		if err := json.Unmarshal(raw, &restored); err != nil {
			t.Fatal(err)
		}
		if restored.IsSelectPageEnabled() != tc.want {
			t.Fatalf("round trip lost value: %s", raw)
		}
	}
	if !NormalizeGatewayPortalConfig(GatewayPortalConfig{}).IsSelectPageEnabled() {
		t.Fatal("zero config must default enabled")
	}
}

func TestSelectPageConfigJSONRoundTripWithoutNormalization(t *testing.T) {
	disabled := NewGatewayPortalConfig(true, "title", true, "corners", "v1", false)
	disabled.SetSelectPageEnabled(false)
	for _, cfg := range []GatewayPortalConfig{{}, {Enabled: true}, NewGatewayPortalConfig(false, "title", false, "corners", "v1", false), disabled} {
		raw, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		var restored GatewayPortalConfig
		if err := json.Unmarshal(raw, &restored); err != nil {
			t.Fatal(err)
		}
		if got, want := restored.IsSelectPageEnabled(), cfg.IsSelectPageEnabled(); got != want {
			t.Fatalf("JSON round trip changed select preference from %v to %v: %s", want, got, raw)
		}
	}
}
