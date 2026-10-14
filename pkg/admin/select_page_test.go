package admin

import (
	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/models"
	"testing"
)

func TestSelectPageProtoPresenceAndRoundTrip(t *testing.T) {
	if !protoToGatewayPortal(&pb.GatewayPortalConfig{}).IsSelectPageEnabled() {
		t.Fatal("legacy protobuf must default enabled")
	}
	for _, enabled := range []bool{true, false} {
		cfg := models.NewGatewayPortalConfig(!enabled, "title", true, "corners", "v1", true)
		cfg.SetSelectPageEnabled(enabled)
		wire := gatewayPortalToProto(cfg)
		if wire.SelectPageEnabled == nil || wire.GetSelectPageEnabled() != enabled {
			t.Fatal("protobuf lost explicit value")
		}
		got := models.NormalizeGatewayPortalConfig(protoToGatewayPortal(wire))
		if got.IsSelectPageEnabled() != enabled || got.Enabled != !enabled {
			t.Fatal("portal switches are coupled")
		}
	}
}
