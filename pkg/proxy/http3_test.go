package proxy

import (
	"crypto/tls"
	"errors"
	"go-reauth-proxy/pkg/models"
	"net/http/httptest"
	"testing"
)

func TestHTTP3IgnoresSpoofedClientIPHeaders(t *testing.T) {
	r := httptest.NewRequest("GET", "https://app.example.test/", nil)
	r.ProtoMajor = 3
	r.Proto = "HTTP/3.0"
	r.RemoteAddr = "192.0.2.7:1234"
	r.Header.Set("X-Forwarded-For", "127.0.0.1")
	r.Header.Set("EO-Connecting-IP", "127.0.0.1")
	r.Header.Set("Ali-CDN-Real-IP", "127.0.0.1")
	if ip := resolveClientIP(r, models.AuthConfig{EdgeClientIPEnabled: true, TencentEdgeOneEnabled: true}, false); ip != "192.0.2.7" {
		t.Fatal(ip)
	}
}
func TestHTTP3ProtocolGuard(t *testing.T) {
	r := httptest.NewRequest("GET", "https://app.example.test/", nil)
	r.ProtoMajor = 3
	r.TLS = &tls.ConnectionState{}
	if !isHTTP1OnlyHostOverHTTP2(r, &models.HostRule{ProtocolMode: "http1"}) || !isHTTP2OnlyHostOverHTTP1(r, &models.HostRule{ProtocolMode: "http2"}) {
		t.Fatal("HTTP/3 bypassed strict protocol")
	}
}
func TestHTTP3ConfigFailureDoesNotPersist(t *testing.T) {
	h, manager := newAdditionalProxyTestHandler(t)
	h.SetHTTP3Hooks(func(models.GatewayHttp3Config) error { return errors.New("bind failed") }, nil)
	err := h.SetGatewayHttp3Config(models.GatewayHttp3Config{AdvertisedPort: 443})
	if err == nil || h.GetGatewayHttp3Config().AdvertisedPort != 0 {
		t.Fatal("failed mutation published")
	}
	cfg, err := manager.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GatewayHttp3.AdvertisedPort != 0 {
		t.Fatal("failed mutation persisted")
	}
	if err := h.SetGatewayHttp3Config(models.GatewayHttp3Config{Enabled: true}); err == nil {
		t.Fatal("enabled without certificate")
	}
}
func TestHTTP3ReservesUDPStreamPort(t *testing.T) {
	h, _ := newAdditionalProxyTestHandler(t)
	h.mu.Lock()
	h.GatewayHttp3.Enabled = true
	h.mu.Unlock()
	if _, err := h.ValidateStreamRules([]models.StreamRule{{Protocol: "udp", ListenPort: h.ProxyPort, Target: "192.0.2.3:8000"}}); err == nil {
		t.Fatal("accepted conflicting UDP rule")
	}
}
