package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go-reauth-proxy/pkg/logger"
)

func TestHTTP2HealthcheckWarning(t *testing.T) {
	dir := t.TempDir()
	t.Cleanup(logger.Setup)
	t.Setenv(logger.DiagnosticLogDirEnv, dir)
	logger.Setup()
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	listener := &responseBlackholeListener{Listener: upstream.Listener}
	upstream.Listener = listener
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()
	tr := newProxyTransport()
	tr.Proxy = nil
	tr.HTTP2.SendPingTimeout = 50 * time.Millisecond
	tr.HTTP2.PingTimeout = 50 * time.Millisecond
	defer tr.CloseIdleConnections()
	tr.HTTP2.CountError("unrelated_error")
	if major, err := faultRequest(tr, upstream.URL, "fn.example", time.Second); err != nil || major != 2 {
		t.Fatalf("HTTP/2 warmup: protocol=%d error=%v", major, err)
	}
	listener.first.Load().drop.Store(true)
	if _, err := faultRequest(tr, upstream.URL, "fn.example", time.Second); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("connection was not terminated by the health check: %v", err)
	}
	logger.FlushDiagnosticLogger()
	data, err := os.ReadFile(filepath.Join(dir, "gateway.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Level     string `json:"level"`
		Component string `json:"component"`
		Event     string `json:"event"`
		Reason    string `json:"reason_code"`
	}
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("want exactly one structured record: %v; %s", err, data)
	}
	if record.Level != "WARN" || record.Component != "proxy" || record.Event != "http2_upstream_healthcheck_failed" || record.Reason != "conn_close_lost_ping" {
		t.Fatalf("unexpected warning: %+v", record)
	}
}
