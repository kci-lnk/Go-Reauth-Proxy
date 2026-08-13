package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"go-reauth-proxy/pkg/models"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

var (
	benchmarkFnosPortSink    int
	benchmarkFnosTargetsSink map[int]string
)

func TestRewriteFnosPortIconHijackMessageRewritesEmptyHostPort(t *testing.T) {
	payload := []byte(`{
		"result":"succ",
		"data":{
			"list":[
				{
					"title":"Emby Server",
					"fullUrl":"",
					"uri":{
						"protocol":"http",
						"host":"",
						"port":"8096",
						"path":"/web/index.html"
					}
				}
			]
		}
	}`)
	targets := map[int]string{8096: "emby.example.com"}

	rewritten, changed, err := rewriteFnosPortIconHijackMessage(payload, targets, fnosPortIconHijackPublicEndpoint{
		protocol: "http",
		port:     18080,
	})
	if err != nil {
		t.Fatalf("rewrite returned error: %v", err)
	}
	if !changed {
		t.Fatal("expected payload to be rewritten")
	}

	var decoded struct {
		Data struct {
			List []struct {
				URI struct {
					Protocol string `json:"protocol"`
					Host     string `json:"host"`
					Port     string `json:"port"`
					Path     string `json:"path"`
				} `json:"uri"`
			} `json:"list"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rewritten, &decoded); err != nil {
		t.Fatalf("rewritten JSON is invalid: %v", err)
	}
	if got := decoded.Data.List[0].URI.Host; got != "emby.example.com" {
		t.Fatalf("host = %q, want emby.example.com", got)
	}
	if got := decoded.Data.List[0].URI.Protocol; got != "http" {
		t.Fatalf("protocol = %q, want http", got)
	}
	if got := decoded.Data.List[0].URI.Port; got != "18080" {
		t.Fatalf("port = %q, want 18080", got)
	}
	if got := decoded.Data.List[0].URI.Path; got != "" {
		t.Fatalf("path = %q, want empty string", got)
	}
}

func TestRewriteFnosPortIconHijackMessageSkipsNonEmptyHost(t *testing.T) {
	payload := []byte(`{"uri":{"host":"192.168.31.98","port":"8096"}}`)

	rewritten, changed, err := rewriteFnosPortIconHijackMessage(payload, map[int]string{8096: "emby.example.com"}, fnosPortIconHijackPublicEndpoint{
		protocol: "http",
		port:     18080,
	})
	if err != nil {
		t.Fatalf("rewrite returned error: %v", err)
	}
	if changed {
		t.Fatal("expected payload to remain unchanged")
	}
	if string(rewritten) != string(payload) {
		t.Fatalf("payload changed unexpectedly: %s", rewritten)
	}
}

func TestBuildFnosPortIconHijackTargetsUsesHostRuleTargetPorts(t *testing.T) {
	targets := buildFnosPortIconHijackTargets([]models.HostRule{
		{Host: "Emby.Example.COM", Target: "http://127.0.0.1:8096"},
		{Host: "other.example.com", Target: "http://127.0.0.1:8096"},
		{Host: "jellyfin.example.com", Target: "https://192.168.31.98:8920"},
	})

	if got := targets[8096]; got != "emby.example.com" {
		t.Fatalf("target 8096 = %q, want emby.example.com", got)
	}
	if got := targets[8920]; got != "jellyfin.example.com" {
		t.Fatalf("target 8920 = %q, want jellyfin.example.com", got)
	}
}

func TestHostRuleTargetPortMatchesLegacyBehavior(t *testing.T) {
	tests := []string{
		"",
		"   ",
		"http://127.0.0.1:8096",
		" http://127.0.0.1:8096/path ",
		"https://192.168.1.10:8920",
		"http://example.com",
		"https://example.com",
		"ws://example.com/socket",
		"wss://example.com/socket",
		"ftp://example.com",
		"ftp://example.com:21",
		"http://:80",
		"http://host:",
		"http://host:abc",
		"http://host:70000",
		"http://[::1]:8080/path",
		"http://[::1]/path",
		"http://::1",
		"http://user:pass@example.com:8080/path",
		"http://user@:80",
		"http://[::1",
		"http://[::1]extra",
	}

	for _, rawTarget := range tests {
		t.Run(rawTarget, func(t *testing.T) {
			gotPort, gotOK := hostRuleTargetPort(rawTarget)
			wantPort, wantOK := legacyHostRuleTargetPortForBenchmark(rawTarget)
			if gotPort != wantPort || gotOK != wantOK {
				t.Fatalf("hostRuleTargetPort(%q) = %d, %v; want legacy %d, %v", rawTarget, gotPort, gotOK, wantPort, wantOK)
			}
		})
	}
}

func TestFnosPortIconHijackResponsePortUsesEdgeClientIPPort(t *testing.T) {
	handler := &Handler{
		ProxyPort: 18080,
		AuthConfig: models.AuthConfig{
			EdgeClientIPEnabled: true,
		},
	}

	if got := handler.fnosPortIconHijackResponsePort(); got != 80 {
		t.Fatalf("response port = %d, want 80", got)
	}
}

func TestFnosPortIconHijackPublicEndpointUsesHTTPSWhenSSLIsEnabled(t *testing.T) {
	handler := &Handler{
		ProxyPort: 18080,
		AuthConfig: models.AuthConfig{
			EdgeClientIPEnabled: true,
		},
	}
	handler.sslBundle.Store(&sslRuntimeBundle{
		certificates: []models.SSLDeployedCertificateInfo{{Domains: []string{"example.com"}}},
	})

	endpoint := handler.fnosPortIconHijackPublicEndpoint()
	if endpoint.protocol != "https" {
		t.Fatalf("protocol = %q, want https", endpoint.protocol)
	}
	if endpoint.port != 443 {
		t.Fatalf("port = %d, want 443", endpoint.port)
	}

	handler.AuthConfig.EdgeClientIPEnabled = false
	endpoint = handler.fnosPortIconHijackPublicEndpoint()
	if endpoint.protocol != "https" {
		t.Fatalf("protocol = %q, want https", endpoint.protocol)
	}
	if endpoint.port != 18080 {
		t.Fatalf("port = %d, want 18080", endpoint.port)
	}
}

func TestShouldProxyFnosPortIconHijackWebSocketAcceptsMissingType(t *testing.T) {
	handler := &Handler{
		FnosPortIconHijack: models.FnosPortIconHijackConfig{Enabled: true},
	}
	req := httptest.NewRequest(http.MethodGet, "/websocket", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	if !handler.shouldProxyFnosPortIconHijackWebSocket(req) {
		t.Fatal("expected websocket request without type query to be hijacked")
	}
}

func TestShouldProxyFnosPortIconHijackWebSocketAcceptsTimerType(t *testing.T) {
	handler := &Handler{
		FnosPortIconHijack: models.FnosPortIconHijackConfig{Enabled: true},
	}
	req := httptest.NewRequest(http.MethodGet, "/websocket?type=timer", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	if !handler.shouldProxyFnosPortIconHijackWebSocket(req) {
		t.Fatal("expected websocket timer request to be hijacked")
	}
}

func TestBuildFnosPortIconHijackWebSocketURLUsesHostEntryPath(t *testing.T) {
	targetURL, err := url.Parse("http://127.0.0.1:19122/p")
	if err != nil {
		t.Fatalf("parse target URL: %v", err)
	}
	incomingURL, err := url.Parse("https://photos.example.com/websocket?type=timer")
	if err != nil {
		t.Fatalf("parse incoming URL: %v", err)
	}

	got := buildFnosPortIconHijackWebSocketURL(
		targetURL,
		incomingURL,
		false,
		"",
		models.HostTargetPathModeEntry,
	)

	if got.Scheme != "ws" {
		t.Fatalf("upstream scheme = %q, want ws", got.Scheme)
	}
	if got.Path != "/websocket" {
		t.Fatalf("upstream path = %q, want /websocket", got.Path)
	}
	if got.RawQuery != "type=timer" {
		t.Fatalf("upstream query = %q, want type=timer", got.RawQuery)
	}
}

func TestBuildFnosPortIconHijackWebSocketURLUsesHostPrefixPath(t *testing.T) {
	targetURL, err := url.Parse("http://127.0.0.1:19122/webdav")
	if err != nil {
		t.Fatalf("parse target URL: %v", err)
	}
	incomingURL, err := url.Parse("https://dav.example.com/websocket?type=timer")
	if err != nil {
		t.Fatalf("parse incoming URL: %v", err)
	}

	got := buildFnosPortIconHijackWebSocketURL(
		targetURL,
		incomingURL,
		false,
		"",
		models.HostTargetPathModePrefix,
	)

	if got.Path != "/webdav/websocket" {
		t.Fatalf("upstream path = %q, want /webdav/websocket", got.Path)
	}
}

func TestBuildFnosPortIconHijackWebSocketURLPreservesHostPrefixRawPath(t *testing.T) {
	targetURL, err := url.Parse("http://127.0.0.1:19122/webdav")
	if err != nil {
		t.Fatalf("parse target URL: %v", err)
	}
	incomingURL, err := url.Parse("https://dav.example.com/folder%2Fname?type=timer")
	if err != nil {
		t.Fatalf("parse incoming URL: %v", err)
	}

	got := buildFnosPortIconHijackWebSocketURL(
		targetURL,
		incomingURL,
		false,
		"",
		models.HostTargetPathModePrefix,
	)

	if got.Path != "/webdav/folder/name" {
		t.Fatalf("upstream path = %q, want /webdav/folder/name", got.Path)
	}
	if got.RawPath != "/webdav/folder%2Fname" {
		t.Fatalf("upstream raw path = %q, want /webdav/folder%%2Fname", got.RawPath)
	}
}

func TestFnosPortIconHijackHTTPResponseRewritesServiceListIgnoringQuery(t *testing.T) {
	handler := &Handler{
		ProxyPort: 18080,
		AuthConfig: models.AuthConfig{
			EdgeClientIPEnabled: true,
		},
		FnosPortIconHijack: models.FnosPortIconHijackConfig{Enabled: true},
	}
	handler.sslBundle.Store(&sslRuntimeBundle{
		certificates: []models.SSLDeployedCertificateInfo{{Domains: []string{"example.com"}}},
	})

	resp := &http.Response{
		Header: http.Header{},
		Body: io.NopCloser(strings.NewReader(`{
			"code":0,
			"data":{
				"list":[
					{
						"appName":"EmbyServer4-9",
						"urls":{
							"protocol":"http",
							"host":"",
							"port":"8096",
							"path":"/web/index.html"
						}
					}
				]
			}
		}`)),
		Request: httptest.NewRequest(http.MethodGet, "/app-center/v1/service/list?lan=zh-CN", nil),
	}

	err := handler.maybeRewriteFnosPortIconHijackHTTPResponse(resp, []models.HostRule{
		{Host: "emby.example.com", Target: "http://127.0.0.1:8096"},
	})
	if err != nil {
		t.Fatalf("rewrite HTTP response returned error: %v", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read rewritten body: %v", err)
	}

	var decoded struct {
		Data struct {
			List []struct {
				URLs struct {
					Protocol string `json:"protocol"`
					Host     string `json:"host"`
					Port     string `json:"port"`
					Path     string `json:"path"`
				} `json:"urls"`
			} `json:"list"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("rewritten JSON is invalid: %v", err)
	}
	if got := decoded.Data.List[0].URLs.Protocol; got != "https" {
		t.Fatalf("protocol = %q, want https", got)
	}
	if got := decoded.Data.List[0].URLs.Host; got != "emby.example.com" {
		t.Fatalf("host = %q, want emby.example.com", got)
	}
	if got := decoded.Data.List[0].URLs.Port; got != "443" {
		t.Fatalf("port = %q, want 443", got)
	}
	if got := decoded.Data.List[0].URLs.Path; got != "" {
		t.Fatalf("path = %q, want empty string", got)
	}
}

func TestFnosPortIconHijackHTTPResponseSkipsLargeServiceList(t *testing.T) {
	handler := &Handler{
		FnosPortIconHijack: models.FnosPortIconHijackConfig{Enabled: true},
	}
	body := `{"data":{"list":[{"uri":{"host":"","port":"8096","path":"/web/index.html"}}]}}` +
		strings.Repeat(" ", int(fnosPortIconHijackHTTPBodyLimitBytes)+1)
	resp := &http.Response{
		Header:        http.Header{},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       httptest.NewRequest(http.MethodGet, "/app-center/v1/service/list", nil),
	}

	err := handler.maybeRewriteFnosPortIconHijackHTTPResponse(resp, []models.HostRule{
		{Host: "emby.example.com", Target: "http://127.0.0.1:8096"},
	})
	if err != nil {
		t.Fatalf("rewrite HTTP response returned error: %v", err)
	}

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read skipped body: %v", err)
	}
	if string(got) != body {
		t.Fatal("large service list body changed despite exceeding rewrite limit")
	}
}

func TestFnosPortIconHijackHTTPResponseRewritesUnknownLengthWithinLimit(t *testing.T) {
	handler := &Handler{
		FnosPortIconHijack: models.FnosPortIconHijackConfig{Enabled: true},
	}
	body := []byte(`{"data":{"list":[{"uri":{"host":"","port":"8096","path":"/web/index.html"}}]}}`)
	rc := newTrackingReadCloser(body)
	resp := &http.Response{
		Header:        http.Header{},
		Body:          rc,
		ContentLength: -1,
		Request:       httptest.NewRequest(http.MethodGet, "/app-center/v1/service/list", nil),
	}

	err := handler.maybeRewriteFnosPortIconHijackHTTPResponse(resp, []models.HostRule{
		{Host: "emby.example.com", Target: "http://127.0.0.1:8096"},
	})
	if err != nil {
		t.Fatalf("rewrite HTTP response returned error: %v", err)
	}
	if rc.readCount == 0 {
		t.Fatal("unknown-length FNOS response was not read")
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read rewritten body: %v", err)
	}
	var decoded struct {
		Data struct {
			List []struct {
				URI struct {
					Host string `json:"host"`
					Port string `json:"port"`
					Path string `json:"path"`
				} `json:"uri"`
			} `json:"list"`
		} `json:"data"`
	}
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("decode rewritten body: %v", err)
	}
	if len(decoded.Data.List) != 1 {
		t.Fatalf("list length = %d, want 1", len(decoded.Data.List))
	}
	if got := decoded.Data.List[0].URI.Host; got != "emby.example.com" {
		t.Fatalf("host = %q, want emby.example.com", got)
	}
	if got := decoded.Data.List[0].URI.Port; got != "7999" {
		t.Fatalf("port = %q, want 7999", got)
	}
	if got := decoded.Data.List[0].URI.Path; got != "" {
		t.Fatalf("path = %q, want empty string", got)
	}
}

func TestFnosPortIconHijackHTTPResponsePreservesUnknownLengthOverLimit(t *testing.T) {
	handler := &Handler{
		FnosPortIconHijack: models.FnosPortIconHijackConfig{Enabled: true},
	}
	body := []byte(`{"data":{"list":[{"uri":{"host":"","port":"8096","path":"/web/index.html"}}]}}` +
		strings.Repeat(" ", int(fnosPortIconHijackHTTPBodyLimitBytes)+1))
	resp := &http.Response{
		Header:        http.Header{},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: -1,
		Request:       httptest.NewRequest(http.MethodGet, "/app-center/v1/service/list", nil),
	}

	err := handler.maybeRewriteFnosPortIconHijackHTTPResponse(resp, []models.HostRule{
		{Host: "emby.example.com", Target: "http://127.0.0.1:8096"},
	})
	if err != nil {
		t.Fatalf("rewrite HTTP response returned error: %v", err)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read preserved body: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatal("unknown-length service list body changed despite exceeding rewrite limit")
	}
}

func TestFnosPortIconHijackWebSocketRewritesUpstreamMessages(t *testing.T) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(_ *http.Request) bool {
			return true
		},
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upstream upgrade failed: %v", err)
			return
		}
		defer conn.Close()

		payload := []byte(`{"data":{"list":[{"uri":{"host":"","port":"8096","path":"/web/index.html"}}]}}`)
		if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
			t.Errorf("upstream write failed: %v", err)
		}
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	handler := &Handler{ProxyPort: 18080}
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := handler.proxyFnosPortIconHijackWebSocket(
			w,
			r,
			fnosPortIconHijackWebSocketOptions{targetURL: targetURL},
			map[int]string{8096: "emby.example.com"},
		)
		if err != nil && !isFNAppConnectionTermination(err) {
			t.Errorf("proxy websocket failed: %v", err)
		}
	}))
	defer proxyServer.Close()

	wsURL := "ws" + strings.TrimPrefix(proxyServer.URL, "http") + "/websocket?type=main"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial proxy websocket: %v", err)
	}
	defer conn.Close()

	_, message, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read proxied websocket message: %v", err)
	}

	var decoded struct {
		Data struct {
			List []struct {
				URI struct {
					Host string `json:"host"`
					Port string `json:"port"`
					Path string `json:"path"`
				} `json:"uri"`
			} `json:"list"`
		} `json:"data"`
	}
	if err := json.Unmarshal(message, &decoded); err != nil {
		t.Fatalf("proxied message JSON is invalid: %v", err)
	}
	if got := decoded.Data.List[0].URI.Host; got != "emby.example.com" {
		t.Fatalf("host = %q, want emby.example.com", got)
	}
	if got := decoded.Data.List[0].URI.Port; got != "18080" {
		t.Fatalf("port = %q, want 18080", got)
	}
	if got := decoded.Data.List[0].URI.Path; got != "" {
		t.Fatalf("path = %q, want empty string", got)
	}
}

func TestFnosPortIconHijackWebSocketUpstreamFailureCanResetConnection(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	upstream.Close()

	handler := &Handler{}
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/websocket", nil)
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	req.Proto = "HTTP/2.0"
	options := fnosPortIconHijackWebSocketOptions{
		targetURL: targetURL,
		unmatchedRoute: models.GatewayUnmatchedRouteConfig{
			UpstreamErrorDetail: models.GatewayUpstreamErrorDetailResetConnection,
		},
	}

	defer func() {
		if recovered := recover(); recovered != http.ErrAbortHandler {
			t.Fatalf("panic = %#v, want http.ErrAbortHandler", recovered)
		}
	}()
	_ = handler.proxyFnosPortIconHijackWebSocket(
		httptest.NewRecorder(),
		req,
		options,
		nil,
	)
}

func TestFnosPortIconHijackWebSocketRelaysTimerMessagesWithoutRewrite(t *testing.T) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(_ *http.Request) bool {
			return true
		},
	}

	upstreamPayload := []byte(`{"data":{"list":[{"uri":{"host":"","port":"8096","path":"/web/index.html"}}]}}`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upstream upgrade failed: %v", err)
			return
		}
		defer conn.Close()

		if err := conn.WriteMessage(websocket.TextMessage, upstreamPayload); err != nil {
			t.Errorf("upstream write failed: %v", err)
		}
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	handler := &Handler{ProxyPort: 18080}
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := handler.proxyFnosPortIconHijackWebSocket(
			w,
			r,
			fnosPortIconHijackWebSocketOptions{targetURL: targetURL},
			map[int]string{8096: "emby.example.com"},
		)
		if err != nil && !isFNAppConnectionTermination(err) {
			t.Errorf("proxy websocket failed: %v", err)
		}
	}))
	defer proxyServer.Close()

	wsURL := "ws" + strings.TrimPrefix(proxyServer.URL, "http") + "/websocket?type=timer"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial proxy websocket: %v", err)
	}
	defer conn.Close()

	_, message, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read proxied websocket message: %v", err)
	}
	if string(message) != string(upstreamPayload) {
		t.Fatalf("proxied timer message = %s, want %s", message, upstreamPayload)
	}
}

func TestFnosPortIconHijackWebSocketMaxLifetimeClosesClientAndUpstream(t *testing.T) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(_ *http.Request) bool {
			return true
		},
	}
	upstreamClosed := make(chan error, 1)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upstream upgrade failed: %v", err)
			return
		}
		defer conn.Close()

		_, _, err = conn.ReadMessage()
		upstreamClosed <- err
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	handler := &Handler{}
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := handler.proxyFnosPortIconHijackWebSocket(
			w,
			r,
			fnosPortIconHijackWebSocketOptions{
				targetURL:            targetURL,
				webSocketMaxLifetime: 25 * time.Millisecond,
			},
			nil,
		)
		if err != nil && !isFNAppConnectionTermination(err) {
			t.Errorf("proxy websocket failed: %v", err)
		}
	}))
	defer proxyServer.Close()

	wsURL := "ws" + strings.TrimPrefix(proxyServer.URL, "http") + "/websocket?type=main"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial proxy websocket: %v", err)
	}
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set client read deadline: %v", err)
	}
	_, _, err = conn.ReadMessage()
	var closeErr *websocket.CloseError
	if !errors.As(err, &closeErr) || closeErr.Code != websocket.CloseNormalClosure {
		t.Fatalf("client read error = %v, want normal websocket close", err)
	}

	select {
	case err := <-upstreamClosed:
		if !websocket.IsCloseError(err, websocket.CloseNormalClosure) {
			t.Fatalf("upstream read error = %v, want normal websocket close", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream websocket to close")
	}
}

func legacyHostRuleTargetPortForBenchmark(rawTarget string) (int, bool) {
	parsed, err := url.Parse(strings.TrimSpace(rawTarget))
	if err != nil || parsed.Host == "" {
		return 0, false
	}
	if port := parsed.Port(); port != "" {
		parsedPort, err := strconv.Atoi(port)
		if err == nil && parsedPort > 0 && parsedPort <= 65535 {
			return parsedPort, true
		}
		return 0, false
	}

	switch strings.ToLower(parsed.Scheme) {
	case "http", "ws":
		return 80, true
	case "https", "wss":
		return 443, true
	default:
		return 0, false
	}
}

func buildFnosPortIconHijackTargetsLegacyForBenchmark(hostRules []models.HostRule) map[int]string {
	targets := make(map[int]string)
	for _, rule := range hostRules {
		host := normalizeRequestHost(rule.Host)
		if host == "" {
			continue
		}

		port, ok := legacyHostRuleTargetPortForBenchmark(rule.Target)
		if !ok {
			continue
		}
		if _, exists := targets[port]; exists {
			continue
		}
		targets[port] = host
	}
	return targets
}

func BenchmarkHostRuleTargetPortExplicit(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchmarkFnosPortSink, benchmarkBoolSink = hostRuleTargetPort("http://127.0.0.1:8096/path")
	}
}

func BenchmarkHostRuleTargetPortExplicitOld(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchmarkFnosPortSink, benchmarkBoolSink = legacyHostRuleTargetPortForBenchmark("http://127.0.0.1:8096/path")
	}
}

func BenchmarkHostRuleTargetPortDefaultHTTPS(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchmarkFnosPortSink, benchmarkBoolSink = hostRuleTargetPort("https://emby.example.com/web")
	}
}

func BenchmarkHostRuleTargetPortDefaultHTTPSOld(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchmarkFnosPortSink, benchmarkBoolSink = legacyHostRuleTargetPortForBenchmark("https://emby.example.com/web")
	}
}

func BenchmarkBuildFnosPortIconHijackTargets(b *testing.B) {
	hostRules := []models.HostRule{
		{Host: "Emby.Example.COM", Target: "http://127.0.0.1:8096/web/index.html"},
		{Host: "jellyfin.example.com", Target: "https://192.168.1.10:8920"},
		{Host: "calibre.example.com", Target: "http://[::1]:8083"},
		{Host: "ignored.example.com", Target: "ftp://192.168.1.10"},
		{Host: "files.example.com", Target: "http://192.168.1.10"},
		{Host: "socket.example.com", Target: "wss://192.168.1.11/socket"},
	}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkFnosTargetsSink = buildFnosPortIconHijackTargets(hostRules)
	}
}

func BenchmarkBuildFnosPortIconHijackTargetsOld(b *testing.B) {
	hostRules := []models.HostRule{
		{Host: "Emby.Example.COM", Target: "http://127.0.0.1:8096/web/index.html"},
		{Host: "jellyfin.example.com", Target: "https://192.168.1.10:8920"},
		{Host: "calibre.example.com", Target: "http://[::1]:8083"},
		{Host: "ignored.example.com", Target: "ftp://192.168.1.10"},
		{Host: "files.example.com", Target: "http://192.168.1.10"},
		{Host: "socket.example.com", Target: "wss://192.168.1.11/socket"},
	}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkFnosTargetsSink = buildFnosPortIconHijackTargetsLegacyForBenchmark(hostRules)
	}
}
