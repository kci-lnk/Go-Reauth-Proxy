package proxy

import (
	"context"
	"go-reauth-proxy/pkg/models"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

var benchmarkPortSink string

func requestWithLocalPort(req *http.Request, port int) *http.Request {
	return req.WithContext(context.WithValue(
		req.Context(),
		http.LocalAddrContextKey,
		&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port},
	))
}

func requestWithLocalAddress(req *http.Request, ip string, port int) *http.Request {
	return req.WithContext(context.WithValue(
		req.Context(),
		http.LocalAddrContextKey,
		&net.TCPAddr{IP: net.ParseIP(ip), Port: port},
	))
}

func TestBuildHTTPSRedirectURLDoesNotUseLocalOriginPort(t *testing.T) {
	req := requestWithLocalPort(
		httptest.NewRequest(http.MethodGet, "http://auth.fnknock.cn/", nil),
		7999,
	)

	got := BuildHTTPSRedirectURL(req, models.AuthConfig{})
	if got != "https://auth.fnknock.cn/" {
		t.Fatalf("BuildHTTPSRedirectURL() = %q, want %q", got, "https://auth.fnknock.cn/")
	}
}

func TestBuildHTTPSRedirectURLKeepsExplicitPublicPorts(t *testing.T) {
	tests := []struct {
		name       string
		rawURL     string
		authConfig models.AuthConfig
		headers    map[string]string
		want       string
	}{
		{
			name:       "configured public https port",
			rawURL:     "http://auth.fnknock.cn/app?x=1",
			authConfig: models.AuthConfig{PublicHTTPSPort: 8443},
			want:       "https://auth.fnknock.cn:8443/app?x=1",
		},
		{
			name:    "forwarded port",
			rawURL:  "http://auth.fnknock.cn/app?x=1",
			headers: map[string]string{"X-Forwarded-Port": "9443"},
			want:    "https://auth.fnknock.cn:9443/app?x=1",
		},
		{
			name:   "host port",
			rawURL: "http://auth.fnknock.cn:10443/app?x=1",
			want:   "https://auth.fnknock.cn:10443/app?x=1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := requestWithLocalPort(httptest.NewRequest(http.MethodGet, tt.rawURL, nil), 7999)
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			if got := BuildHTTPSRedirectURL(req, tt.authConfig); got != tt.want {
				t.Fatalf("BuildHTTPSRedirectURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSplitRequestHostPortMatchesLegacyBehavior(t *testing.T) {
	cases := []string{
		"",
		" auth.fnknock.cn ",
		"auth.fnknock.cn:8443",
		"auth.fnknock.cn:",
		":8443",
		"auth.fnknock.cn:abc",
		"auth.fnknock.cn:8443:extra",
		"2001:db8::1",
		"[2001:db8::1]",
		"[2001:db8::1]:8443",
		"[2001:db8::1]:abc",
		"[2001:db8::1]trailing",
		"http://auth.fnknock.cn",
		"auth.fnknock.cn/path",
	}

	for _, tc := range cases {
		gotHost, gotPort := splitRequestHostPort(tc)
		wantHost, wantPort := legacySplitRequestHostPort(tc)
		if gotHost != wantHost || gotPort != wantPort {
			t.Fatalf("splitRequestHostPort(%q) = (%q, %q), want legacy (%q, %q)", tc, gotHost, gotPort, wantHost, wantPort)
		}
	}
}

func legacySplitRequestHostPort(host string) (string, string) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", ""
	}

	parsed, err := url.Parse("//" + host)
	if err != nil {
		return host, ""
	}

	hostname := parsed.Hostname()
	if hostname == "" {
		return host, ""
	}

	return hostname, parsed.Port()
}

func TestIsPublicHTTPSRequestUsesForwardedScheme(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
	}{
		{
			name:    "forwarded header",
			headers: map[string]string{"Forwarded": `for=192.0.2.1;proto=https;host=auth.fnknock.cn`},
		},
		{
			name:    "x forwarded proto",
			headers: map[string]string{"X-Forwarded-Proto": "https"},
		},
		{
			name:    "x forwarded scheme",
			headers: map[string]string{"X-Forwarded-Scheme": "https"},
		},
		{
			name:    "x original proto",
			headers: map[string]string{"X-Original-Proto": "https"},
		},
		{
			name:    "cloudflare visitor",
			headers: map[string]string{"CF-Visitor": `{"scheme":"https"}`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://auth.fnknock.cn/", nil)
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			if !IsPublicHTTPSRequest(req) {
				t.Fatalf("IsPublicHTTPSRequest() = false, want true")
			}
		})
	}
}

func TestCloudflareVisitorScheme(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "exact", value: `{"scheme":"https"}`, want: "https"},
		{name: "spaces", value: `{ "scheme" : "https" }`, want: "https"},
		{name: "uppercase", value: `{"scheme":"HTTPS"}`, want: "https"},
		{name: "other field first", value: `{"foo":"scheme","scheme":"http"}`, want: "http"},
		{name: "escaped fallback", value: `{"scheme":"http\u0073"}`, want: "https"},
		{name: "unsupported", value: `{"scheme":"ftp"}`, want: ""},
		{name: "invalid json", value: `{"scheme":`, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cloudflareVisitorScheme(tt.value); got != tt.want {
				t.Fatalf("cloudflareVisitorScheme(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestIsValidPortMatchesLegacyBehavior(t *testing.T) {
	cases := []string{
		"",
		"0",
		"1",
		"80",
		"443",
		"65535",
		"65536",
		"99999",
		"100000",
		" 8443 ",
		"08",
		"+80",
		"+65535",
		"+65536",
		"-80",
		"80/tcp",
		"abc",
	}

	for _, tc := range cases {
		if got, want := isValidPort(tc), legacyIsValidPort(tc); got != want {
			t.Fatalf("isValidPort(%q) = %v, want legacy %v", tc, got, want)
		}
	}
}

func legacyIsValidPort(value string) bool {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	return err == nil && port > 0 && port <= 65535
}

func TestPublicPortFromAuthBaseURLMatchesLegacyBehavior(t *testing.T) {
	tests := []struct {
		name       string
		rawBaseURL string
		scheme     string
	}{
		{
			name:       "empty",
			rawBaseURL: "",
			scheme:     "https",
		},
		{
			name:       "explicit port",
			rawBaseURL: " https://auth.fnknock.cn:8443/path ",
			scheme:     "https",
		},
		{
			name:       "uppercase scheme",
			rawBaseURL: "HTTPS://auth.fnknock.cn:8443/path",
			scheme:     "https",
		},
		{
			name:       "trimmed requested scheme",
			rawBaseURL: "https://auth.fnknock.cn:8443/path",
			scheme:     " HTTPS ",
		},
		{
			name:       "scheme mismatch",
			rawBaseURL: "http://auth.fnknock.cn:8080/path",
			scheme:     "https",
		},
		{
			name:       "no port",
			rawBaseURL: "https://auth.fnknock.cn/path",
			scheme:     "https",
		},
		{
			name:       "empty port",
			rawBaseURL: "https://auth.fnknock.cn:/path",
			scheme:     "https",
		},
		{
			name:       "invalid port",
			rawBaseURL: "https://auth.fnknock.cn:abc/path",
			scheme:     "https",
		},
		{
			name:       "out of range port",
			rawBaseURL: "https://auth.fnknock.cn:70000/path",
			scheme:     "https",
		},
		{
			name:       "userinfo",
			rawBaseURL: "https://user:pass@auth.fnknock.cn:8443/path?x=1",
			scheme:     "https",
		},
		{
			name:       "ipv6 explicit port",
			rawBaseURL: "https://[2001:db8::1]:8443/path",
			scheme:     "https",
		},
		{
			name:       "ipv6 no port",
			rawBaseURL: "https://[2001:db8::1]/path",
			scheme:     "https",
		},
		{
			name:       "unbracketed ipv6 legacy port",
			rawBaseURL: "https://2001:db8::1",
			scheme:     "https",
		},
		{
			name:       "plus port rejected by url parser",
			rawBaseURL: "https://auth.fnknock.cn:+80/path",
			scheme:     "https",
		},
		{
			name:       "leading zero port preserved",
			rawBaseURL: "https://auth.fnknock.cn:080/path",
			scheme:     "https",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := publicPortFromAuthBaseURL(tt.rawBaseURL, tt.scheme)
			want := legacyPublicPortFromAuthBaseURL(tt.rawBaseURL, tt.scheme)
			if got != want {
				t.Fatalf("publicPortFromAuthBaseURL(%q, %q) = %q, want legacy %q", tt.rawBaseURL, tt.scheme, got, want)
			}
		})
	}
}

func legacyPublicPortFromAuthBaseURL(rawBaseURL string, scheme string) string {
	baseURL, err := url.Parse(strings.TrimSpace(rawBaseURL))
	if err != nil || baseURL == nil {
		return ""
	}

	if !strings.EqualFold(baseURL.Scheme, strings.TrimSpace(scheme)) {
		return ""
	}

	port := strings.TrimSpace(baseURL.Port())
	if !isValidPort(port) {
		return ""
	}

	return port
}

func TestShouldRedirectHTTPToHTTPSRequiresTrustedForwardedProto(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://auth.fnknock.cn/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")

	if !ShouldRedirectHTTPToHTTPS(req, models.AuthConfig{}) {
		t.Fatal("ShouldRedirectHTTPToHTTPS() = false without trust_forwarded_proto, want true")
	}
	if ShouldRedirectHTTPToHTTPS(req, models.AuthConfig{TrustForwardedProto: true}) {
		t.Fatal("ShouldRedirectHTTPToHTTPS() = true with trusted forwarded https, want false")
	}
}

func BenchmarkPublicRequestSchemeNoForwardedHeaders(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "http://auth.fnknock.cn/", nil)

	b.ReportAllocs()
	for b.Loop() {
		benchmarkHostSink = publicRequestScheme(req)
	}
}

func BenchmarkPublicRequestSchemeForwardedHeader(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "http://auth.fnknock.cn/", nil)
	req.Header.Set("Forwarded", `for=192.0.2.1; proto="https"; host=auth.fnknock.cn`)

	b.ReportAllocs()
	for b.Loop() {
		benchmarkHostSink = publicRequestScheme(req)
	}
}

func BenchmarkPublicRequestSchemeCloudflareVisitor(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "http://auth.fnknock.cn/", nil)
	req.Header.Set("CF-Visitor", `{"scheme":"https"}`)

	b.ReportAllocs()
	for b.Loop() {
		benchmarkHostSink = publicRequestScheme(req)
	}
}

func BenchmarkSplitRequestHostPortNoPort(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchmarkHostSink, benchmarkPortSink = splitRequestHostPort("auth.fnknock.cn")
	}
}

func BenchmarkSplitRequestHostPortWithPort(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchmarkHostSink, benchmarkPortSink = splitRequestHostPort("auth.fnknock.cn:8443")
	}
}

func BenchmarkSplitRequestHostPortIPv6WithPort(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchmarkHostSink, benchmarkPortSink = splitRequestHostPort("[2001:db8::1]:8443")
	}
}

func BenchmarkIsValidPortValid(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBoolSink = isValidPort("8443")
	}
}

func BenchmarkIsValidPortValidOld(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBoolSink = legacyIsValidPort("8443")
	}
}

func BenchmarkIsValidPortInvalid(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBoolSink = isValidPort("8443/tcp")
	}
}

func BenchmarkIsValidPortInvalidOld(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBoolSink = legacyIsValidPort("8443/tcp")
	}
}

func BenchmarkPublicPortFromAuthBaseURL(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchmarkPortSink = publicPortFromAuthBaseURL("https://auth.fnknock.cn:8443/path", "https")
	}
}

func BenchmarkPublicPortFromAuthBaseURLOld(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchmarkPortSink = legacyPublicPortFromAuthBaseURL("https://auth.fnknock.cn:8443/path", "https")
	}
}

func TestBuildPublicAuthLoginURLDoesNotAppendLocalOriginPort(t *testing.T) {
	req := requestWithLocalPort(
		httptest.NewRequest(http.MethodGet, "http://auth.fnknock.cn/private?x=1", nil),
		7999,
	)
	req.Header.Set("X-Forwarded-Proto", "https")

	originalURL := buildPublicRequestURL(req, models.AuthConfig{}, "")
	loginURL := buildPublicAuthLoginURL(models.AuthConfig{
		PublicAuthBaseURL: "https://auth.fnknock.cn",
		LoginURL:          "/#/login",
	}, req, originalURL)
	if loginURL == nil {
		t.Fatal("buildPublicAuthLoginURL() returned nil")
	}
	if strings.Contains(loginURL.Host, ":7999") {
		t.Fatalf("login URL host = %q, must not contain local origin port", loginURL.Host)
	}
	redirectURI := loginURL.Query().Get("redirect_uri")
	if redirectURI != "https://auth.fnknock.cn/private?x=1" {
		t.Fatalf("redirect_uri = %q, want %q", redirectURI, "https://auth.fnknock.cn/private?x=1")
	}
}

func TestBuildPublicAuthLoginURLEdgeModeOverridesOriginPort(t *testing.T) {
	tests := []struct {
		name       string
		authConfig models.AuthConfig
	}{
		{
			name: "Aliyun ESA",
			authConfig: models.AuthConfig{
				EdgeClientIPEnabled: true,
				AliyunESAEnabled:    true,
			},
		},
		{
			name: "Tencent EdgeOne",
			authConfig: models.AuthConfig{
				EdgeClientIPEnabled:   true,
				TencentEdgeOneEnabled: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://fnos.edge.example:7999/", nil)
			req.Header.Set("X-Forwarded-Host", "fnos.edge.example:7999")
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("X-Forwarded-Port", "7999")

			tt.authConfig.PublicAuthBaseURL = "https://auth.edge.example:7999"
			tt.authConfig.PublicHTTPSPort = 7999
			tt.authConfig.LoginURL = "/login"

			originalURL := buildPublicRequestURL(req, tt.authConfig, "")
			if originalURL == nil {
				t.Fatal("buildPublicRequestURL() returned nil")
			}
			if got, want := originalURL.String(), "https://fnos.edge.example/"; got != want {
				t.Fatalf("original URL = %q, want %q", got, want)
			}

			loginURL := buildPublicAuthLoginURL(tt.authConfig, req, originalURL)
			if loginURL == nil {
				t.Fatal("buildPublicAuthLoginURL() returned nil")
			}
			if got, want := loginURL.String(), "https://auth.edge.example/login?redirect_uri=https%3A%2F%2Ffnos.edge.example%2F"; got != want {
				t.Fatalf("login URL = %q, want %q", got, want)
			}
		})
	}
}

func TestBuildPublicAuthLoginURLCloudflareTunnelOverridesOriginPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://app-5920.tu.wxlnk.com:7999/", nil)
	req.Header.Set("X-Forwarded-Host", "app-5920.tu.wxlnk.com:7999")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Port", "7999")
	req.Header.Set("CF-Ray", "a261079199891d1c-SIN")
	req.Header.Set("CF-Visitor", `{"scheme":"https"}`)
	req.Header.Set("CF-Connecting-IP", "203.0.113.7")

	authConfig := models.AuthConfig{
		PublicAuthBaseURL: "https://auth.tu.wxlnk.com:7999",
		PublicHTTPSPort:   7999,
		LoginURL:          "/login",
	}
	originalURL := buildPublicRequestURL(req, authConfig, "")
	if originalURL == nil {
		t.Fatal("buildPublicRequestURL() returned nil")
	}
	if got, want := originalURL.String(), "https://app-5920.tu.wxlnk.com/"; got != want {
		t.Fatalf("original URL = %q, want %q", got, want)
	}

	loginURL := buildPublicAuthLoginURL(authConfig, req, originalURL)
	if loginURL == nil {
		t.Fatal("buildPublicAuthLoginURL() returned nil")
	}
	if got, want := loginURL.String(), "https://auth.tu.wxlnk.com/login?redirect_uri=https%3A%2F%2Fapp-5920.tu.wxlnk.com%2F"; got != want {
		t.Fatalf("login URL = %q, want %q", got, want)
	}
}

func TestBuildPublicAuthLoginURLManagedCloudflareIngressOverridesOriginPortWithoutEdgeHeaders(t *testing.T) {
	req := requestWithLocalAddress(
		httptest.NewRequest(http.MethodGet, "http://app-5920.tu.wxlnk.com:7999/", nil),
		"127.0.0.1",
		ManagedCloudflareIngressPort,
	)
	req.Header.Set("X-Forwarded-Host", "app-5920.tu.wxlnk.com:7999")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Port", "7999")

	authConfig := models.AuthConfig{
		PublicAuthBaseURL: "https://auth.tu.wxlnk.com:7999",
		PublicHTTPSPort:   7999,
		LoginURL:          "/login",
	}
	originalURL := buildPublicRequestURL(req, authConfig, "")
	if originalURL == nil {
		t.Fatal("buildPublicRequestURL() returned nil")
	}
	if got, want := originalURL.String(), "https://app-5920.tu.wxlnk.com/"; got != want {
		t.Fatalf("original URL = %q, want %q", got, want)
	}

	loginURL := buildPublicAuthLoginURL(authConfig, req, originalURL)
	if loginURL == nil {
		t.Fatal("buildPublicAuthLoginURL() returned nil")
	}
	if got, want := loginURL.String(), "https://auth.tu.wxlnk.com/login?redirect_uri=https%3A%2F%2Fapp-5920.tu.wxlnk.com%2F"; got != want {
		t.Fatalf("login URL = %q, want %q", got, want)
	}
}

func TestCloudflareEdgeRequestRequiresVerifiedHeaderSet(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		scheme  string
		want    bool
	}{
		{
			name: "valid",
			headers: map[string]string{
				"CF-Ray":           "a261079199891d1c-SIN",
				"CF-Visitor":       `{"scheme":"https"}`,
				"CF-Connecting-IP": "203.0.113.7",
			},
			scheme: "https",
			want:   true,
		},
		{
			name: "missing ray",
			headers: map[string]string{
				"CF-Visitor":       `{"scheme":"https"}`,
				"CF-Connecting-IP": "203.0.113.7",
			},
			scheme: "https",
		},
		{
			name: "invalid connecting ip",
			headers: map[string]string{
				"CF-Ray":           "a261079199891d1c-SIN",
				"CF-Visitor":       `{"scheme":"https"}`,
				"CF-Connecting-IP": "not-an-ip",
			},
			scheme: "https",
		},
		{
			name: "visitor scheme mismatch",
			headers: map[string]string{
				"CF-Ray":           "a261079199891d1c-SIN",
				"CF-Visitor":       `{"scheme":"http"}`,
				"CF-Connecting-IP": "2001:db8::7",
			},
			scheme: "https",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://app.example/", nil)
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}
			if got := isCloudflareEdgeRequest(req, tt.scheme); got != tt.want {
				t.Fatalf("isCloudflareEdgeRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestManagedCloudflareTunnelIngressUsesDedicatedLoopbackDestination(t *testing.T) {
	tests := []struct {
		name    string
		localIP string
		port    int
		want    bool
	}{
		{name: "managed cloudflare ingress", localIP: "127.0.0.1", port: ManagedCloudflareIngressPort, want: true},
		{name: "ordinary loopback ingress", localIP: "127.0.0.1", port: 7999},
		{name: "managed port on lan", localIP: "192.168.1.10", port: ManagedCloudflareIngressPort},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := requestWithLocalAddress(
				httptest.NewRequest(http.MethodGet, "http://app.example/", nil),
				tt.localIP,
				tt.port,
			)
			if got := isManagedCloudflareTunnelIngress(req); got != tt.want {
				t.Fatalf("isManagedCloudflareTunnelIngress() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolveClientIPManagedCloudflareIngressIgnoresSpoofedForwardedHeaders(t *testing.T) {
	req := requestWithLocalAddress(
		httptest.NewRequest(http.MethodGet, "http://app.example/", nil),
		"127.0.0.1",
		ManagedCloudflareIngressPort,
	)
	req.RemoteAddr = "127.0.0.1:49952"
	req.Header.Set("CF-Connecting-IP", "198.51.100.25")
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	req.Header.Set("X-Real-IP", "192.168.1.100")

	if got, want := resolveClientIP(req, models.AuthConfig{}, true), "198.51.100.25"; got != want {
		t.Fatalf("resolveClientIP() = %q, want %q", got, want)
	}
}

func TestResolveClientIPManagedCloudflareIngressRestoresOriginalIPv6FromPseudoIPv4(t *testing.T) {
	const originalIPv6 = "2409:8a00:1234:5678::25"
	for _, pseudoIPv4 := range []string{
		"240.0.0.1",
		"247.37.202.182",
		"251.169.165.161",
		"253.21.85.116",
		"255.83.0.1",
		"255.255.255.254",
	} {
		t.Run(pseudoIPv4, func(t *testing.T) {
			req := requestWithLocalAddress(
				httptest.NewRequest(http.MethodGet, "http://app.example/", nil),
				"127.0.0.1",
				ManagedCloudflareIngressPort,
			)
			req.RemoteAddr = "127.0.0.1:49952"
			req.Header.Set("CF-Connecting-IP", pseudoIPv4)
			req.Header.Set("CF-Connecting-IPv6", originalIPv6)
			req.Header.Set("X-Forwarded-For", pseudoIPv4)

			if got := resolveClientIP(req, models.AuthConfig{}, true); got != originalIPv6 {
				t.Fatalf("resolveClientIP() = %q, want original IPv6 %q", got, originalIPv6)
			}
		})
	}
}

func TestResolveClientIPManagedCloudflareIngressKeepsPseudoIPv4WithoutUsableIPv6(t *testing.T) {
	const pseudoIPv4 = "251.169.165.161"
	for _, originalIPv6 := range []string{
		"",
		"not-an-ip",
		"203.0.113.7",
		"[2409:8a00::1]",
		"[2409:8a00::1]:443",
		"2409:8a00::1%eth0",
		"::ffff:203.0.113.7",
		"::",
		"::1",
		"fc00::1",
		"fe80::1",
		"2409:8a00::1, 2409:8a00::2",
	} {
		t.Run(originalIPv6, func(t *testing.T) {
			req := requestWithLocalAddress(
				httptest.NewRequest(http.MethodGet, "http://app.example/", nil),
				"127.0.0.1",
				ManagedCloudflareIngressPort,
			)
			req.Header.Set("CF-Connecting-IP", pseudoIPv4)
			req.Header.Set("CF-Connecting-IPv6", originalIPv6)

			if got := resolveClientIP(req, models.AuthConfig{}, true); got != pseudoIPv4 {
				t.Fatalf("resolveClientIP() = %q, want fail-closed pseudo IPv4 %q", got, pseudoIPv4)
			}
		})
	}
}

func TestResolveClientIPManagedCloudflareIngressRejectsDuplicateClientHeaders(t *testing.T) {
	t.Run("connecting IP", func(t *testing.T) {
		req := requestWithLocalAddress(
			httptest.NewRequest(http.MethodGet, "http://app.example/", nil),
			"127.0.0.1",
			ManagedCloudflareIngressPort,
		)
		req.Header.Add("CF-Connecting-IP", "251.169.165.161")
		req.Header.Add("CF-Connecting-IP", "253.21.85.116")
		req.Header.Set("CF-Connecting-IPv6", "2409:8a00:1234:5678::25")

		if got := resolveClientIP(req, models.AuthConfig{}, true); got != "" {
			t.Fatalf("resolveClientIP() = %q, want fail-closed empty IP", got)
		}
	})

	t.Run("connecting IPv6", func(t *testing.T) {
		req := requestWithLocalAddress(
			httptest.NewRequest(http.MethodGet, "http://app.example/", nil),
			"127.0.0.1",
			ManagedCloudflareIngressPort,
		)
		req.Header.Set("CF-Connecting-IP", "251.169.165.161")
		req.Header.Add("CF-Connecting-IPv6", "2409:8a00:1234:5678::25")
		req.Header.Add("CF-Connecting-IPv6", "2409:8a00:1234:5678::26")

		if got, want := resolveClientIP(req, models.AuthConfig{}, true), "251.169.165.161"; got != want {
			t.Fatalf("resolveClientIP() = %q, want fail-closed pseudo IPv4 %q", got, want)
		}
	})
}

func TestResolveClientIPManagedCloudflareIngressIgnoresUnexpectedIPv6ForRegularClientIP(t *testing.T) {
	req := requestWithLocalAddress(
		httptest.NewRequest(http.MethodGet, "http://app.example/", nil),
		"127.0.0.1",
		ManagedCloudflareIngressPort,
	)
	req.Header.Set("CF-Connecting-IP", "198.51.100.25")
	req.Header.Set("CF-Connecting-IPv6", "2409:8a00:1234:5678::25")

	if got, want := resolveClientIP(req, models.AuthConfig{}, true), "198.51.100.25"; got != want {
		t.Fatalf("resolveClientIP() = %q, want regular client IP %q", got, want)
	}
}

func TestManagedCloudflarePseudoIPv4UsesOriginalIPv6ForVisibility(t *testing.T) {
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{
		Enabled: true,
		CIDRs:   []string{"2409:8a00::/32"},
	}); err != nil {
		t.Fatalf("SetGatewayVisibility() returned error: %v", err)
	}
	if err := handler.SetHostRules([]models.HostRule{{
		Host:   "music.example.test",
		Target: upstream.URL,
	}}); err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}

	req := requestWithLocalAddress(
		httptest.NewRequest(http.MethodGet, "http://music.example.test/api/player/play", nil),
		"127.0.0.1",
		ManagedCloudflareIngressPort,
	)
	req.RemoteAddr = "127.0.0.1:49952"
	req.Header.Set("CF-Connecting-IP", "253.21.85.116")
	req.Header.Set("CF-Connecting-IPv6", "2409:8a00:1234:5678::25")
	req.Header.Set("X-Forwarded-For", "253.21.85.116")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusNoContent, recorder.Body.String())
	}
	if upstreamHits != 1 {
		t.Fatalf("upstream hits = %d, want 1", upstreamHits)
	}
}

func TestResolveClientIPManagedCloudflareIngressFailsClosed(t *testing.T) {
	for _, connectingIP := range []string{
		"",
		"not-an-ip",
		"198.51.100.25:443",
		"[2001:db8::25]",
		"[2001:db8::25]:443",
		"2001:db8::25%eth0",
		"::ffff:198.51.100.25",
		"198.51.100.25, 192.168.1.100",
	} {
		t.Run(connectingIP, func(t *testing.T) {
			req := requestWithLocalAddress(
				httptest.NewRequest(http.MethodGet, "http://app.example/", nil),
				"127.0.0.1",
				ManagedCloudflareIngressPort,
			)
			req.RemoteAddr = "127.0.0.1:49952"
			req.Header.Set("CF-Connecting-IP", connectingIP)
			req.Header.Set("X-Forwarded-For", "192.168.1.100")
			req.Header.Set("X-Real-IP", "192.168.1.100")

			if got := resolveClientIP(req, models.AuthConfig{}, true); got != "" {
				t.Fatalf("resolveClientIP() = %q, want fail-closed empty IP", got)
			}
		})
	}
}

func TestResolveClientIPOrdinaryIngressPreservesExistingProxyProtocolBehavior(t *testing.T) {
	req := requestWithLocalAddress(
		httptest.NewRequest(http.MethodGet, "http://app.example/", nil),
		"127.0.0.1",
		7999,
	)
	req.RemoteAddr = "127.0.0.1:49952"
	req.Header.Set("CF-Connecting-IP", "198.51.100.25")
	req.Header.Set("X-Forwarded-For", "192.168.1.100")

	if got, want := resolveClientIP(req, models.AuthConfig{}, true), "192.168.1.100"; got != want {
		t.Fatalf("resolveClientIP() = %q, want existing non-Cloudflare behavior %q", got, want)
	}
}

func TestResolveClientIPOrdinaryIngressDoesNotTrustCloudflareConnectingIPv6(t *testing.T) {
	req := requestWithLocalAddress(
		httptest.NewRequest(http.MethodGet, "http://app.example/", nil),
		"127.0.0.1",
		7999,
	)
	req.RemoteAddr = "127.0.0.1:49952"
	req.Header.Set("CF-Connecting-IP", "251.169.165.161")
	req.Header.Set("CF-Connecting-IPv6", "2409:8a00:1234:5678::25")
	req.Header.Set("X-Forwarded-For", "251.169.165.161")

	if got, want := resolveClientIP(req, models.AuthConfig{}, true), "251.169.165.161"; got != want {
		t.Fatalf("resolveClientIP() = %q, want existing non-Cloudflare behavior %q", got, want)
	}
}
