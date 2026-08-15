package streamprobe

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestProbeDetectsServerFirstRFBOnExactTarget(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_, _ = conn.Write([]byte("RFB 003.008\n"))
			_ = conn.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := Probe(ctx, "tcp", listener.Addr().String())
	if result.Status != "verified" || result.Profile.ServiceID != "rfb" {
		t.Fatalf("probe result = %#v", result)
	}
	if result.Profile.TargetFingerprint != TargetFingerprint("tcp", listener.Addr().String()) {
		t.Fatal("probe target fingerprint does not bind the exact target")
	}
}

func TestProbeRejectsOversizedBannerEvenWithValidPrefix(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			payload := append([]byte("RFB 003.008\n"), make([]byte, probeMaxResponse)...)
			_, _ = conn.Write(payload)
			_ = conn.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := Probe(ctx, "tcp", listener.Addr().String())
	if result.Status == "verified" {
		t.Fatalf("oversized response was verified: %#v", result)
	}
}

func TestProbeDetectsWebDAVCapability(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(time.Second))
				request := make([]byte, 2048)
				n, _ := conn.Read(request)
				if bytes.HasPrefix(request[:n], []byte("OPTIONS / HTTP/1.1")) {
					_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nDAV: 1, 2\r\nContent-Length: 0\r\n\r\n"))
				}
			}()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := Probe(ctx, "tcp", listener.Addr().String())
	if result.Status != "verified" || result.Profile.ServiceID != "webdav" {
		t.Fatalf("probe result = %#v", result)
	}
	if result.Profile.Metadata["dav"] != "1, 2" {
		t.Fatalf("WebDAV metadata = %#v", result.Profile.Metadata)
	}
}

func TestProbeDetectsWebDAVFromReadOnlyPropfind(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(time.Second))
				request := make([]byte, 2048)
				n, _ := conn.Read(request)
				switch {
				case bytes.HasPrefix(request[:n], []byte("OPTIONS / HTTP/1.1")):
					_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
				case bytes.HasPrefix(request[:n], []byte("PROPFIND / HTTP/1.1")):
					body := `<?xml version="1.0"?><D:multistatus xmlns:D="DAV:"></D:multistatus>`
					_, _ = conn.Write([]byte("HTTP/1.1 207 Multi-Status\r\nContent-Type: application/xml\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\nConnection: close\r\n\r\n" + body))
				}
			}()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := Probe(ctx, "tcp", listener.Addr().String())
	if result.Status != "verified" || result.Profile.ServiceID != "webdav" {
		t.Fatalf("probe result = %#v", result)
	}
	if len(result.Profile.EvidenceCodes) != 1 || result.Profile.EvidenceCodes[0] != "webdav_multistatus" {
		t.Fatalf("WebDAV evidence = %#v", result.Profile.EvidenceCodes)
	}
}

func TestProbeDoesNotGuessWebDAVBehindGenericBasicAuth(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(time.Second))
				request := make([]byte, 2048)
				n, _ := conn.Read(request)
				if bytes.HasPrefix(request[:n], []byte("OPTIONS * HTTP/1.1")) {
					_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
					return
				}
				_, _ = conn.Write([]byte("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Restricted\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			}()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := Probe(ctx, "tcp", listener.Addr().String())
	if result.Status != "unknown" || result.Profile.ServiceID != "http1" {
		t.Fatalf("probe result = %#v", result)
	}
	if result.Profile.Metadata["http_status"] != "200" ||
		result.Profile.Metadata["auth_probe_status"] != "401" ||
		result.Profile.Metadata["auth_scheme"] != "basic" {
		t.Fatalf("HTTP auth metadata = %#v", result.Profile.Metadata)
	}
	if result.Message == "" {
		t.Fatal("authenticated HTTP ambiguity did not explain why manual confirmation is required")
	}
	if len(result.Profile.EvidenceCodes) != 2 || result.Profile.EvidenceCodes[1] != "http_auth_challenge" {
		t.Fatalf("HTTP authentication evidence = %#v", result.Profile.EvidenceCodes)
	}
}

func TestAuthenticatedHTTPAmbiguityKeepsTLSCarrierUnverified(t *testing.T) {
	result := withAuthenticatedHTTPAmbiguity(profileResult("tls", "strong", "tls_handshake", map[string]string{
		"http_status": "401",
		"auth_scheme": "basic",
	}), "401", "basic")
	if result.Status != "unknown" || result.Profile.ServiceID != "tls" {
		t.Fatalf("authenticated TLS result = %#v", result)
	}
}

func TestClassifierVersionTracksWebDAVProbeSemantics(t *testing.T) {
	if ClassifierVersion != "stream-signatures-v3" {
		t.Fatalf("ClassifierVersion = %q", ClassifierVersion)
	}
}

func TestWebDAVCapabilityProbesPrecedeGenericHTTPOnHTTPPorts(t *testing.T) {
	for _, port := range []string{"80", "8080"} {
		probes := tcpActiveProbes(net.JoinHostPort("127.0.0.1", port))
		positions := map[string]int{}
		for index, probe := range probes {
			positions[probe.name] = index
		}
		if positions["webdav_options"] >= positions["http_options"] || positions["webdav_propfind"] >= positions["http_options"] {
			t.Fatalf("port %s probe order = %#v", port, positions)
		}
	}
}

func TestProbeDetectsWebDAVOverTLSCapability(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodOptions {
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writer.Header().Set("DAV", "1, 2")
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := Probe(ctx, "tcp", server.Listener.Addr().String())
	if result.Status != "verified" || result.Profile.ServiceID != "webdav_tls" {
		t.Fatalf("probe result = %#v", result)
	}
	if result.Profile.Metadata["dav"] != "1, 2" {
		t.Fatalf("WebDAV TLS metadata = %#v", result.Profile.Metadata)
	}
}

func TestHTTPProbeHostUsesExactSafeTarget(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   string
	}{
		{name: "dns", target: "files.example.test:8080", want: "files.example.test:8080"},
		{name: "ipv6", target: "[2001:db8::1]:443", want: "[2001:db8::1]:443"},
		{name: "invalid", target: "missing-port", want: "service-probe.invalid"},
		{name: "header injection", target: "files.example.test\r\nX-Probe: injected:80", want: "service-probe.invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := httpProbeHost(test.target); got != test.want {
				t.Fatalf("httpProbeHost(%q) = %q, want %q", test.target, got, test.want)
			}
		})
	}
}

func TestONVIFNVRRoleUsesOnlyStructuredRoleFields(t *testing.T) {
	declared := []byte(`<Envelope><Body><ProbeMatch><Types>tds:NetworkVideoRecorder</Types><Scopes>onvif://www.onvif.org/type/video_encoder</Scopes></ProbeMatch></Body></Envelope>`)
	if metadata := extractMetadata("onvif", declared); metadata["device_type"] != "nvr" {
		t.Fatalf("declared NVR metadata = %#v", metadata)
	}
	unrelated := []byte(`<Envelope><!-- NetworkVideoRecorder /type/nvr --><Body><ProbeMatch><Types>tds:NetworkVideoTransmitter</Types><Scopes>onvif://www.onvif.org/type/video_encoder</Scopes></ProbeMatch></Body></Envelope>`)
	if metadata := extractMetadata("onvif", unrelated); metadata != nil {
		t.Fatalf("unrelated NVR text produced metadata: %#v", metadata)
	}
}

func TestProbeUDPTriesEverySafeProbeBeforeRetries(t *testing.T) {
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, client, readErr := listener.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			response := []byte("not-a-known-protocol")
			if bytes.Contains(buffer[:n], []byte("schemas.xmlsoap.org/ws/2005/04/discovery")) {
				response = []byte(`<d:ProbeMatches xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">ProbeMatches</d:ProbeMatches>`)
			}
			_, _ = listener.WriteToUDP(response, client)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := Probe(ctx, "udp", listener.LocalAddr().String())
	if result.Status != "verified" || result.Profile.ServiceID != "onvif" {
		t.Fatalf("probe result = %#v", result)
	}
}
