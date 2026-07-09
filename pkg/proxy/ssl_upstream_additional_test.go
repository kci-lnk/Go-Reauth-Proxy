package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go-reauth-proxy/pkg/models"
)

func TestNormalizeSSLConfigDropsEmptyCertificates(t *testing.T) {
	cfg, err := normalizeSSLConfig(models.SSLConfig{Certificates: []models.SSLDeployedCertificate{{}, {Cert: " cert ", Key: " key "}}})
	if err != nil {
		t.Fatalf("normalizeSSLConfig() returned error: %v", err)
	}
	if len(cfg.Certificates) != 1 || cfg.Certificates[0].Cert != "cert" || cfg.Certificates[0].Key != "key" {
		t.Fatalf("normalized certificates = %#v", cfg.Certificates)
	}
}

func TestNewProxyTransportEnablesBoundedTLSClientSessionCache(t *testing.T) {
	transport := newProxyTransport()
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.ClientSessionCache == nil {
		t.Fatal("proxy transport does not enable TLS client session reuse")
	}
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("proxy transport changed the configured upstream TLS verification behavior")
	}
	if transport.ResponseHeaderTimeout != 0 {
		t.Fatalf("ResponseHeaderTimeout = %v, want no gateway-level timeout", transport.ResponseHeaderTimeout)
	}
}

func TestNormalizeSSLConfigRejectsPartialCertificate(t *testing.T) {
	if _, err := normalizeSSLConfig(models.SSLConfig{Certificates: []models.SSLDeployedCertificate{{Cert: "cert"}}}); err == nil {
		t.Fatal("normalizeSSLConfig() accepted cert without key")
	}
}

func TestNormalizeSSLConfigRejectsMultipleDefaults(t *testing.T) {
	_, err := normalizeSSLConfig(models.SSLConfig{
		DeploymentMode: models.SSLDeploymentModeMultiSNI,
		Certificates: []models.SSLDeployedCertificate{
			{Cert: "a", Key: "a", IsDefault: true},
			{Cert: "b", Key: "b", IsDefault: true},
		},
	})
	if err == nil {
		t.Fatal("normalizeSSLConfig() accepted multiple defaults")
	}
}

func TestNormalizeSSLConfigSingleActiveRejectsMultipleCertificates(t *testing.T) {
	_, err := normalizeSSLConfig(models.SSLConfig{
		DeploymentMode: models.SSLDeploymentModeSingleActive,
		Certificates: []models.SSLDeployedCertificate{
			{Cert: "a", Key: "a"},
			{Cert: "b", Key: "b"},
		},
	})
	if err == nil {
		t.Fatal("normalizeSSLConfig() accepted multiple single_active certificates")
	}
}

func TestNormalizeSSLConfigMarksFirstCertificateDefault(t *testing.T) {
	cfg, err := normalizeSSLConfig(models.SSLConfig{DeploymentMode: models.SSLDeploymentModeMultiSNI, Certificates: []models.SSLDeployedCertificate{{Cert: "a", Key: "a"}}})
	if err != nil {
		t.Fatalf("normalizeSSLConfig() returned error: %v", err)
	}
	if !cfg.Certificates[0].IsDefault {
		t.Fatalf("first certificate was not marked default: %#v", cfg.Certificates)
	}
}

func TestBuildLegacySSLConfigEmptyInputReturnsEmptyDeployment(t *testing.T) {
	cfg := buildLegacySSLConfig("", "key")
	if len(cfg.Certificates) != 0 || cfg.DeploymentMode != models.SSLDeploymentModeSingleActive {
		t.Fatalf("legacy config = %#v", cfg)
	}
}

func TestValidateLegacySSLPairRejectsMissingCertificate(t *testing.T) {
	if _, _, err := validateLegacySSLPair("", "key"); err == nil {
		t.Fatal("validateLegacySSLPair() accepted key without cert")
	}
}

func TestCopySSLInfoDeepCopiesDomains(t *testing.T) {
	original := models.SSLInfo{Certificates: []models.SSLDeployedCertificateInfo{{Domains: []string{"a.example.test"}}}}
	info := copySSLInfo(original)
	info.Certificates[0].Domains[0] = "b.example.test"
	if original.Certificates[0].Domains[0] != "a.example.test" {
		t.Fatal("copySSLInfo() did not deep-copy domains")
	}
}

func TestLegacySSLPEMFromConfigUsesDefaultCertificate(t *testing.T) {
	cert, key := legacySSLPEMFromConfig(models.SSLConfig{Certificates: []models.SSLDeployedCertificate{
		{Cert: "first", Key: "first-key"},
		{Cert: "second", Key: "second-key", IsDefault: true},
	}})
	if cert != "second" || key != "second-key" {
		t.Fatalf("legacy PEM = %q %q", cert, key)
	}
}

func TestNewSSLRuntimeBundleLoadsExactDomain(t *testing.T) {
	certPEM, keyPEM := makeTestCertificatePEM(t, []string{"app.example.test"}, nil)
	bundle, err := newSSLRuntimeBundle(models.SSLConfig{Certificates: []models.SSLDeployedCertificate{{ID: "app", Cert: certPEM, Key: keyPEM, IsDefault: true}}})
	if err != nil {
		t.Fatalf("newSSLRuntimeBundle() returned error: %v", err)
	}
	if !bundle.hasCertificates() || len(bundle.certificates) != 1 {
		t.Fatalf("bundle = %#v", bundle)
	}
	if bundle.certificateForServerName("APP.EXAMPLE.TEST.") == nil {
		t.Fatal("certificateForServerName() did not match exact domain case-insensitively")
	}
}

func TestNewSSLRuntimeBundleRejectsDuplicateExactDomains(t *testing.T) {
	certPEM, keyPEM := makeTestCertificatePEM(t, []string{"app.example.test"}, nil)
	_, err := newSSLRuntimeBundle(models.SSLConfig{DeploymentMode: models.SSLDeploymentModeMultiSNI, Certificates: []models.SSLDeployedCertificate{
		{Cert: certPEM, Key: keyPEM, IsDefault: true},
		{Cert: certPEM, Key: keyPEM},
	}})
	if err == nil {
		t.Fatal("newSSLRuntimeBundle() accepted duplicate exact domains")
	}
}

func TestWildcardMatchesServerNameRequiresSingleLabel(t *testing.T) {
	if !wildcardMatchesServerName("*.example.test", "app.example.test") {
		t.Fatal("wildcard did not match one label")
	}
	if wildcardMatchesServerName("*.example.test", "deep.app.example.test") {
		t.Fatal("wildcard matched multiple labels")
	}
}

func TestIsSupportedWildcardDomainRejectsMultipleWildcards(t *testing.T) {
	if isSupportedWildcardDomain("*.*.example.test") {
		t.Fatal("isSupportedWildcardDomain() accepted multiple wildcards")
	}
}

func TestExtractCertificateDomainsIncludesIPAddresses(t *testing.T) {
	certPEM, keyPEM := makeTestCertificatePEM(t, []string{"app.example.test"}, []net.IP{net.ParseIP("192.168.1.5")})
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatalf("X509KeyPair() returned error: %v", err)
	}
	domains, err := extractCertificateDomains(&pair)
	if err != nil {
		t.Fatalf("extractCertificateDomains() returned error: %v", err)
	}
	if !stringSliceContains(domains, "app.example.test") || !stringSliceContains(domains, "192.168.1.5") {
		t.Fatalf("domains = %#v", domains)
	}
}

func TestNormalizeTLSServerNameStripsPortAndTrailingDot(t *testing.T) {
	if got := normalizeTLSServerName(" Example.Test:443. "); got != "example.test" {
		t.Fatalf("normalizeTLSServerName() = %q", got)
	}
}

func TestPreferredPrivateIPv4DetectorCachesValue(t *testing.T) {
	var calls atomic.Int32
	detector := newPreferredPrivateIPv4Detector(time.Hour, func() string {
		calls.Add(1)
		return "192.168.1.10"
	})
	if got := detector.get(); got != "" {
		t.Fatalf("cold detector value = %q, want non-blocking empty value", got)
	}
	waitForPrivateIPv4Value(t, detector.get, "192.168.1.10")
	if detector.get() != "192.168.1.10" {
		t.Fatal("detector returned unexpected value")
	}
	if calls.Load() != 1 {
		t.Fatalf("detect calls = %d, want 1", calls.Load())
	}
}

func TestCachedPrivateIPv4ResolverCachesValue(t *testing.T) {
	var calls atomic.Int32
	resolver := newCachedPrivateIPv4Resolver(time.Hour, func(host string) string {
		calls.Add(1)
		return "10.0.0.5"
	})
	if got := resolver.get("HOST.EXAMPLE.TEST."); got != "" {
		t.Fatalf("cold resolver value = %q, want non-blocking empty value", got)
	}
	waitForPrivateIPv4Value(t, func() string { return resolver.get("host.example.test") }, "10.0.0.5")
	if resolver.get("host.example.test") != "10.0.0.5" {
		t.Fatal("resolver returned unexpected value")
	}
	if calls.Load() != 1 {
		t.Fatalf("resolve calls = %d, want 1", calls.Load())
	}
}

func TestCachedPrivateIPv4ResolverRejectsEmptyHostname(t *testing.T) {
	resolver := newCachedPrivateIPv4Resolver(time.Hour, func(string) string {
		t.Fatal("resolver should not be called")
		return ""
	})
	if got := resolver.get(" . "); got != "" {
		t.Fatalf("resolver.get(empty) = %q", got)
	}
}

func TestResolveUpstreamPrivateIPv4HintReturnsPrivateIPAddress(t *testing.T) {
	target, _ := url.Parse("http://192.168.1.20:8080")
	if got := resolveUpstreamPrivateIPv4Hint(target); got != "192.168.1.20" {
		t.Fatalf("hint = %q", got)
	}
}

func TestResolveUpstreamPrivateIPv4HintUsesLoopbackDetector(t *testing.T) {
	oldDetector := privateIPv4Detector
	privateIPv4Detector = newPreferredPrivateIPv4Detector(time.Hour, func() string { return "10.0.0.9" })
	defer func() { privateIPv4Detector = oldDetector }()

	target, _ := url.Parse("http://127.0.0.1:8080")
	waitForPrivateIPv4Value(t, func() string { return resolveUpstreamPrivateIPv4Hint(target) }, "10.0.0.9")
	if got := resolveUpstreamPrivateIPv4Hint(target); got != "10.0.0.9" {
		t.Fatalf("hint = %q", got)
	}
}

func TestResolveUpstreamPrivateIPv4HintUsesHostnameResolver(t *testing.T) {
	oldResolver := hostnamePrivateIPv4Resolver
	resolvedHost := make(chan string, 1)
	hostnamePrivateIPv4Resolver = newCachedPrivateIPv4Resolver(time.Hour, func(host string) string {
		resolvedHost <- host
		return "172.16.1.9"
	})
	defer func() { hostnamePrivateIPv4Resolver = oldResolver }()

	target, _ := url.Parse("http://app.example.test:8080")
	waitForPrivateIPv4Value(t, func() string { return resolveUpstreamPrivateIPv4Hint(target) }, "172.16.1.9")
	if got := resolveUpstreamPrivateIPv4Hint(target); got != "172.16.1.9" {
		t.Fatalf("hint = %q", got)
	}
	if got := <-resolvedHost; got != "app.example.test" {
		t.Fatalf("resolved host = %q", got)
	}
}

func TestPreferredPrivateIPv4DetectorReturnsStaleValueDuringRefresh(t *testing.T) {
	var calls atomic.Int32
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	detector := newPreferredPrivateIPv4Detector(time.Millisecond, func() string {
		if calls.Add(1) == 1 {
			return "10.0.0.1"
		}
		close(refreshStarted)
		<-releaseRefresh
		return "10.0.0.2"
	})

	waitForPrivateIPv4Value(t, detector.get, "10.0.0.1")
	time.Sleep(5 * time.Millisecond)
	result := make(chan string, 1)
	go func() { result <- detector.get() }()
	select {
	case got := <-result:
		if got != "10.0.0.1" {
			t.Fatalf("stale value = %q, want 10.0.0.1", got)
		}
	case <-time.After(100 * time.Millisecond):
		close(releaseRefresh)
		t.Fatal("expired detector cache blocked on refresh")
	}
	select {
	case <-refreshStarted:
	case <-time.After(time.Second):
		close(releaseRefresh)
		t.Fatal("detector refresh did not start")
	}
	detector.ttl = time.Hour
	close(releaseRefresh)
	waitForPrivateIPv4Value(t, detector.get, "10.0.0.2")
}

func TestCachedPrivateIPv4ResolverReturnsStaleValueDuringRefresh(t *testing.T) {
	var calls atomic.Int32
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	resolver := newCachedPrivateIPv4Resolver(time.Millisecond, func(string) string {
		if calls.Add(1) == 1 {
			return "172.16.0.1"
		}
		close(refreshStarted)
		<-releaseRefresh
		return "172.16.0.2"
	})
	get := func() string { return resolver.get("app.example.test") }

	waitForPrivateIPv4Value(t, get, "172.16.0.1")
	time.Sleep(5 * time.Millisecond)
	result := make(chan string, 1)
	go func() { result <- get() }()
	select {
	case got := <-result:
		if got != "172.16.0.1" {
			t.Fatalf("stale value = %q, want 172.16.0.1", got)
		}
	case <-time.After(100 * time.Millisecond):
		close(releaseRefresh)
		t.Fatal("expired hostname cache blocked on refresh")
	}
	select {
	case <-refreshStarted:
	case <-time.After(time.Second):
		close(releaseRefresh)
		t.Fatal("hostname refresh did not start")
	}
	resolver.ttl = time.Hour
	close(releaseRefresh)
	waitForPrivateIPv4Value(t, get, "172.16.0.2")
}

func TestCachedPrivateIPv4ResolverCleansLongExpiredHosts(t *testing.T) {
	resolver := newCachedPrivateIPv4Resolver(10*time.Millisecond, func(string) string { return "" })
	holder := &cachedPrivateIPv4ResolverEntry{}
	holder.value.Store(&cachedPrivateIPv4Entry{
		value:     "172.16.0.1",
		expiresAt: time.Now().Add(-time.Second),
	})
	resolver.entries.Store("old.example.test", holder)
	resolver.cleanupExpiredAsync(time.Now())

	deadline := time.Now().Add(time.Second)
	for {
		if _, ok := resolver.entries.Load("old.example.test"); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("long-expired hostname cache entry was not removed")
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForPrivateIPv4Value(t *testing.T, get func() string, want string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		if got := get(); got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for private IPv4 value %q", want)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestApplyUpstreamPrivateIPv4HintHeaderDeletesStaleHint(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.test", nil)
	req.Header.Set(upstreamPrivateIPv4HeaderName, "10.0.0.1")
	applyUpstreamPrivateIPv4HintHeader(req, nil)
	if got := req.Header.Get(upstreamPrivateIPv4HeaderName); got != "" {
		t.Fatalf("stale hint header = %q", got)
	}
}

func TestShouldSkipPrivateIPv4InterfaceSkipsDocker(t *testing.T) {
	if !shouldSkipPrivateIPv4Interface("docker0") {
		t.Fatal("docker interface was not skipped")
	}
}

func TestShouldSkipPrivateIPv4InterfaceKeepsEthernet(t *testing.T) {
	if shouldSkipPrivateIPv4Interface("en0") {
		t.Fatal("en0 should not be skipped")
	}
}

func TestIsLoopbackOrLocalHostnameAcceptsIPv6Loopback(t *testing.T) {
	if !isLoopbackOrLocalHostname("::1") {
		t.Fatal("::1 was not treated as loopback")
	}
}

func TestIsUsablePrivateIPv4RejectsPublicAddress(t *testing.T) {
	if isUsablePrivateIPv4("8.8.8.8") {
		t.Fatal("public address was treated as usable private IPv4")
	}
}

func TestCopyUserAgentHeaderClearsDefaultUserAgentWhenMissing(t *testing.T) {
	src, _ := http.NewRequest(http.MethodGet, "http://example.test", nil)
	dst, _ := http.NewRequest(http.MethodGet, "http://example.test", nil)
	copyUserAgentHeader(dst, src)
	if values, ok := dst.Header["User-Agent"]; !ok || len(values) != 1 || values[0] != "" {
		t.Fatalf("User-Agent header = %#v", dst.Header["User-Agent"])
	}
}

func makeTestCertificatePEM(t *testing.T, dnsNames []string, ips []net.IP) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() returned error: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: firstTestDNSName(dnsNames)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() returned error: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return string(certPEM), string(keyPEM)
}

func firstTestDNSName(values []string) string {
	if len(values) == 0 {
		return "localhost"
	}
	return strings.TrimPrefix(values[0], "*.")
}

func stringSliceContains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
