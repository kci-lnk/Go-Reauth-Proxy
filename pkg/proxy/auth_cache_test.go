package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

var (
	benchmarkAuthCacheLookupSink      authCacheLookup
	benchmarkPreflightCacheLookupSink preflightCacheLookup
	benchmarkCookieIdentitySink       string
	benchmarkBoolSink                 bool
	benchmarkCookieMapSink            map[string]string
	benchmarkSetCookieMutationsSink   authSetCookieMutations
)

func TestCanonicalCookieIdentitySkipsProxyPathAndSorts(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/path", nil)
	req.AddCookie(&http.Cookie{Name: "b", Value: "3"})
	req.AddCookie(&http.Cookie{Name: proxyPathCookieName, Value: "/app"})
	req.AddCookie(&http.Cookie{Name: "", Value: "ignored"})
	req.AddCookie(&http.Cookie{Name: "empty", Value: ""})
	req.AddCookie(&http.Cookie{Name: "a", Value: "1"})
	req.AddCookie(&http.Cookie{Name: "b", Value: "2"})

	if got, want := canonicalCookieIdentity(req), "a=1;b=2;b=3"; got != want {
		t.Fatalf("canonicalCookieIdentity() = %q, want %q", got, want)
	}
}

func TestCanonicalCookieIdentitySingleCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/path", nil)
	req.AddCookie(&http.Cookie{Name: proxyPathCookieName, Value: "/app"})
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "session-a"})

	if got, want := canonicalCookieIdentity(req), authSessionCookieName+"=session-a"; got != want {
		t.Fatalf("canonicalCookieIdentity() = %q, want %q", got, want)
	}
}

func TestCanonicalCookieIdentityMatchesRequestCookiesParsing(t *testing.T) {
	tests := []struct {
		name          string
		cookieHeaders []string
	}{
		{
			name:          "multiple cookie headers",
			cookieHeaders: []string{"b=3; " + proxyPathCookieName + "=/app", "a=1; b=2; empty="},
		},
		{
			name:          "quoted value",
			cookieHeaders: []string{`b=ok; a="two words"`},
		},
		{
			name:          "invalid parts",
			cookieHeaders: []string{`bad name=x; good=ok; weird="unterminated; slash=a\b; quote=a"b; tokenonly`},
		},
		{
			name:          "trimmed name keeps value spacing",
			cookieHeaders: []string{" name = value ; a=1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://app.example.com/path", nil)
			for _, value := range tt.cookieHeaders {
				req.Header.Add("Cookie", value)
			}
			if got, want := canonicalCookieIdentity(req), legacyCanonicalCookieIdentity(req); got != want {
				t.Fatalf("canonicalCookieIdentity() = %q, want legacy %q", got, want)
			}
		})
	}
}

func TestCanonicalCookieIdentityHonorsDefaultCookieLimit(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/path", nil)
	req.Header.Set("Cookie", strings.Repeat("a=1;", defaultCookieMaxNum)+"b=2")

	if got := canonicalCookieIdentity(req); got != "" {
		t.Fatalf("canonicalCookieIdentity() = %q, want empty over default cookie limit", got)
	}
}

func TestCanonicalCookieIdentityKeyMatchesCanonicalSourceHash(t *testing.T) {
	tests := []struct {
		name          string
		cookieHeaders []string
	}{
		{
			name:          "single cookie",
			cookieHeaders: []string{authSessionCookieName + "=session-a; " + proxyPathCookieName + "=/app"},
		},
		{
			name:          "sorted cookies",
			cookieHeaders: []string{"b=3; a=1; b=2"},
		},
		{
			name:          "quoted cookie",
			cookieHeaders: []string{`b=ok; a="two words"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://app.example.com/path", nil)
			for _, value := range tt.cookieHeaders {
				req.Header.Add("Cookie", value)
			}
			got, ok := canonicalCookieIdentityKey(req)
			if !ok {
				t.Fatal("canonicalCookieIdentityKey() was not buildable")
			}
			want := activeIdentityKeyFromSource(identitySourceCookiePrefix + canonicalCookieIdentity(req))
			if got != want {
				t.Fatalf("canonicalCookieIdentityKey() = %q, want %q", got, want)
			}
		})
	}
}

func TestAuthCacheLookupSeparatesCookieIdentityByClientIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/path?q=1", nil)
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "session-a"})

	first, ok := buildAuthCacheLookup(req, "198.51.100.10", "login_first")
	if !ok {
		t.Fatal("first auth cache lookup was not buildable")
	}
	second, ok := buildAuthCacheLookup(req, "198.51.100.11", "login_first")
	if !ok {
		t.Fatal("second auth cache lookup was not buildable")
	}
	if first.identityKey != second.identityKey {
		t.Fatalf("identity keys differ for the same cookie: %q != %q", first.identityKey, second.identityKey)
	}
	if first.cacheKey == second.cacheKey {
		t.Fatal("auth cache keys should differ when the same cookie is seen from different client IPs")
	}

	firstPreflight, ok := buildPreflightCacheLookup(req, "198.51.100.10", "login_first", true)
	if !ok {
		t.Fatal("first preflight cache lookup was not buildable")
	}
	secondPreflight, ok := buildPreflightCacheLookup(req, "198.51.100.11", "login_first", true)
	if !ok {
		t.Fatal("second preflight cache lookup was not buildable")
	}
	if firstPreflight.identityKey != secondPreflight.identityKey {
		t.Fatalf("preflight identity keys differ for the same cookie: %q != %q", firstPreflight.identityKey, secondPreflight.identityKey)
	}
	if firstPreflight.cacheKey == secondPreflight.cacheKey {
		t.Fatal("preflight cache keys should differ when the same cookie is seen from different client IPs")
	}
}

func TestAuthCacheLookupKeysMatchCanonicalHashFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://app.example.com/path?q=1", nil)
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "session-a"})
	clientIP := "198.51.100.10"
	accessMode := " login_FIRST "

	authLookup, ok := buildAuthCacheLookup(req, clientIP, accessMode)
	if !ok {
		t.Fatal("auth cache lookup was not buildable")
	}
	identitySource := requestIdentitySource(req, clientIP)
	identityKey := legacySHA256HexString(identitySource)
	authRaw := strings.Join([]string{
		identityKey,
		strings.TrimSpace(clientIP),
		strings.TrimSpace(strings.ToLower(accessMode)),
		strings.TrimSpace(strings.ToLower(requestScheme(req))),
		strings.TrimSpace(strings.ToUpper(req.Method)),
		normalizeRequestHost(req.Host),
		req.URL.RequestURI(),
	}, "\n")
	if got, want := authLookup.identityKey, identityKey; got != want {
		t.Fatalf("auth lookup identityKey = %q, want %q", got, want)
	}
	if got, want := authLookup.cacheKey, legacySHA256HexString(authRaw); got != want {
		t.Fatalf("auth lookup cacheKey = %q, want %q", got, want)
	}

	preflightLookup, ok := buildPreflightCacheLookup(req, clientIP, accessMode, true)
	if !ok {
		t.Fatal("preflight cache lookup was not buildable")
	}
	preflightRaw := strings.Join([]string{
		identityKey,
		strings.TrimSpace(clientIP),
		strings.TrimSpace(strings.ToLower(accessMode)),
		strings.TrimSpace(strings.ToLower(requestScheme(req))),
		normalizeRequestHost(req.Host),
		"true",
		req.URL.RequestURI(),
	}, "\n")
	if got, want := preflightLookup.identityKey, identityKey; got != want {
		t.Fatalf("preflight lookup identityKey = %q, want %q", got, want)
	}
	if got, want := preflightLookup.cacheKey, legacySHA256HexString(preflightRaw); got != want {
		t.Fatalf("preflight lookup cacheKey = %q, want %q", got, want)
	}
}

func TestAppendURLRequestURIMatchesURLRequestURI(t *testing.T) {
	tests := []*url.URL{
		mustParseURLForTest("https://app.example.com/path?q=1"),
		mustParseURLForTest("https://app.example.com/path"),
		mustParseURLForTest("https://app.example.com/a%20b?q=two%20words"),
		{Path: "/path", ForceQuery: true},
		{Scheme: "http", Opaque: "//app.example.com/path", RawQuery: "q=1"},
		{Opaque: "opaque/path", RawQuery: "q=1"},
		{},
	}

	for _, u := range tests {
		got := string(appendURLRequestURI(nil, u))
		if want := u.RequestURI(); got != want {
			t.Fatalf("appendURLRequestURI(%#v) = %q, want %q", u, got, want)
		}
	}
}

func TestAuthCacheLookupSeparatesAuthorizationIdentityByClientIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/path", nil)
	req.Header.Set("Authorization", "Bearer token-a")

	first, ok := buildAuthCacheLookup(req, "2001:db8::10", "login_first")
	if !ok {
		t.Fatal("first auth cache lookup was not buildable")
	}
	second, ok := buildAuthCacheLookup(req, "2001:db8::11", "login_first")
	if !ok {
		t.Fatal("second auth cache lookup was not buildable")
	}
	if first.identityKey != second.identityKey {
		t.Fatalf("identity keys differ for the same auth header: %q != %q", first.identityKey, second.identityKey)
	}
	if first.cacheKey == second.cacheKey {
		t.Fatal("auth cache keys should differ when the same auth header is seen from different client IPs")
	}
}

func TestAuthCacheInvalidationClearsAllClientIPVariantsForIdentity(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/path", nil)
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "session-a"})

	first, ok := buildAuthCacheLookup(req, "198.51.100.10", "login_first")
	if !ok {
		t.Fatal("first auth cache lookup was not buildable")
	}
	second, ok := buildAuthCacheLookup(req, "198.51.100.11", "login_first")
	if !ok {
		t.Fatal("second auth cache lookup was not buildable")
	}
	firstPreflight, ok := buildPreflightCacheLookup(req, "198.51.100.10", "login_first", true)
	if !ok {
		t.Fatal("first preflight cache lookup was not buildable")
	}
	secondPreflight, ok := buildPreflightCacheLookup(req, "198.51.100.11", "login_first", true)
	if !ok {
		t.Fatal("second preflight cache lookup was not buildable")
	}

	handler := &Handler{
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	now := time.Now()
	handler.authCacheStore(first.cacheKey, authCacheEntry{
		result:      authCheckResult{allowed: true, authenticated: true},
		expiresAt:   now.Add(time.Minute),
		identityKey: first.identityKey,
	}, now)
	handler.authCacheStore(second.cacheKey, authCacheEntry{
		result:      authCheckResult{allowed: true, authenticated: true},
		expiresAt:   now.Add(time.Minute),
		identityKey: second.identityKey,
	}, now)
	handler.preflightCacheStore(firstPreflight.cacheKey, preflightCacheEntry{
		decision:    preflightDecision{},
		expiresAt:   now.Add(time.Minute),
		identityKey: firstPreflight.identityKey,
	}, now)
	handler.preflightCacheStore(secondPreflight.cacheKey, preflightCacheEntry{
		decision:    preflightDecision{},
		expiresAt:   now.Add(time.Minute),
		identityKey: secondPreflight.identityKey,
	}, now)

	handler.authCacheInvalidateByIdentityKeys(first.identityKey)

	if _, ok := handler.authCacheGet(first.cacheKey, now); ok {
		t.Fatal("first auth cache entry was not invalidated")
	}
	if _, ok := handler.authCacheGet(second.cacheKey, now); ok {
		t.Fatal("second auth cache entry was not invalidated")
	}
	if _, ok := handler.preflightCacheGet(firstPreflight.cacheKey, now); ok {
		t.Fatal("first preflight cache entry was not invalidated")
	}
	if _, ok := handler.preflightCacheGet(secondPreflight.cacheKey, now); ok {
		t.Fatal("second preflight cache entry was not invalidated")
	}
}

func TestAuthCacheStoreEnforcesMaxEntriesAndIdentityIndex(t *testing.T) {
	handler := &Handler{authCache: newAuthStateCache()}
	now := time.Now()

	for i := 0; i <= authCacheMaxEntries; i++ {
		suffix := strconv.Itoa(i)
		handler.authCacheStore("key-"+suffix, authCacheEntry{
			result:      authCheckResult{allowed: true, authenticated: true},
			expiresAt:   now.Add(time.Duration(i+1) * time.Second),
			identityKey: "identity-" + suffix,
		}, now)
	}

	if got := len(handler.authCache.entries); got != authCacheMaxEntries {
		t.Fatalf("auth cache entries = %d, want %d", got, authCacheMaxEntries)
	}
	if _, ok := handler.authCache.entries["key-0"]; ok {
		t.Fatal("oldest auth cache entry was not evicted")
	}
	if _, ok := handler.authCache.keysByIdentity["identity-0"]; ok {
		t.Fatal("oldest auth cache identity index was not removed")
	}
	if _, ok := handler.authCache.entries["key-"+strconv.Itoa(authCacheMaxEntries)]; !ok {
		t.Fatal("newest auth cache entry was evicted unexpectedly")
	}
}

func TestPreflightCacheStoreEnforcesMaxEntriesAndIdentityIndex(t *testing.T) {
	handler := &Handler{preflightCache: newPreflightStateCache()}
	now := time.Now()

	for i := 0; i <= authCacheMaxEntries; i++ {
		suffix := strconv.Itoa(i)
		handler.preflightCacheStore("key-"+suffix, preflightCacheEntry{
			decision:    preflightDecision{},
			expiresAt:   now.Add(time.Duration(i+1) * time.Second),
			identityKey: "identity-" + suffix,
		}, now)
	}

	if got := len(handler.preflightCache.entries); got != authCacheMaxEntries {
		t.Fatalf("preflight cache entries = %d, want %d", got, authCacheMaxEntries)
	}
	if _, ok := handler.preflightCache.entries["key-0"]; ok {
		t.Fatal("oldest preflight cache entry was not evicted")
	}
	if _, ok := handler.preflightCache.keysByIdentity["identity-0"]; ok {
		t.Fatal("oldest preflight cache identity index was not removed")
	}
	if _, ok := handler.preflightCache.entries["key-"+strconv.Itoa(authCacheMaxEntries)]; !ok {
		t.Fatal("newest preflight cache entry was evicted unexpectedly")
	}
}

func TestRequestHasExplicitAuthIdentity(t *testing.T) {
	tests := []struct {
		name          string
		cookieHeaders []string
		authorization string
		want          bool
	}{
		{
			name:          "auth cookie",
			cookieHeaders: []string{authSessionCookieName + "=session-a; theme=dark"},
			want:          true,
		},
		{
			name:          "trimmed auth cookie name with value spacing",
			cookieHeaders: []string{authSessionCookieName + " = session-a"},
			want:          true,
		},
		{
			name:          "share auth cookie",
			cookieHeaders: []string{"theme=dark; " + authShareSessionCookieName + "=share-a"},
			want:          true,
		},
		{
			name:          "empty auth cookie",
			cookieHeaders: []string{authSessionCookieName + "="},
			want:          false,
		},
		{
			name:          "quoted empty auth cookie",
			cookieHeaders: []string{authSessionCookieName + `=""`},
			want:          false,
		},
		{
			name:          "quoted auth cookie",
			cookieHeaders: []string{authSessionCookieName + `="session-a"`},
			want:          true,
		},
		{
			name:          "malformed quoted auth cookie",
			cookieHeaders: []string{authSessionCookieName + `="`},
			want:          false,
		},
		{
			name:          "authorization",
			authorization: "Bearer token-a",
			want:          true,
		},
		{
			name:          "cookie limit falls back to authorization",
			cookieHeaders: []string{strings.Repeat(authSessionCookieName+"=session-a;", defaultCookieMaxNum) + authSessionCookieName + "=session-a"},
			authorization: "Bearer token-a",
			want:          true,
		},
		{
			name:          "cookie limit suppresses cookie identity",
			cookieHeaders: []string{strings.Repeat(authSessionCookieName+"=session-a;", defaultCookieMaxNum) + authSessionCookieName + "=session-a"},
			want:          false,
		},
		{
			name:          "whitespace authorization",
			authorization: "   ",
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://app.example.com/path", nil)
			for _, value := range tt.cookieHeaders {
				req.Header.Add("Cookie", value)
			}
			if tt.authorization != "" {
				req.Header.Set("Authorization", tt.authorization)
			}
			if got := requestHasExplicitAuthIdentity(req); got != tt.want {
				t.Fatalf("requestHasExplicitAuthIdentity() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRequestCookieMapMatchesRequestCookiesParsing(t *testing.T) {
	tests := []struct {
		name          string
		cookieHeaders []string
	}{
		{
			name:          "duplicates and empty delete",
			cookieHeaders: []string{"a=1; b=2; a=; c=3; " + proxyPathCookieName + "=/app"},
		},
		{
			name:          "multiple cookie headers",
			cookieHeaders: []string{"a=1; b=2", "b=3; c=4"},
		},
		{
			name:          "quoted and invalid parts",
			cookieHeaders: []string{`a="two words"; bad name=x; slash=a\b; c=ok`},
		},
		{
			name:          "trimmed name keeps value spacing",
			cookieHeaders: []string{" name = value ; a=1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://app.example.com/path", nil)
			for _, value := range tt.cookieHeaders {
				req.Header.Add("Cookie", value)
			}
			if got, want := requestCookieMap(req), legacyRequestCookieMap(req); !reflect.DeepEqual(got, want) {
				t.Fatalf("requestCookieMap() = %#v, want legacy %#v", got, want)
			}
		})
	}
}

func TestRequestCookieMapHonorsDefaultCookieLimit(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/path", nil)
	req.Header.Set("Cookie", strings.Repeat("a=1;", defaultCookieMaxNum)+"b=2")

	if got := requestCookieMap(req); got != nil {
		t.Fatalf("requestCookieMap() = %#v, want nil over default cookie limit", got)
	}
}

func TestParseRelevantAuthSetCookiesMatchesLegacyFields(t *testing.T) {
	headers := []string{
		authSessionCookieName + "=session-a; Path=/; HttpOnly; Max-Age=3600",
		"theme=dark; Path=/; Max-Age=3600",
		authShareSessionCookieName + `="share-a"; Max-Age=0`,
		authSessionCookieName + "=bad space ; Max-Age=10",
		authSessionCookieName + "=session-b; Max-Age=01",
		authSessionCookieName + "=session-c; Max-Age=+30",
	}

	got := parseRelevantAuthSetCookies(headers)
	want := legacyRelevantAuthSetCookieMutations(headers)
	if got.Len() != want.Len() {
		t.Fatalf("parseRelevantAuthSetCookies() length = %d, want %d", got.Len(), want.Len())
	}
	for i := 0; i < got.Len(); i++ {
		if got.At(i) != want.At(i) {
			t.Fatalf("mutation %d = %#v, want %#v", i, got.At(i), want.At(i))
		}
	}
}

func TestApplySetCookieMutationsMatchesLegacy(t *testing.T) {
	base := map[string]string{
		authSessionCookieName:      "old-session",
		authShareSessionCookieName: "old-share",
		"theme":                    "dark",
	}
	headers := []string{
		authSessionCookieName + "=new-session; Max-Age=3600",
		authShareSessionCookieName + "=deleted; Max-Age=0",
		"theme=light; Max-Age=3600",
	}

	got := applySetCookieMutations(base, parseRelevantAuthSetCookies(headers))
	want := applySetCookieMutationsLegacy(base, legacyRelevantAuthCookies(headers))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("applySetCookieMutations() = %#v, want legacy %#v", got, want)
	}
}

func BenchmarkCanonicalCookieIdentitySingleCookie(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/path", nil)
	req.AddCookie(&http.Cookie{Name: proxyPathCookieName, Value: "/app"})
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "session-a"})

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkCookieIdentitySink = canonicalCookieIdentity(req)
	}
}

func legacySHA256HexString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func mustParseURLForTest(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

func legacyCanonicalCookieIdentity(r *http.Request) string {
	cookies := r.Cookies()
	filtered := make([]*http.Cookie, 0, len(cookies))
	for _, c := range cookies {
		if c == nil || c.Name == proxyPathCookieName || c.Name == "" || c.Value == "" {
			continue
		}
		filtered = append(filtered, c)
	}
	if len(filtered) == 0 {
		return ""
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Name == filtered[j].Name {
			return filtered[i].Value < filtered[j].Value
		}
		return filtered[i].Name < filtered[j].Name
	})
	var b strings.Builder
	for i, c := range filtered {
		if i > 0 {
			b.WriteByte(';')
		}
		b.WriteString(c.Name)
		b.WriteByte('=')
		b.WriteString(c.Value)
	}
	return b.String()
}

func legacyRequestCookieMap(r *http.Request) map[string]string {
	cookies := r.Cookies()
	if len(cookies) == 0 {
		return nil
	}

	values := make(map[string]string, len(cookies))
	for _, cookie := range cookies {
		if cookie == nil || cookie.Name == "" || cookie.Name == proxyPathCookieName {
			continue
		}
		if cookie.Value == "" {
			delete(values, cookie.Name)
			continue
		}
		values[cookie.Name] = cookie.Value
	}
	if len(values) == 0 {
		return nil
	}
	return values
}

func legacyRelevantAuthCookies(setCookieHeaders []string) []*http.Cookie {
	if len(setCookieHeaders) == 0 {
		return nil
	}

	header := http.Header{}
	for _, value := range setCookieHeaders {
		header.Add("Set-Cookie", value)
	}
	resp := &http.Response{Header: header}
	all := resp.Cookies()
	if len(all) == 0 {
		return nil
	}

	relevant := make([]*http.Cookie, 0, len(all))
	for _, cookie := range all {
		if cookie == nil {
			continue
		}
		switch cookie.Name {
		case authSessionCookieName, authShareSessionCookieName:
			relevant = append(relevant, cookie)
		}
	}
	return relevant
}

func legacyRelevantAuthSetCookieMutations(setCookieHeaders []string) authSetCookieMutations {
	var mutations authSetCookieMutations
	for _, cookie := range legacyRelevantAuthCookies(setCookieHeaders) {
		mutations.Append(authSetCookieMutation{
			name:   cookie.Name,
			value:  cookie.Value,
			maxAge: cookie.MaxAge,
		})
	}
	return mutations
}

func applySetCookieMutationsLegacy(base map[string]string, cookies []*http.Cookie) map[string]string {
	if len(cookies) == 0 {
		return base
	}

	updated := make(map[string]string, len(base)+len(cookies))
	for name, value := range base {
		updated[name] = value
	}

	for _, cookie := range cookies {
		if cookie == nil || cookie.Name == "" {
			continue
		}
		if cookie.Value == "" || cookie.MaxAge < 0 || cookie.MaxAge == 0 {
			delete(updated, cookie.Name)
			continue
		}
		updated[cookie.Name] = cookie.Value
	}
	if len(updated) == 0 {
		return nil
	}
	return updated
}

func legacyCanonicalCookieIdentityFromMap(values map[string]string) string {
	if len(values) == 0 {
		return ""
	}

	names := make([]string, 0, len(values))
	for name, value := range values {
		if name == "" || value == "" || name == proxyPathCookieName {
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return ""
	}

	sort.Strings(names)
	var b strings.Builder
	for i, name := range names {
		if i > 0 {
			b.WriteByte(';')
		}
		b.WriteString(name)
		b.WriteByte('=')
		b.WriteString(values[name])
	}
	return b.String()
}

func BenchmarkCanonicalCookieIdentityManyCookies(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/path", nil)
	req.AddCookie(&http.Cookie{Name: "theme", Value: "dark"})
	req.AddCookie(&http.Cookie{Name: proxyPathCookieName, Value: "/app"})
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "session-a"})
	req.AddCookie(&http.Cookie{Name: "locale", Value: "zh-CN"})
	req.AddCookie(&http.Cookie{Name: authShareSessionCookieName, Value: "share-a"})
	req.AddCookie(&http.Cookie{Name: "empty", Value: ""})

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkCookieIdentitySink = canonicalCookieIdentity(req)
	}
}

func BenchmarkBuildAuthCacheLookupCookie(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/app/api?q=1", nil)
	req.AddCookie(&http.Cookie{Name: proxyPathCookieName, Value: "/app"})
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "session-a"})
	req.AddCookie(&http.Cookie{Name: "theme", Value: "dark"})

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		lookup, ok := buildAuthCacheLookup(req, "198.51.100.10", "login_first")
		if !ok {
			b.Fatal("auth cache lookup was not buildable")
		}
		benchmarkAuthCacheLookupSink = lookup
	}
}

func BenchmarkBuildPreflightCacheLookupCookie(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/app/api?q=1", nil)
	req.AddCookie(&http.Cookie{Name: proxyPathCookieName, Value: "/app"})
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "session-a"})
	req.AddCookie(&http.Cookie{Name: "theme", Value: "dark"})

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		lookup, ok := buildPreflightCacheLookup(req, "198.51.100.10", "login_first", true)
		if !ok {
			b.Fatal("preflight cache lookup was not buildable")
		}
		benchmarkPreflightCacheLookupSink = lookup
	}
}

func BenchmarkRequestHasExplicitAuthIdentityCookie(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/path", nil)
	req.AddCookie(&http.Cookie{Name: proxyPathCookieName, Value: "/app"})
	req.AddCookie(&http.Cookie{Name: "theme", Value: "dark"})
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "session-a"})

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkBoolSink = requestHasExplicitAuthIdentity(req)
	}
}

func BenchmarkRequestHasExplicitAuthIdentityAuthorization(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/path", nil)
	req.Header.Set("Authorization", "Bearer token-a")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkBoolSink = requestHasExplicitAuthIdentity(req)
	}
}

func BenchmarkRequestCookieMap(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/path", nil)
	req.AddCookie(&http.Cookie{Name: "theme", Value: "dark"})
	req.AddCookie(&http.Cookie{Name: proxyPathCookieName, Value: "/app"})
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "session-a"})
	req.AddCookie(&http.Cookie{Name: "locale", Value: "zh-CN"})
	req.AddCookie(&http.Cookie{Name: authShareSessionCookieName, Value: "share-a"})
	req.AddCookie(&http.Cookie{Name: "empty", Value: ""})

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkCookieMapSink = requestCookieMap(req)
	}
}

func BenchmarkRequestCookieMapLegacy(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/path", nil)
	req.AddCookie(&http.Cookie{Name: "theme", Value: "dark"})
	req.AddCookie(&http.Cookie{Name: proxyPathCookieName, Value: "/app"})
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "session-a"})
	req.AddCookie(&http.Cookie{Name: "locale", Value: "zh-CN"})
	req.AddCookie(&http.Cookie{Name: authShareSessionCookieName, Value: "share-a"})
	req.AddCookie(&http.Cookie{Name: "empty", Value: ""})

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkCookieMapSink = legacyRequestCookieMap(req)
	}
}

func BenchmarkCanonicalCookieIdentityFromMap(b *testing.B) {
	values := map[string]string{
		"theme":                    "dark",
		authSessionCookieName:      "session-a",
		"locale":                   "zh-CN",
		authShareSessionCookieName: "share-a",
		"empty":                    "",
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkCookieIdentitySink = canonicalCookieIdentityFromMap(values)
	}
}

func BenchmarkCanonicalCookieIdentityFromMapLegacy(b *testing.B) {
	values := map[string]string{
		"theme":                    "dark",
		authSessionCookieName:      "session-a",
		"locale":                   "zh-CN",
		authShareSessionCookieName: "share-a",
		"empty":                    "",
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkCookieIdentitySink = legacyCanonicalCookieIdentityFromMap(values)
	}
}

func BenchmarkParseRelevantAuthSetCookies(b *testing.B) {
	headers := []string{
		authSessionCookieName + "=session-a; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600",
		"theme=dark; Path=/; Max-Age=3600",
		authShareSessionCookieName + "=share-a; Path=/; Max-Age=0",
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkSetCookieMutationsSink = parseRelevantAuthSetCookies(headers)
	}
}

func BenchmarkParseRelevantAuthSetCookiesLegacy(b *testing.B) {
	headers := []string{
		authSessionCookieName + "=session-a; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600",
		"theme=dark; Path=/; Max-Age=3600",
		authShareSessionCookieName + "=share-a; Path=/; Max-Age=0",
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkSetCookieMutationsSink = legacyRelevantAuthSetCookieMutations(headers)
	}
}
