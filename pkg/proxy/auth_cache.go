package proxy

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"go-reauth-proxy/pkg/diagnostics"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/response"

	"golang.org/x/sync/singleflight"
)

const (
	authSessionCookieName      = "x-go-reauth-proxy-session-id"
	authShareSessionCookieName = "fn-knock-fnos-share-session"
	authCacheMaxEntries        = 4096
	authCacheHashBufferSize    = 512
	identitySourceCookiePrefix = "cookie:"
	identitySourceAuthPrefix   = "auth:"
	identitySourceIPPrefix     = "ip:"
)

type authStateCache struct {
	mu             sync.RWMutex
	entries        map[string]authCacheEntry
	keysByIdentity map[string]map[string]struct{}
	order          *list.List
	orderByKey     map[string]*list.Element
	group          singleflight.Group
}

type authRouteIdentityContextKey struct{}

func withAuthRouteIdentity(r *http.Request, identity string) *http.Request {
	if r == nil {
		return nil
	}
	return r.WithContext(context.WithValue(
		r.Context(),
		authRouteIdentityContextKey{},
		strings.TrimSpace(identity),
	))
}

func authRouteIdentityFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	identity, _ := r.Context().Value(authRouteIdentityContextKey{}).(string)
	return strings.TrimSpace(identity)
}

type preflightStateCache struct {
	mu             sync.RWMutex
	entries        map[string]preflightCacheEntry
	keysByIdentity map[string]map[string]struct{}
	order          *list.List
	orderByKey     map[string]*list.Element
	group          singleflight.Group
}

type authCacheLookup struct {
	cacheKey     string
	hostCacheKey string
	identityKey  string
}

type preflightCacheLookup struct {
	cacheKey    string
	identityKey string
}

type authCacheEntry struct {
	result           authCheckResult
	setCookies       []string
	redirectLocation string
	abortConnection  bool
	expiresAt        time.Time
	identityKey      string
}

type preflightCacheEntry struct {
	decision    preflightDecision
	expiresAt   time.Time
	identityKey string
}

type preflightCacheExecution struct {
	entry    *preflightCacheEntry
	decision preflightDecision
}

type authSetCookieMutation struct {
	name   string
	value  string
	maxAge int
}

type authSetCookieMutations struct {
	inline [2]authSetCookieMutation
	extra  []authSetCookieMutation
	count  int
}

func newAuthStateCache() authStateCache {
	return authStateCache{
		entries:        make(map[string]authCacheEntry),
		keysByIdentity: make(map[string]map[string]struct{}),
		order:          list.New(),
		orderByKey:     make(map[string]*list.Element),
	}
}

func newPreflightStateCache() preflightStateCache {
	return preflightStateCache{
		entries:        make(map[string]preflightCacheEntry),
		keysByIdentity: make(map[string]map[string]struct{}),
		order:          list.New(),
		orderByKey:     make(map[string]*list.Element),
	}
}

func authCacheEnabled(authConfig models.AuthConfig) bool {
	return authConfig.AuthCacheTTL > 0 || authConfig.AuthCacheFailTTL > 0
}

func authCacheTTL(authConfig models.AuthConfig, result authCheckResult) time.Duration {
	if result.allowed && result.cacheMaxAgeSeconds > 0 {
		if authConfig.AuthCacheTTL <= 0 {
			return 0
		}
		seconds := result.cacheMaxAgeSeconds
		if seconds > 60 {
			seconds = 60
		}
		if int32(authConfig.AuthCacheTTL) < seconds {
			seconds = int32(authConfig.AuthCacheTTL)
		}
		return time.Duration(seconds) * time.Second
	}
	switch {
	case result.allowed && result.authenticated && authConfig.AuthCacheTTL > 0:
		return time.Duration(authConfig.AuthCacheTTL) * time.Second
	case !result.allowed && result.decision != "error" && result.decision != "rate_limited" && result.decision != "fn_app_prompt" && authConfig.AuthCacheFailTTL > 0:
		return time.Duration(authConfig.AuthCacheFailTTL) * time.Second
	default:
		return 0
	}
}

func shouldBypassFNAppUnauthorizedAuthCache(r *http.Request, result authCheckResult) bool {
	return isFNAppRequest(r) && (!result.allowed || !result.authenticated)
}

func shouldBypassFNAppNegativePreflightCache(r *http.Request, decision preflightDecision) bool {
	return isFNAppRequest(r) && (decision.deny || strings.TrimSpace(decision.redirectLocation) != "")
}

func preflightCacheTTL(authConfig models.AuthConfig) time.Duration {
	successTTL := authConfig.AuthCacheTTL
	failTTL := authConfig.AuthCacheFailTTL

	switch {
	case successTTL > 0 && failTTL > 0:
		if successTTL < failTTL {
			return time.Duration(successTTL) * time.Second
		}
		return time.Duration(failTTL) * time.Second
	case successTTL > 0:
		return time.Duration(successTTL) * time.Second
	case failTTL > 0:
		return time.Duration(failTTL) * time.Second
	default:
		return 0
	}
}

func requestIdentitySource(r *http.Request, clientIP string) string {
	if cookieID := canonicalCookieIdentity(r); cookieID != "" {
		return identitySourceCookiePrefix + cookieID
	}
	if auth := strings.TrimSpace(r.Header.Get("Authorization")); auth != "" {
		return identitySourceAuthPrefix + auth
	}
	clientIP = strings.TrimSpace(clientIP)
	if clientIP != "" {
		return identitySourceIPPrefix + clientIP
	}
	return ""
}

func requestIdentityKey(r *http.Request, clientIP string) string {
	identityKey, _, ok := requestIdentityForCache(r, clientIP)
	if !ok {
		return ""
	}
	return identityKey
}

func authCacheClientIPDimension(identitySource string, clientIP string) string {
	identitySource = strings.TrimSpace(identitySource)
	if !(strings.HasPrefix(identitySource, identitySourceCookiePrefix) || strings.HasPrefix(identitySource, identitySourceAuthPrefix)) {
		return ""
	}
	return strings.TrimSpace(clientIP)
}

func requestIdentityForCache(r *http.Request, clientIP string) (identityKey string, clientIPDimension string, ok bool) {
	if cookieKey, ok := canonicalCookieIdentityKey(r); ok {
		return augmentAuthCacheIdentity(cookieKey, r), strings.TrimSpace(clientIP), true
	}
	if auth := strings.TrimSpace(r.Header.Get("Authorization")); auth != "" {
		return augmentAuthCacheIdentity(activeIdentityKeyFromParts(identitySourceAuthPrefix, auth), r), strings.TrimSpace(clientIP), true
	}
	if clientIP = strings.TrimSpace(clientIP); clientIP != "" {
		return augmentAuthCacheIdentity(activeIdentityKeyFromParts(identitySourceIPPrefix, clientIP), r), "", true
	}
	return "", "", false
}

func augmentAuthCacheIdentity(identityKey string, r *http.Request) string {
	if identityKey == "" || r == nil {
		return identityKey
	}
	compactToken := strings.TrimSpace(r.Header.Get("AccessToken"))
	hyphenatedToken := strings.TrimSpace(r.Header.Get("Access-Token"))
	userAgent := strings.TrimSpace(r.UserAgent())
	if compactToken == "" && hyphenatedToken == "" && userAgent == "" {
		return identityKey
	}

	totalLen := len(identityKey) + len(userAgent) + len(compactToken) + len(hyphenatedToken) + 32
	if totalLen <= authCacheHashBufferSize {
		var stack [authCacheHashBufferSize]byte
		buf := stack[:0]
		buf = appendCacheKeyField(buf, identityKey)
		buf = appendCacheKeyField(buf, userAgent)
		buf = appendCacheKeyField(buf, compactToken)
		buf = appendCacheKeyField(buf, hyphenatedToken)
		return sha256HexBytes(buf)
	}
	buf := make([]byte, 0, totalLen)
	buf = appendCacheKeyField(buf, identityKey)
	buf = appendCacheKeyField(buf, userAgent)
	buf = appendCacheKeyField(buf, compactToken)
	buf = appendCacheKeyField(buf, hyphenatedToken)
	return sha256HexBytes(buf)
}

func buildAuthCacheLookup(r *http.Request, clientIP string, accessMode string) (authCacheLookup, bool) {
	identityKey, clientIPDimension, ok := requestIdentityForCache(r, clientIP)
	if !ok {
		return authCacheLookup{}, false
	}

	host := requestHostForRouting(r)
	// Include the server-generated policy version in every cache dimension.
	// This makes a policy rotation (including disabling or deleting a host)
	// invalidate a previously successful temporary grant immediately instead
	// of waiting for the 60-second bridge cache cap.
	if version := advancedAuthPolicyVersionFromRequest(r); version != "" {
		host += "\x00advanced-auth:" + version
	}
	if routeIdentity := authRouteIdentityFromRequest(r); routeIdentity != "" {
		host += "\x00route:" + routeIdentity
	}

	cacheKey := authCacheLookupKey(
		identityKey,
		clientIPDimension,
		strings.TrimSpace(strings.ToLower(accessMode)),
		strings.TrimSpace(strings.ToLower(requestScheme(r))),
		strings.TrimSpace(strings.ToUpper(r.Method)),
		host,
		r.URL,
	)

	return authCacheLookup{
		cacheKey: cacheKey,
		hostCacheKey: authCacheHostLookupKey(
			identityKey,
			clientIPDimension,
			strings.TrimSpace(strings.ToLower(accessMode)),
			strings.TrimSpace(strings.ToLower(requestScheme(r))),
			host,
		),
		identityKey: identityKey,
	}, true
}

func buildPreflightCacheLookup(r *http.Request, clientIP string, accessMode string, isMatch bool) (preflightCacheLookup, bool) {
	identityKey, clientIPDimension, ok := requestIdentityForCache(r, clientIP)
	if !ok {
		return preflightCacheLookup{}, false
	}

	host := requestHostForRouting(r)
	if version := advancedAuthPolicyVersionFromRequest(r); version != "" {
		host += "\x00advanced-auth:" + version
	}
	if routeIdentity := authRouteIdentityFromRequest(r); routeIdentity != "" {
		host += "\x00route:" + routeIdentity
	}

	cacheKey := preflightCacheLookupKey(
		identityKey,
		clientIPDimension,
		strings.TrimSpace(strings.ToLower(accessMode)),
		strings.TrimSpace(strings.ToLower(requestScheme(r))),
		host,
		boolCacheField(isMatch),
		r.URL,
	)

	return preflightCacheLookup{
		cacheKey:    cacheKey,
		identityKey: identityKey,
	}, true
}

func authCacheLookupKey(identityKey, clientIPDimension, accessMode, scheme, method, host string, requestURL *url.URL) string {
	var stack [authCacheHashBufferSize]byte
	buf := stack[:0]
	buf = appendCacheKeyField(buf, identityKey)
	buf = appendCacheKeyField(buf, clientIPDimension)
	buf = appendCacheKeyField(buf, accessMode)
	buf = appendCacheKeyField(buf, scheme)
	buf = appendCacheKeyField(buf, method)
	buf = appendCacheKeyField(buf, host)
	buf = appendCacheKeyRequestURIField(buf, requestURL)
	return sha256HexBytes(buf)
}

func authCacheHostLookupKey(identityKey, clientIPDimension, accessMode, scheme, host string) string {
	var stack [authCacheHashBufferSize]byte
	buf := stack[:0]
	buf = appendCacheKeyField(buf, "host")
	buf = appendCacheKeyField(buf, identityKey)
	buf = appendCacheKeyField(buf, clientIPDimension)
	buf = appendCacheKeyField(buf, accessMode)
	buf = appendCacheKeyField(buf, scheme)
	buf = appendCacheKeyField(buf, host)
	return sha256HexBytes(buf)
}

func preflightCacheLookupKey(identityKey, clientIPDimension, accessMode, scheme, host, isMatch string, requestURL *url.URL) string {
	var stack [authCacheHashBufferSize]byte
	buf := stack[:0]
	buf = appendCacheKeyField(buf, identityKey)
	buf = appendCacheKeyField(buf, clientIPDimension)
	buf = appendCacheKeyField(buf, accessMode)
	buf = appendCacheKeyField(buf, scheme)
	buf = appendCacheKeyField(buf, host)
	buf = appendCacheKeyField(buf, isMatch)
	buf = appendCacheKeyRequestURIField(buf, requestURL)
	return sha256HexBytes(buf)
}

func appendCacheKeyField(buf []byte, field string) []byte {
	if len(buf) > 0 {
		buf = append(buf, '\n')
	}
	return append(buf, field...)
}

func appendCacheKeyRequestURIField(buf []byte, requestURL *url.URL) []byte {
	if len(buf) > 0 {
		buf = append(buf, '\n')
	}
	return appendURLRequestURI(buf, requestURL)
}

func appendURLRequestURI(buf []byte, requestURL *url.URL) []byte {
	result := requestURL.Opaque
	if result == "" {
		result = requestURL.EscapedPath()
		if result == "" {
			result = "/"
		}
	} else if strings.HasPrefix(result, "//") {
		buf = append(buf, requestURL.Scheme...)
		buf = append(buf, ':')
	}
	buf = append(buf, result...)
	if requestURL.ForceQuery || requestURL.RawQuery != "" {
		buf = append(buf, '?')
		buf = append(buf, requestURL.RawQuery...)
	}
	return buf
}

func boolCacheField(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func activeIdentityKeyFromParts(prefix string, value string) string {
	totalLen := len(prefix) + len(value)
	if totalLen <= authCacheHashBufferSize {
		var stack [authCacheHashBufferSize]byte
		buf := stack[:0]
		buf = append(buf, prefix...)
		buf = append(buf, value...)
		return sha256HexBytes(buf)
	}

	buf := make([]byte, 0, totalLen)
	buf = append(buf, prefix...)
	buf = append(buf, value...)
	return sha256HexBytes(buf)
}

func sha256HexString(value string) string {
	if len(value) <= authCacheHashBufferSize {
		var stack [authCacheHashBufferSize]byte
		buf := stack[:0]
		buf = append(buf, value...)
		return sha256HexBytes(buf)
	}
	return sha256HexBytes([]byte(value))
}

func sha256HexBytes(value []byte) string {
	sum := sha256.Sum256(value)
	var encoded [sha256.Size * 2]byte
	hex.Encode(encoded[:], sum[:])
	return string(encoded[:])
}

func copySetCookieHeaders(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}

func (h *Handler) authCacheGet(cacheKey string, now time.Time) (authCacheEntry, bool) {
	cache := &h.authCache

	cache.mu.RLock()
	entry, ok := cache.entries[cacheKey]
	cache.mu.RUnlock()
	if !ok {
		diagnostics.RecordAuthCacheMiss()
		return authCacheEntry{}, false
	}
	if !entry.expiresAt.After(now) {
		cache.mu.Lock()
		if current, exists := cache.entries[cacheKey]; exists && !current.expiresAt.After(now) {
			cache.deleteEntryLocked(cacheKey)
		}
		cache.mu.Unlock()
		diagnostics.RecordAuthCacheMiss()
		return authCacheEntry{}, false
	}
	diagnostics.RecordAuthCacheHit()
	return entry, true
}

func (h *Handler) preflightCacheGet(cacheKey string, now time.Time) (preflightCacheEntry, bool) {
	cache := &h.preflightCache

	cache.mu.RLock()
	entry, ok := cache.entries[cacheKey]
	cache.mu.RUnlock()
	if !ok {
		diagnostics.RecordAuthCacheMiss()
		return preflightCacheEntry{}, false
	}
	if !entry.expiresAt.After(now) {
		cache.mu.Lock()
		if current, exists := cache.entries[cacheKey]; exists && !current.expiresAt.After(now) {
			cache.deleteEntryLocked(cacheKey)
		}
		cache.mu.Unlock()
		diagnostics.RecordAuthCacheMiss()
		return preflightCacheEntry{}, false
	}
	diagnostics.RecordAuthCacheHit()
	return entry, true
}

func (h *Handler) authCacheStore(cacheKey string, entry authCacheEntry, _ time.Time) {
	cache := &h.authCache

	cache.mu.Lock()
	cache.deleteEntryLocked(cacheKey)
	cache.entries[cacheKey] = entry
	cache.orderByKey[cacheKey] = cache.order.PushBack(cacheKey)
	if entry.identityKey != "" {
		keys := cache.keysByIdentity[entry.identityKey]
		if keys == nil {
			keys = make(map[string]struct{})
			cache.keysByIdentity[entry.identityKey] = keys
		}
		keys[cacheKey] = struct{}{}
	}
	cache.enforceMaxEntriesLocked(authCacheMaxEntries)
	cache.mu.Unlock()
}

func (h *Handler) preflightCacheStore(cacheKey string, entry preflightCacheEntry, _ time.Time) {
	cache := &h.preflightCache

	cache.mu.Lock()
	cache.deleteEntryLocked(cacheKey)
	cache.entries[cacheKey] = entry
	cache.orderByKey[cacheKey] = cache.order.PushBack(cacheKey)
	if entry.identityKey != "" {
		keys := cache.keysByIdentity[entry.identityKey]
		if keys == nil {
			keys = make(map[string]struct{})
			cache.keysByIdentity[entry.identityKey] = keys
		}
		keys[cacheKey] = struct{}{}
	}
	cache.enforceMaxEntriesLocked(authCacheMaxEntries)
	cache.mu.Unlock()
}

func (h *Handler) authCacheInvalidateByIdentityKeys(identityKeys ...string) {
	authCache := &h.authCache
	preflightCache := &h.preflightCache

	authCache.mu.Lock()
	for _, identityKey := range identityKeys {
		if identityKey == "" {
			continue
		}
		keys := authCache.keysByIdentity[identityKey]
		for cacheKey := range keys {
			authCache.deleteEntryLocked(cacheKey)
		}
	}
	authCache.mu.Unlock()

	preflightCache.mu.Lock()
	for _, identityKey := range identityKeys {
		if identityKey == "" {
			continue
		}
		keys := preflightCache.keysByIdentity[identityKey]
		for cacheKey := range keys {
			preflightCache.deleteEntryLocked(cacheKey)
		}
	}
	preflightCache.mu.Unlock()
}

func (h *Handler) clearAuthCache() {
	authCache := &h.authCache
	preflightCache := &h.preflightCache

	authCache.mu.Lock()
	authCache.entries = make(map[string]authCacheEntry)
	authCache.keysByIdentity = make(map[string]map[string]struct{})
	authCache.order = list.New()
	authCache.orderByKey = make(map[string]*list.Element)
	authCache.mu.Unlock()

	preflightCache.mu.Lock()
	preflightCache.entries = make(map[string]preflightCacheEntry)
	preflightCache.keysByIdentity = make(map[string]map[string]struct{})
	preflightCache.order = list.New()
	preflightCache.orderByKey = make(map[string]*list.Element)
	preflightCache.mu.Unlock()
}

func (c *authStateCache) deleteEntryLocked(cacheKey string) {
	entry, ok := c.entries[cacheKey]
	if !ok {
		return
	}
	delete(c.entries, cacheKey)
	if element := c.orderByKey[cacheKey]; element != nil {
		c.order.Remove(element)
		delete(c.orderByKey, cacheKey)
	}
	if entry.identityKey == "" {
		return
	}
	keys := c.keysByIdentity[entry.identityKey]
	delete(keys, cacheKey)
	if len(keys) == 0 {
		delete(c.keysByIdentity, entry.identityKey)
	}
}

func (c *authStateCache) enforceMaxEntriesLocked(limit int) {
	if limit <= 0 {
		return
	}
	for len(c.entries) > limit {
		oldest := c.order.Front()
		if oldest == nil {
			return
		}
		c.deleteEntryLocked(oldest.Value.(string))
	}
}

func (c *preflightStateCache) deleteEntryLocked(cacheKey string) {
	entry, ok := c.entries[cacheKey]
	if !ok {
		return
	}
	delete(c.entries, cacheKey)
	if element := c.orderByKey[cacheKey]; element != nil {
		c.order.Remove(element)
		delete(c.orderByKey, cacheKey)
	}
	if entry.identityKey == "" {
		return
	}
	keys := c.keysByIdentity[entry.identityKey]
	delete(keys, cacheKey)
	if len(keys) == 0 {
		delete(c.keysByIdentity, entry.identityKey)
	}
}

func (c *preflightStateCache) enforceMaxEntriesLocked(limit int) {
	if limit <= 0 {
		return
	}
	for len(c.entries) > limit {
		oldest := c.order.Front()
		if oldest == nil {
			return
		}
		c.deleteEntryLocked(oldest.Value.(string))
	}
}

func requestCookieMap(r *http.Request) map[string]string {
	if r == nil {
		return nil
	}

	headers := r.Header.Values("Cookie")
	if len(headers) == 0 || !cookieHeaderValuesWithinDefaultLimit(headers) {
		return nil
	}

	var values map[string]string
	for _, header := range headers {
		values = appendRequestCookieMapHeader(values, header)
	}
	if len(values) == 0 {
		return nil
	}
	return values
}

func appendRequestCookieMapHeader(values map[string]string, header string) map[string]string {
	for {
		part, rest, more := strings.Cut(header, ";")
		name, value, ok := parseCanonicalCookiePart(strings.TrimSpace(part))
		if ok && name != proxyPathCookieName {
			if value == "" {
				delete(values, name)
			} else {
				if values == nil {
					values = make(map[string]string, strings.Count(header, ";")+1)
				}
				values[name] = value
			}
		}
		if !more {
			return values
		}
		header = rest
	}
}

func canonicalCookieIdentityFromMap(values map[string]string) string {
	if len(values) == 0 {
		return ""
	}

	var stackNames [canonicalCookieIdentityStackPairs]string
	names := stackNames[:0]
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
	b.Grow(canonicalCookieMapIdentitySize(values, names))
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

func canonicalCookieMapIdentitySize(values map[string]string, names []string) int {
	if len(names) == 0 {
		return 0
	}
	size := len(names) - 1
	for _, name := range names {
		size += len(name) + 1 + len(values[name])
	}
	return size
}

func identityKeyFromState(cookieValues map[string]string, authHeader string, clientIP string) string {
	if cookieID := canonicalCookieIdentityFromMap(cookieValues); cookieID != "" {
		return activeIdentityKeyFromSource("cookie:" + cookieID)
	}
	if auth := strings.TrimSpace(authHeader); auth != "" {
		return activeIdentityKeyFromSource("auth:" + auth)
	}
	if clientIP := strings.TrimSpace(clientIP); clientIP != "" {
		return activeIdentityKeyFromSource("ip:" + clientIP)
	}
	return ""
}

func parseRelevantAuthSetCookies(setCookieHeaders []string) authSetCookieMutations {
	var mutations authSetCookieMutations
	if len(setCookieHeaders) == 0 {
		return mutations
	}

	for _, value := range setCookieHeaders {
		if mutation, ok := parseRelevantAuthSetCookie(value); ok {
			mutations.Append(mutation)
		}
	}
	return mutations
}

func (m *authSetCookieMutations) Append(mutation authSetCookieMutation) {
	if m.count < len(m.inline) {
		m.inline[m.count] = mutation
	} else {
		m.extra = append(m.extra, mutation)
	}
	m.count++
}

func (m authSetCookieMutations) Len() int {
	return m.count
}

func (m authSetCookieMutations) At(index int) authSetCookieMutation {
	if index < len(m.inline) {
		return m.inline[index]
	}
	return m.extra[index-len(m.inline)]
}

func parseRelevantAuthSetCookie(header string) (authSetCookieMutation, bool) {
	part, attrs, _ := strings.Cut(strings.Trim(header, " \t"), ";")
	part = strings.Trim(part, " \t")
	name, rawValue, ok := strings.Cut(part, "=")
	if !ok {
		return authSetCookieMutation{}, false
	}
	name = strings.Trim(name, " \t")
	switch name {
	case authSessionCookieName, authShareSessionCookieName:
	default:
		return authSetCookieMutation{}, false
	}
	value, ok := parseCanonicalCookieValue(rawValue)
	if !ok {
		return authSetCookieMutation{}, false
	}

	mutation := authSetCookieMutation{name: name, value: value}
	for attrs != "" {
		attrPart := attrs
		if before, after, more := strings.Cut(attrs, ";"); more {
			attrPart = before
			attrs = after
		} else {
			attrs = ""
		}
		attrPart = strings.Trim(attrPart, " \t")
		if attrPart == "" {
			continue
		}
		attr, rawAttrValue, _ := strings.Cut(attrPart, "=")
		if !equalFoldASCIIString(attr, "max-age") {
			continue
		}
		attrValue, ok := parseSetCookieAttributeValue(rawAttrValue)
		if !ok {
			continue
		}
		mutation.maxAge = parseSetCookieMaxAge(attrValue)
	}
	return mutation, true
}

func parseSetCookieAttributeValue(raw string) (string, bool) {
	for i := 0; i < len(raw); i++ {
		if !validCanonicalCookieValueByte(raw[i]) {
			return "", false
		}
	}
	return raw, true
}

func parseSetCookieMaxAge(value string) int {
	if value == "" {
		return 0
	}
	i := 0
	negative := false
	switch value[0] {
	case '+':
		i = 1
	case '-':
		i = 1
		negative = true
	}
	if i == len(value) {
		return 0
	}
	leadingZeroInvalid := value[0] == '0'
	maxInt := int(^uint(0) >> 1)
	seconds := 0
	for ; i < len(value); i++ {
		c := value[i]
		if c < '0' || c > '9' {
			return 0
		}
		digit := int(c - '0')
		if seconds > (maxInt-digit)/10 {
			return 0
		}
		seconds = seconds*10 + digit
	}
	if leadingZeroInvalid && seconds != 0 {
		return 0
	}
	if negative || seconds <= 0 {
		return -1
	}
	return seconds
}

func applySetCookieMutations(base map[string]string, cookies authSetCookieMutations) map[string]string {
	if cookies.Len() == 0 {
		return base
	}

	updated := make(map[string]string, len(base)+cookies.Len())
	for name, value := range base {
		updated[name] = value
	}

	for i := 0; i < cookies.Len(); i++ {
		cookie := cookies.At(i)
		if cookie.name == "" {
			continue
		}
		if cookie.value == "" || cookie.maxAge < 0 || cookie.maxAge == 0 {
			delete(updated, cookie.name)
			continue
		}
		updated[cookie.name] = cookie.value
	}
	if len(updated) == 0 {
		return nil
	}
	return updated
}

func (h *Handler) authCacheInvalidateForSetCookieMutation(r *http.Request, clientIP string, setCookieHeaders []string) {
	relevantCookies := parseRelevantAuthSetCookies(setCookieHeaders)
	if relevantCookies.Len() == 0 {
		return
	}

	identityKeySet := make(map[string]struct{}, 3)
	if key := requestIdentityKey(r, clientIP); key != "" {
		identityKeySet[key] = struct{}{}
	}
	if key := activeIdentityKeyFromClientIP(clientIP); key != "" {
		identityKeySet[key] = struct{}{}
	}

	nextCookies := applySetCookieMutations(requestCookieMap(r), relevantCookies)
	if key := identityKeyFromState(nextCookies, r.Header.Get("Authorization"), clientIP); key != "" {
		identityKeySet[augmentAuthCacheIdentity(key, r)] = struct{}{}
	}

	identityKeys := make([]string, 0, len(identityKeySet))
	for key := range identityKeySet {
		identityKeys = append(identityKeys, key)
	}
	h.authCacheInvalidateByIdentityKeys(identityKeys...)
}

func (h *Handler) applyAuthCacheEntry(w http.ResponseWriter, r *http.Request, entry authCacheEntry, clientIP string, upstreamTarget string) authCheckResult {
	for _, setCookie := range entry.setCookies {
		w.Header().Add("Set-Cookie", setCookie)
	}
	if len(entry.setCookies) > 0 {
		applyNoStoreCacheHeaders(w.Header())
		h.authCacheInvalidateForSetCookieMutation(r, clientIP, entry.setCookies)
	}

	if entry.result.allowed && entry.result.authenticated {
		h.markLoggedInActive(r, clientIP, time.Now())
		return entry.result
	}

	if entry.result.decision == "access_denied" {
		response.AccessDenied(w, r)
		return entry.result
	}

	if h.fnAppMockService != nil {
		handled, err := h.fnAppMockService.handleUnauthorizedRequest(w, r, upstreamTarget)
		if err != nil {
			log.Printf("Failed to serve unauthorized FN App mock response from auth cache: %v", err)
			return authCheckResult{decision: "error"}
		}
		if handled {
			return authCheckResult{decision: "fn_app_prompt"}
		}
	}

	if entry.abortConnection {
		h.abortConnection(w)
		return entry.result
	}
	if entry.redirectLocation != "" {
		applyNoStoreCacheHeaders(w.Header())
		http.Redirect(w, r, entry.redirectLocation, http.StatusFound)
		return entry.result
	}
	return entry.result
}
