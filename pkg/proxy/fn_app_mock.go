package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/sync/singleflight"
)

const (
	fnAppMetadataCacheTTL          = 24 * time.Hour
	fnAppMetadataFetchTimeout      = 4 * time.Second
	fnAppPasswordErrorCode         = 84934746
	fnAppMetadataCachePrefix       = "go_reauth_proxy:fn_app_upstream_meta:v1:"
	fnAppRelayCookieValue          = "mode=relay"
	fnAppDefaultUserAgent          = "Dart/3.5 (dart:io), Flutter/3.5.4"
	fnAppUnauthorizedWSIdleTimeout = 3 * time.Second
	fnAppUnauthorizedWSReadLimit   = 8 << 10
	fnAppUnauthorizedWSCloseWait   = 500 * time.Millisecond
	fnAppPasswordFailureDrainDelay = 20 * time.Millisecond
)

type fnAppUpstreamMetadata struct {
	Version   int    `json:"version"`
	MachineID string `json:"machine_id"`
	SI        string `json:"si"`
	PublicKey string `json:"public_key"`
	CachedAt  string `json:"cached_at"`
}

type fnAppMetadataCache interface {
	Get(ctx context.Context, key string) (*fnAppUpstreamMetadata, error)
	Set(ctx context.Context, key string, value fnAppUpstreamMetadata, ttl time.Duration) error
}

type fnAppMetadataCacheEntry struct {
	value     fnAppUpstreamMetadata
	expiresAt time.Time
}

type memoryFNAppMetadataCache struct {
	mu     sync.RWMutex
	values map[string]fnAppMetadataCacheEntry
}

func newMemoryFNAppMetadataCache() *memoryFNAppMetadataCache {
	return &memoryFNAppMetadataCache{
		values: map[string]fnAppMetadataCacheEntry{},
	}
}

func (c *memoryFNAppMetadataCache) Get(_ context.Context, key string) (*fnAppUpstreamMetadata, error) {
	if c == nil {
		return nil, nil
	}

	c.mu.RLock()
	entry, ok := c.values[key]
	c.mu.RUnlock()
	if !ok {
		return nil, nil
	}

	if !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt) {
		c.mu.Lock()
		delete(c.values, key)
		c.mu.Unlock()
		return nil, nil
	}

	value := entry.value
	return &value, nil
}

func (c *memoryFNAppMetadataCache) Set(_ context.Context, key string, value fnAppUpstreamMetadata, ttl time.Duration) error {
	if c == nil {
		return nil
	}

	entry := fnAppMetadataCacheEntry{value: value}
	if ttl > 0 {
		entry.expiresAt = time.Now().Add(ttl)
	}

	c.mu.Lock()
	c.values[key] = entry
	c.mu.Unlock()
	return nil
}

type fnAppMockService struct {
	cache                     fnAppMetadataCache
	fetchTimeout              time.Duration
	unauthorizedWSIdleTimeout time.Duration
	unauthorizedWSReadLimit   int64
	unauthorizedWSCloseWait   time.Duration
	upgrader                  websocket.Upgrader
	wsDialer                  websocket.Dialer
	fetchGroup                singleflight.Group
}

func newFNAppMockServiceFromEnv() *fnAppMockService {
	return &fnAppMockService{
		cache:                     newMemoryFNAppMetadataCache(),
		fetchTimeout:              fnAppMetadataFetchTimeout,
		unauthorizedWSIdleTimeout: fnAppUnauthorizedWSIdleTimeout,
		unauthorizedWSReadLimit:   fnAppUnauthorizedWSReadLimit,
		unauthorizedWSCloseWait:   fnAppUnauthorizedWSCloseWait,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
			EnableCompression: false,
		},
		wsDialer: websocket.Dialer{
			Proxy:             http.ProxyFromEnvironment,
			HandshakeTimeout:  fnAppMetadataFetchTimeout,
			EnableCompression: false,
		},
	}
}

func isFNAppRequest(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}

	cleanPath := path.Clean(r.URL.Path)
	if cleanPath != "/trimcon" && cleanPath != "/websocket" {
		return false
	}

	userAgent := strings.TrimSpace(r.UserAgent())
	if containsFoldASCIIString(userAgent, "com.trim.app") ||
		containsFoldASCIIString(userAgent, "com.trim.media") ||
		containsFoldASCIIString(userAgent, "dart:io") ||
		containsFoldASCIIString(userAgent, "flutter/") {
		return true
	}

	return containsFoldASCIIString(r.Header.Get("Cookie"), fnAppRelayCookieValue)
}

func isFNAppWebSocketRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") &&
		containsFoldASCIIString(r.Header.Get("Connection"), "upgrade")
}

func (s *fnAppMockService) handleUnauthorizedRequest(w http.ResponseWriter, r *http.Request, upstreamTarget string) (bool, error) {
	if s == nil || !isFNAppRequest(r) {
		return false, nil
	}

	switch path.Clean(r.URL.Path) {
	case "/trimcon":
		s.primeMetadata(upstreamTarget, r.UserAgent())
		sendFNAppTrimconResponse(w)
		return true, nil
	case "/websocket":
		if !isFNAppWebSocketRequest(r) {
			http.Error(w, "websocket upgrade required", http.StatusBadRequest)
			return true, nil
		}
		return true, s.serveUnauthorizedWebsocket(w, r, upstreamTarget)
	default:
		return false, nil
	}
}

func sendFNAppTrimconResponse(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Allow-Methods", "*")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Request-Private-Network", "true")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Content-Length", "0")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Server", "nginx")
	w.WriteHeader(http.StatusOK)
}

func (s *fnAppMockService) serveUnauthorizedWebsocket(w http.ResponseWriter, r *http.Request, upstreamTarget string) error {
	metadata, err := s.getUpstreamMetadata(r.Context(), upstreamTarget, r.UserAgent())
	if err != nil {
		http.Error(w, "FN App metadata unavailable", http.StatusBadGateway)
		return err
	}

	headers := http.Header{}
	headers.Set("Server", "nginx")
	conn, err := s.upgrader.Upgrade(w, r, headers)
	if err != nil {
		return err
	}
	defer conn.Close()
	monitorTrace := deepMonitorFromRequest(r)
	if monitorTrace != nil {
		monitorTrace.recordCustomWebSocketOpen(r, upstreamTarget, r.Header, headers, conn.Subprotocol())
	}

	if readLimit := s.resolvedUnauthorizedWSReadLimit(); readLimit > 0 {
		conn.SetReadLimit(readLimit)
	}

	if err := s.resetUnauthorizedWSReadDeadline(conn); err != nil {
		return err
	}

	request, rawRequest, err := readFNAppMockRequest(conn)
	if err != nil {
		return s.handleUnauthorizedWSReadError(conn, "", err, monitorTrace)
	}
	if monitorTrace != nil {
		monitorTrace.recordWebSocketMessage("client_to_gateway", websocket.TextMessage, rawRequest)
	}
	if request.Req != "util.crypto.getRSAPub" {
		return s.failUnauthorizedWebsocket(conn, resolveFNAppFailureReqID(request.ReqID, ""), monitorTrace)
	}

	response := struct {
		PublicKey string `json:"pub"`
		SI        string `json:"si"`
		MachineID string `json:"machineId"`
		Result    string `json:"result"`
		ReqID     string `json:"reqid"`
	}{
		PublicKey: metadata.PublicKey,
		SI:        metadata.SI,
		MachineID: metadata.MachineID,
		Result:    "succ",
		ReqID:     request.ReqID,
	}
	responsePayload, err := json.Marshal(response)
	if err != nil {
		return err
	}
	if monitorTrace != nil {
		monitorTrace.recordWebSocketMessage("gateway_to_client", websocket.TextMessage, responsePayload)
	}
	if err := conn.WriteMessage(websocket.TextMessage, responsePayload); err != nil {
		return err
	}

	if err := s.resetUnauthorizedWSReadDeadline(conn); err != nil {
		return err
	}

	request, rawRequest, err = readFNAppMockRequest(conn)
	if err != nil {
		return s.handleUnauthorizedWSReadError(conn, response.ReqID, err, monitorTrace)
	}
	if monitorTrace != nil {
		monitorTrace.recordWebSocketMessage("client_to_gateway", websocket.TextMessage, rawRequest)
	}

	return s.failUnauthorizedWebsocket(conn, resolveFNAppFailureReqID(request.ReqID, response.ReqID), monitorTrace)
}

var errFNAppUnexpectedWSMessageType = errors.New("unexpected FN App websocket message type")

type fnAppMockRequest struct {
	Req   string `json:"req"`
	ReqID string `json:"reqid"`
}

func readFNAppMockRequest(conn *websocket.Conn) (fnAppMockRequest, []byte, error) {
	messageType, payload, err := conn.ReadMessage()
	if err != nil {
		return fnAppMockRequest{}, nil, err
	}
	if messageType != websocket.TextMessage {
		return fnAppMockRequest{}, payload, errFNAppUnexpectedWSMessageType
	}

	var request fnAppMockRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		return fnAppMockRequest{}, payload, err
	}
	return request, payload, nil
}

func (s *fnAppMockService) resolvedUnauthorizedWSIdleTimeout() time.Duration {
	if s != nil && s.unauthorizedWSIdleTimeout > 0 {
		return s.unauthorizedWSIdleTimeout
	}
	return fnAppUnauthorizedWSIdleTimeout
}

func (s *fnAppMockService) resolvedUnauthorizedWSReadLimit() int64 {
	if s != nil && s.unauthorizedWSReadLimit > 0 {
		return s.unauthorizedWSReadLimit
	}
	return fnAppUnauthorizedWSReadLimit
}

func (s *fnAppMockService) resolvedUnauthorizedWSCloseWait() time.Duration {
	if s != nil && s.unauthorizedWSCloseWait > 0 {
		return s.unauthorizedWSCloseWait
	}
	return fnAppUnauthorizedWSCloseWait
}

func (s *fnAppMockService) resetUnauthorizedWSReadDeadline(conn *websocket.Conn) error {
	return conn.SetReadDeadline(time.Now().Add(s.resolvedUnauthorizedWSIdleTimeout()))
}

func (s *fnAppMockService) handleUnauthorizedWSReadError(conn *websocket.Conn, previousReqID string, err error, monitorTrace *deepMonitorRequest) error {
	if err == nil || isFNAppConnectionTermination(err) {
		return nil
	}
	return s.failUnauthorizedWebsocket(conn, nextReqID(previousReqID), monitorTrace)
}

func (s *fnAppMockService) failUnauthorizedWebsocket(conn *websocket.Conn, reqID string, monitorTrace *deepMonitorRequest) error {
	if err := sendFNAppPasswordFailure(conn, reqID, monitorTrace); err != nil {
		return err
	}

	deadline := time.Now().Add(s.resolvedUnauthorizedWSCloseWait())
	if err := conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), deadline); err != nil && !isFNAppConnectionTermination(err) {
		return err
	}
	return nil
}

func resolveFNAppFailureReqID(requestReqID string, previousReqID string) string {
	if strings.TrimSpace(requestReqID) != "" {
		return requestReqID
	}
	return nextReqID(previousReqID)
}

func isFNAppConnectionTermination(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return true
	}

	var closeErr *websocket.CloseError
	if errors.As(err, &closeErr) {
		return true
	}

	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func sendFNAppPasswordFailure(conn *websocket.Conn, reqID string, monitorTrace *deepMonitorRequest) error {
	response := struct {
		Errno  int    `json:"errno"`
		Result string `json:"result"`
		ReqID  string `json:"reqid"`
	}{
		Errno:  fnAppPasswordErrorCode,
		Result: "fail",
		ReqID:  reqID,
	}

	payload, err := json.Marshal(response)
	if err != nil {
		return err
	}
	if monitorTrace != nil {
		monitorTrace.recordWebSocketMessage("gateway_to_client", websocket.TextMessage, payload)
	}
	if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
		return err
	}

	time.Sleep(fnAppPasswordFailureDrainDelay)
	return nil
}

func (s *fnAppMockService) primeMetadata(upstreamTarget string, userAgent string) {
	if strings.TrimSpace(upstreamTarget) == "" {
		return
	}

	go func() {
		if _, err := s.getUpstreamMetadata(context.Background(), upstreamTarget, userAgent); err != nil {
			log.Printf("Failed to prime FN App metadata cache: %v", err)
		}
	}()
}

func (s *fnAppMockService) getUpstreamMetadata(ctx context.Context, upstreamTarget string, userAgent string) (fnAppUpstreamMetadata, error) {
	baseURL, err := normalizeFNAppUpstreamBaseURL(upstreamTarget)
	if err != nil {
		return fnAppUpstreamMetadata{}, err
	}

	cacheKey := buildFNAppMetadataCacheKey(baseURL)
	if cached, err := s.cache.Get(ctx, cacheKey); err == nil && cached != nil {
		return *cached, nil
	} else if err != nil {
		log.Printf("Failed to read FN App metadata cache: %v", err)
	}

	result, err, _ := s.fetchGroup.Do(cacheKey, func() (any, error) {
		if cached, err := s.cache.Get(ctx, cacheKey); err == nil && cached != nil {
			return *cached, nil
		}

		fresh, err := s.fetchUpstreamMetadata(ctx, baseURL, userAgent)
		if err != nil {
			return fnAppUpstreamMetadata{}, err
		}

		if err := s.cache.Set(ctx, cacheKey, fresh, fnAppMetadataCacheTTL); err != nil {
			log.Printf("Failed to write FN App metadata cache: %v", err)
		}
		return fresh, nil
	})
	if err != nil {
		return fnAppUpstreamMetadata{}, err
	}

	metadata, ok := result.(fnAppUpstreamMetadata)
	if !ok {
		return fnAppUpstreamMetadata{}, fmt.Errorf("unexpected FN App metadata fetch result type")
	}
	return metadata, nil
}

func (s *fnAppMockService) fetchUpstreamMetadata(ctx context.Context, baseURL *url.URL, userAgent string) (fnAppUpstreamMetadata, error) {
	if baseURL == nil {
		return fnAppUpstreamMetadata{}, fmt.Errorf("missing upstream base URL")
	}

	fetchCtx := ctx
	if fetchCtx == nil {
		fetchCtx = context.Background()
	}
	var cancel context.CancelFunc
	fetchCtx, cancel = context.WithTimeout(fetchCtx, s.fetchTimeout)
	defer cancel()

	wsURL := buildFNAppWebSocketURL(baseURL)
	requestHeaders := http.Header{}
	requestHeaders.Set("Cookie", fnAppRelayCookieValue)
	requestHeaders.Set("User-Agent", buildFNAppUserAgent(userAgent))

	conn, resp, err := s.wsDialer.DialContext(fetchCtx, wsURL.String(), requestHeaders)
	if resp != nil && resp.Body != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if err != nil {
		return fnAppUpstreamMetadata{}, err
	}
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(s.fetchTimeout)); err != nil {
		return fnAppUpstreamMetadata{}, err
	}

	reqID := strconv.FormatInt(time.Now().UnixNano(), 16)
	requestBody := map[string]any{
		"getMachineId": true,
		"reqid":        reqID,
		"req":          "util.crypto.getRSAPub",
	}
	if err := conn.WriteJSON(requestBody); err != nil {
		return fnAppUpstreamMetadata{}, err
	}

	messageType, payload, err := conn.ReadMessage()
	if err != nil {
		return fnAppUpstreamMetadata{}, err
	}
	if messageType != websocket.TextMessage {
		return fnAppUpstreamMetadata{}, fmt.Errorf("unexpected upstream websocket message type: %d", messageType)
	}

	var response struct {
		PublicKey string `json:"pub"`
		SI        string `json:"si"`
		MachineID string `json:"machineId"`
		Result    string `json:"result"`
		ReqID     string `json:"reqid"`
	}
	if err := json.Unmarshal(payload, &response); err != nil {
		return fnAppUpstreamMetadata{}, err
	}
	if strings.TrimSpace(response.Result) != "succ" {
		return fnAppUpstreamMetadata{}, fmt.Errorf("upstream returned non-success RSA metadata response")
	}
	if strings.TrimSpace(response.PublicKey) == "" ||
		strings.TrimSpace(response.SI) == "" ||
		strings.TrimSpace(response.MachineID) == "" {
		return fnAppUpstreamMetadata{}, fmt.Errorf("upstream returned incomplete FN App metadata")
	}

	return fnAppUpstreamMetadata{
		Version:   1,
		MachineID: response.MachineID,
		SI:        response.SI,
		PublicKey: response.PublicKey,
		CachedAt:  time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}

func buildFNAppUserAgent(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed != "" {
		return trimmed
	}
	return fnAppDefaultUserAgent
}

func normalizeFNAppUpstreamBaseURL(rawTarget string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawTarget))
	if err != nil {
		return nil, err
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("invalid FN App upstream target: missing host")
	}

	switch strings.ToLower(parsed.Scheme) {
	case "ws":
		parsed.Scheme = "http"
	case "wss":
		parsed.Scheme = "https"
	case "http", "https":
	default:
		return nil, fmt.Errorf("unsupported FN App upstream target scheme: %s", parsed.Scheme)
	}

	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed, nil
}

func buildFNAppWebSocketURL(baseURL *url.URL) *url.URL {
	target := *baseURL
	switch target.Scheme {
	case "https":
		target.Scheme = "wss"
	default:
		target.Scheme = "ws"
	}
	target.Path = singleJoiningSlash(baseURL.Path, "/websocket")
	target.RawPath = ""
	target.RawQuery = ""
	target.Fragment = ""
	return &target
}

func buildFNAppMetadataCacheKey(baseURL *url.URL) string {
	sum := sha256.Sum256([]byte(baseURL.String()))
	return fnAppMetadataCachePrefix + hex.EncodeToString(sum[:])
}

func nextReqID(previousReqID string) string {
	if previousReqID == "" {
		return strconv.FormatInt(time.Now().UnixNano(), 10)
	}

	lastHexIdx := len(previousReqID)
	for lastHexIdx > 0 {
		ch := previousReqID[lastHexIdx-1]
		if (ch >= '0' && ch <= '9') ||
			(ch >= 'a' && ch <= 'f') ||
			(ch >= 'A' && ch <= 'F') {
			lastHexIdx--
			continue
		}
		break
	}
	if lastHexIdx == len(previousReqID) {
		return previousReqID
	}

	prefix := previousReqID[:lastHexIdx]
	suffix := previousReqID[lastHexIdx:]
	nextValue, ok := new(bigIntHex).AddOne(suffix)
	if !ok {
		return previousReqID
	}
	return prefix + nextValue
}

type bigIntHex struct{}

func (bigIntHex) AddOne(raw string) (string, bool) {
	value, ok := new(bigInt).Parse(raw)
	if !ok {
		return "", false
	}
	return value.AddOne(len(raw)), true
}

type bigInt struct {
	value []byte
}

func (b *bigInt) Parse(raw string) (*bigInt, bool) {
	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return nil, false
	}
	return &bigInt{value: decoded}, true
}

func (b *bigInt) AddOne(width int) string {
	if len(b.value) == 0 {
		return ""
	}

	updated := append([]byte(nil), b.value...)
	for i := len(updated) - 1; i >= 0; i-- {
		updated[i]++
		if updated[i] != 0 {
			break
		}
	}

	result := hex.EncodeToString(updated)
	if len(result) >= width {
		return result[len(result)-width:]
	}
	return strings.Repeat("0", width-len(result)) + result
}
