package stream

import (
	"context"
	"errors"
	"fmt"
	"go-reauth-proxy/pkg/diagnostics"
	"go-reauth-proxy/pkg/gatewaylog"
	compiledipset "go-reauth-proxy/pkg/ipset"
	"go-reauth-proxy/pkg/logger"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/proxy"
	"go-reauth-proxy/pkg/rpcbridge"
	"go-reauth-proxy/pkg/streamprobe"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	streamAuthTimeout          = 2 * time.Second
	streamDialTimeout          = 5 * time.Second
	streamAcceptBackoff        = 150 * time.Millisecond
	udpSessionIdleTimeout      = 2 * time.Minute
	udpSessionReaperInterval   = 10 * time.Second
	udpSmallPacketBufferSize   = 2 * 1024
	udpMediumPacketBufferSize  = 8 * 1024
	udp16KPacketBufferSize     = 16 * 1024
	udp32KPacketBufferSize     = 32 * 1024
	udpLargePacketBufferSize   = 64 * 1024
	udpSessionQueuePacketLimit = 32
	udpSessionQueueByteLimit   = 256 * 1024
	udpListenerQueueByteLimit  = 64 * 1024 * 1024
	udpSessionInitLimit        = 128
	udpListenerSessionLimit    = 8192
)

type udpSmallPacketBuffer [udpSmallPacketBufferSize]byte
type udpMediumPacketBuffer [udpMediumPacketBufferSize]byte
type udp16KPacketBuffer [udp16KPacketBufferSize]byte
type udp32KPacketBuffer [udp32KPacketBufferSize]byte
type udpLargePacketBuffer [udpLargePacketBufferSize]byte

var (
	udpSmallPacketBufferPool = sync.Pool{New: func() any {
		return new(udpSmallPacketBuffer)
	}}
	udpMediumPacketBufferPool = sync.Pool{New: func() any {
		return new(udpMediumPacketBuffer)
	}}
	udpLargePacketBufferPool = sync.Pool{New: func() any {
		return new(udpLargePacketBuffer)
	}}
	udp16KPacketBufferPool = sync.Pool{New: func() any { return new(udp16KPacketBuffer) }}
	udp32KPacketBufferPool = sync.Pool{New: func() any { return new(udp32KPacketBuffer) }}
)

type Manager struct {
	mu                     sync.RWMutex
	handler                *proxy.Handler
	listeners              map[streamRuleKey]managedListener
	rules                  map[streamRuleKey]models.StreamRule
	availability           *models.StreamAvailability
	accessPolicies         map[string]models.CompiledIPSet
	compiledAccessPolicies map[string]*compiledipset.Set
	ruleSnapshot           atomic.Pointer[streamRuleSnapshot]
	now                    func() time.Time
	closed                 bool
}

type streamRuleSnapshot struct {
	rules                  map[streamRuleKey]models.StreamRule
	availability           *models.StreamAvailability
	accessPolicies         map[string]models.CompiledIPSet
	compiledAccessPolicies map[string]*compiledipset.Set
}

type streamRuleKey struct {
	Protocol   string
	ListenPort int
}

func (k streamRuleKey) String() string {
	return k.Protocol + "/" + strconv.Itoa(k.ListenPort)
}

func debugStreamKeys(keys []streamRuleKey) []map[string]any {
	out := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		out = append(out, map[string]any{
			"protocol":    logger.SanitizeLogString(key.Protocol),
			"listen_port": logger.SanitizePort(key.ListenPort),
			"key":         logger.SanitizeLogString(key.String()),
		})
	}
	return out
}

func debugStreamRuleSummaries(rules []models.StreamRule) []map[string]any {
	out := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		out = append(out, map[string]any{
			"protocol":    logger.SanitizeLogString(rule.Protocol),
			"listen_port": logger.SanitizePort(rule.ListenPort),
			"target":      logger.SanitizeLogString(rule.Target),
			"use_auth":    rule.UseAuth,
		})
	}
	return out
}

func debugSanitizeStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, logger.SanitizeLogString(value))
	}
	return out
}

type managedListener interface {
	close()
}

type tcpListenerState struct {
	key       streamRuleKey
	listeners []net.Listener
	stop      chan struct{}
	wg        sync.WaitGroup
	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	closing   bool
}

type udpListenerState struct {
	key            streamRuleKey
	packetConns    []net.PacketConn
	stop           chan struct{}
	initSlots      chan struct{}
	wg             sync.WaitGroup
	mu             sync.Mutex
	sessions       map[string]*udpSession
	closing        bool
	queuedBytes    atomic.Int64
	droppedPackets atomic.Uint64
	droppedBytes   atomic.Uint64
	bufferBudget   *udpBufferBudget
	idleTimeout    time.Duration
}

type udpSession struct {
	id           string
	listener     *udpListenerState
	packetConn   net.PacketConn
	clientAddr   net.Addr
	rule         models.StreamRule
	start        time.Time
	ctx          context.Context
	cancel       context.CancelFunc
	done         chan struct{}
	notify       chan struct{}
	closed       atomic.Bool
	lastActivity atomic.Int64
	bytesIn      atomic.Uint64
	bytesOut     atomic.Uint64
	status       atomic.Int64
	initReserved atomic.Bool

	closeOnce   sync.Once
	upstreamMu  sync.Mutex
	upstream    net.Conn
	queueMu     sync.Mutex
	queue       [udpSessionQueuePacketLimit]udpPacket
	queueHead   int
	queueLen    int
	queueBytes  int
	queueClosed bool
	entryMu     sync.Mutex
	entry       gatewaylog.Entry
	meter       *streamTrafficMeter
}

type relayResult struct {
	bytes uint64
	err   error
}

type udpPacket struct {
	payload   []byte
	poolClass int
	pooled    any
	budget    *udpBufferBudget
}

func acquireUDPPacket(size int) udpPacket {
	switch {
	case size <= udpSmallPacketBufferSize:
		buffer := udpSmallPacketBufferPool.Get().(*udpSmallPacketBuffer)
		return udpPacket{payload: buffer[:size], poolClass: udpSmallPacketBufferSize, pooled: buffer}
	case size <= udpMediumPacketBufferSize:
		buffer := udpMediumPacketBufferPool.Get().(*udpMediumPacketBuffer)
		return udpPacket{payload: buffer[:size], poolClass: udpMediumPacketBufferSize, pooled: buffer}
	case size <= udp16KPacketBufferSize:
		buffer := udp16KPacketBufferPool.Get().(*udp16KPacketBuffer)
		return udpPacket{payload: buffer[:size], poolClass: udp16KPacketBufferSize, pooled: buffer}
	case size <= udp32KPacketBufferSize:
		buffer := udp32KPacketBufferPool.Get().(*udp32KPacketBuffer)
		return udpPacket{payload: buffer[:size], poolClass: udp32KPacketBufferSize, pooled: buffer}
	case size <= udpLargePacketBufferSize:
		buffer := udpLargePacketBufferPool.Get().(*udpLargePacketBuffer)
		return udpPacket{payload: buffer[:size], poolClass: udpLargePacketBufferSize, pooled: buffer}
	default:
		return udpPacket{payload: make([]byte, size)}
	}
}

func releaseUDPPacket(packet udpPacket) {
	if packet.budget != nil {
		packet.budget.used.Add(-int64(udpPacketQueueFootprint(packet)))
	}
	if packet.pooled == nil {
		return
	}
	switch packet.poolClass {
	case udpSmallPacketBufferSize:
		udpSmallPacketBufferPool.Put(packet.pooled)
	case udpMediumPacketBufferSize:
		udpMediumPacketBufferPool.Put(packet.pooled)
	case udp16KPacketBufferSize:
		udp16KPacketBufferPool.Put(packet.pooled)
	case udp32KPacketBufferSize:
		udp32KPacketBufferPool.Put(packet.pooled)
	case udpLargePacketBufferSize:
		udpLargePacketBufferPool.Put(packet.pooled)
	}
}

func udpPacketQueueFootprint(packet udpPacket) int {
	if packet.poolClass > 0 {
		return packet.poolClass
	}
	return len(packet.payload)
}

func NewManager(handler *proxy.Handler) *Manager {
	m := &Manager{
		handler:                handler,
		listeners:              make(map[streamRuleKey]managedListener),
		rules:                  make(map[streamRuleKey]models.StreamRule),
		accessPolicies:         make(map[string]models.CompiledIPSet),
		compiledAccessPolicies: make(map[string]*compiledipset.Set),
		now:                    time.Now,
	}
	m.ruleSnapshot.Store(&streamRuleSnapshot{rules: m.rules, accessPolicies: m.accessPolicies, compiledAccessPolicies: m.compiledAccessPolicies})
	return m
}

func (m *Manager) Reconcile(rules []models.StreamRule) error {
	return m.reconcile(rules, nil, false, nil, nil, false)
}

func (m *Manager) ReconcileConfig(
	rules []models.StreamRule,
	availability *models.StreamAvailability,
) error {
	normalizedAvailability, err := models.NormalizeDailyAvailability(availability)
	if err != nil {
		return err
	}
	return m.reconcile(rules, normalizedAvailability, true, nil, nil, false)
}

func (m *Manager) ReconcileConfigBundle(
	rules []models.StreamRule,
	availability *models.StreamAvailability,
	policies map[string]models.CompiledIPSet,
) error {
	normalizedAvailability, err := models.NormalizeDailyAvailability(availability)
	if err != nil {
		return err
	}
	normalizedPolicies, compiledPolicies, err := decodeStreamAccessPolicies(policies)
	if err != nil {
		return err
	}
	return m.reconcile(rules, normalizedAvailability, true, normalizedPolicies, compiledPolicies, true)
}

func (m *Manager) reconcile(
	rules []models.StreamRule,
	availability *models.StreamAvailability,
	replaceAvailability bool,
	accessPolicies map[string]models.CompiledIPSet,
	compiledAccessPolicies map[string]*compiledipset.Set,
	replaceAccessPolicies bool,
) error {
	start := time.Now()
	if event := logger.DebugEvent("stream", "reconcile_start"); event != nil {
		event.Int("requested_rule_count", len(rules)).
			Interface("rules", debugStreamRuleSummaries(rules)).
			Send()
	}
	normalizedRules, err := m.normalizeRules(rules)
	if err != nil {
		if event := logger.DebugEvent("stream", "reconcile_failed"); event != nil {
			event.Str("phase", "normalize").
				Str("error", logger.SanitizeLogString(err.Error())).
				Int64("duration_ms", time.Since(start).Milliseconds()).
				Send()
		}
		return err
	}
	effectiveCompiledPolicies := compiledAccessPolicies
	if !replaceAccessPolicies {
		snapshot := m.ruleSnapshot.Load()
		if snapshot != nil {
			effectiveCompiledPolicies = snapshot.compiledAccessPolicies
		}
	}
	for _, rule := range normalizedRules {
		if !rule.UseAuth || !rule.BypassPolicy.Enabled {
			continue
		}
		for _, group := range rule.BypassPolicy.Groups {
			if len(group.Conditions) == 0 {
				return fmt.Errorf("stream bypass group %q has no conditions", group.ID)
			}
			for _, condition := range group.Conditions {
				if effectiveCompiledPolicies[strings.TrimSpace(condition.PolicyID)] == nil {
					return fmt.Errorf("stream bypass condition %q references a missing compiled IP set", condition.ID)
				}
			}
		}
	}

	nextRules := make(map[streamRuleKey]models.StreamRule, len(normalizedRules))
	nextKeys := make([]streamRuleKey, 0, len(normalizedRules))
	for _, rule := range normalizedRules {
		if rule.Disabled {
			continue
		}
		key := streamRuleKeyFromRule(rule)
		if _, exists := nextRules[key]; exists {
			return fmt.Errorf("duplicate stream rule for %s", key.String())
		}
		nextRules[key] = rule
		nextKeys = append(nextKeys, key)
	}
	slices.SortFunc(nextKeys, compareStreamRuleKeys)

	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		if event := logger.DebugEvent("stream", "reconcile_failed"); event != nil {
			event.Str("phase", "closed").
				Int64("duration_ms", time.Since(start).Milliseconds()).
				Send()
		}
		return fmt.Errorf("stream manager is closed")
	}
	currentKeys := make([]streamRuleKey, 0, len(m.listeners))
	for key := range m.listeners {
		currentKeys = append(currentKeys, key)
	}
	m.mu.RUnlock()
	slices.SortFunc(currentKeys, compareStreamRuleKeys)

	currentSet := make(map[streamRuleKey]struct{}, len(currentKeys))
	for _, key := range currentKeys {
		currentSet[key] = struct{}{}
	}

	toAdd := make([]streamRuleKey, 0)
	for _, key := range nextKeys {
		if _, exists := currentSet[key]; !exists {
			toAdd = append(toAdd, key)
		}
		delete(currentSet, key)
	}

	toRemove := make([]streamRuleKey, 0, len(currentSet))
	for key := range currentSet {
		toRemove = append(toRemove, key)
	}
	slices.SortFunc(toRemove, compareStreamRuleKeys)

	created := make(map[streamRuleKey]managedListener, len(toAdd))
	for _, key := range toAdd {
		state, err := m.newManagedListener(key)
		if err != nil {
			for _, candidate := range created {
				candidate.close()
			}
			if event := logger.DebugEvent("stream", "reconcile_failed"); event != nil {
				event.Str("phase", "listener_create").
					Str("key", logger.SanitizeLogString(key.String())).
					Interface("listen_port", logger.SanitizePort(key.ListenPort)).
					Str("error", logger.SanitizeLogString(err.Error())).
					Int64("duration_ms", time.Since(start).Milliseconds()).
					Send()
			}
			return err
		}
		created[key] = state
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		for _, candidate := range created {
			candidate.close()
		}
		if event := logger.DebugEvent("stream", "reconcile_failed"); event != nil {
			event.Str("phase", "closed_after_create").
				Int64("duration_ms", time.Since(start).Milliseconds()).
				Send()
		}
		return fmt.Errorf("stream manager is closed")
	}

	for key, state := range created {
		m.listeners[key] = state
	}
	m.rules = nextRules
	if replaceAvailability {
		m.availability = models.CopyDailyAvailability(availability)
	}
	if replaceAccessPolicies {
		m.accessPolicies = accessPolicies
		m.compiledAccessPolicies = compiledAccessPolicies
	}
	m.ruleSnapshot.Store(&streamRuleSnapshot{
		rules:                  nextRules,
		availability:           models.CopyDailyAvailability(m.availability),
		accessPolicies:         m.accessPolicies,
		compiledAccessPolicies: m.compiledAccessPolicies,
	})

	removed := make([]managedListener, 0, len(toRemove))
	for _, key := range toRemove {
		if state, exists := m.listeners[key]; exists {
			removed = append(removed, state)
			delete(m.listeners, key)
		}
	}
	m.mu.Unlock()

	for _, state := range removed {
		state.close()
	}
	if event := logger.DebugEvent("stream", "reconcile_end"); event != nil {
		event.Int("normalized_rule_count", len(normalizedRules)).
			Int("added_listener_count", len(toAdd)).
			Int("removed_listener_count", len(toRemove)).
			Interface("added_listeners", debugStreamKeys(toAdd)).
			Interface("removed_listeners", debugStreamKeys(toRemove)).
			Int64("duration_ms", time.Since(start).Milliseconds()).
			Send()
	}

	return nil
}

func (m *Manager) ReconcileBestEffort(rules []models.StreamRule) ([]models.StreamRule, []error) {
	start := time.Now()
	if event := logger.DebugEvent("stream", "reconcile_best_effort_start"); event != nil {
		event.Int("requested_rule_count", len(rules)).
			Interface("rules", debugStreamRuleSummaries(rules)).
			Send()
	}
	startedRules := make([]models.StreamRule, 0, len(rules))
	warnings := make([]error, 0)

	for _, rule := range rules {
		nextRule, err := m.normalizeRule(rule)
		if err != nil {
			key := streamRuleKey{Protocol: fallbackStreamProtocol(rule.Protocol), ListenPort: rule.ListenPort}
			warnings = append(warnings, fmt.Errorf("skipping stream rule %s -> %s: %w", key.String(), strings.TrimSpace(rule.Target), err))
			if event := logger.DebugEvent("stream", "reconcile_best_effort_skip"); event != nil {
				event.Str("key", logger.SanitizeLogString(key.String())).
					Interface("listen_port", logger.SanitizePort(key.ListenPort)).
					Str("target", logger.SanitizeLogString(rule.Target)).
					Str("error", logger.SanitizeLogString(err.Error())).
					Send()
			}
			continue
		}
		if nextRule.Disabled {
			continue
		}

		if err := m.Reconcile(append(startedRules, nextRule)); err != nil {
			warnings = append(warnings, fmt.Errorf("skipping stream rule %s -> %s: %w", streamRuleKeyFromRule(nextRule).String(), nextRule.Target, err))
			if event := logger.DebugEvent("stream", "reconcile_best_effort_skip"); event != nil {
				event.Str("key", logger.SanitizeLogString(streamRuleKeyFromRule(nextRule).String())).
					Interface("listen_port", logger.SanitizePort(nextRule.ListenPort)).
					Str("target", logger.SanitizeLogString(nextRule.Target)).
					Str("error", logger.SanitizeLogString(err.Error())).
					Send()
			}
			continue
		}
		startedRules = append(startedRules, nextRule)
	}

	if event := logger.DebugEvent("stream", "reconcile_best_effort_end"); event != nil {
		event.Int("started_rule_count", len(startedRules)).
			Int("warning_count", len(warnings)).
			Int64("duration_ms", time.Since(start).Milliseconds()).
			Send()
	}
	return startedRules, warnings
}

func (m *Manager) Stop() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true

	states := make([]managedListener, 0, len(m.listeners))
	for key, state := range m.listeners {
		states = append(states, state)
		delete(m.listeners, key)
	}
	m.rules = map[streamRuleKey]models.StreamRule{}
	m.availability = nil
	m.accessPolicies = map[string]models.CompiledIPSet{}
	m.compiledAccessPolicies = map[string]*compiledipset.Set{}
	m.ruleSnapshot.Store(&streamRuleSnapshot{rules: m.rules, accessPolicies: m.accessPolicies, compiledAccessPolicies: m.compiledAccessPolicies})
	m.mu.Unlock()

	for _, state := range states {
		state.close()
	}
	if event := logger.DebugEvent("stream", "manager_stopped"); event != nil {
		event.Int("listener_count", len(states)).Send()
	}
}

func (m *Manager) currentRule(key streamRuleKey) (models.StreamRule, bool) {
	rule, _, ok := m.currentRuleConfig(key)
	return rule, ok
}

func (m *Manager) currentRuleConfig(
	key streamRuleKey,
) (models.StreamRule, *models.StreamAvailability, bool) {
	snapshot := m.ruleSnapshot.Load()
	if snapshot == nil {
		return models.StreamRule{}, nil, false
	}
	rule, ok := snapshot.rules[key]
	return rule, snapshot.availability, ok
}

func (m *Manager) ConfigSnapshot() ([]models.StreamRule, *models.StreamAvailability) {
	rules, availability, _ := m.ConfigSnapshotBundle()
	return rules, availability
}

func (m *Manager) ConfigSnapshotBundle() ([]models.StreamRule, *models.StreamAvailability, map[string]models.CompiledIPSet) {
	snapshot := m.ruleSnapshot.Load()
	if snapshot == nil {
		return nil, nil, nil
	}
	keys := make([]streamRuleKey, 0, len(snapshot.rules))
	for key := range snapshot.rules {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, compareStreamRuleKeys)
	rules := make([]models.StreamRule, 0, len(keys))
	for _, key := range keys {
		rules = append(rules, snapshot.rules[key])
	}
	return rules, models.CopyDailyAvailability(snapshot.availability), copyCompiledPolicies(snapshot.accessPolicies)
}

func (m *Manager) SetAvailability(availability *models.StreamAvailability) error {
	normalized, err := models.NormalizeDailyAvailability(availability)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return fmt.Errorf("stream manager is closed")
	}
	m.availability = models.CopyDailyAvailability(normalized)
	m.ruleSnapshot.Store(&streamRuleSnapshot{
		rules:                  m.rules,
		availability:           models.CopyDailyAvailability(m.availability),
		accessPolicies:         m.accessPolicies,
		compiledAccessPolicies: m.compiledAccessPolicies,
	})
	return nil
}

func (m *Manager) availabilityOpenNow(availability *models.StreamAvailability) bool {
	now := time.Now()
	if m.now != nil {
		now = m.now()
	}
	return models.DailyAvailabilityOpenAt(availability, now)
}

func (m *Manager) newManagedListener(key streamRuleKey) (managedListener, error) {
	switch key.Protocol {
	case models.StreamProtocolTCP:
		return newTCPListenerState(key, m.handleConn)
	case models.StreamProtocolUDP:
		return newUDPListenerState(key, m.handleUDPPacket)
	default:
		return nil, fmt.Errorf("unsupported stream protocol %q", key.Protocol)
	}
}

func newTCPListenerState(key streamRuleKey, handler func(net.Conn, streamRuleKey)) (*tcpListenerState, error) {
	hosts := []string{"0.0.0.0", "::"}
	listeners := make([]net.Listener, 0, len(hosts))
	listenAddrs := make([]string, 0, len(hosts))

	for _, host := range hosts {
		network := "tcp4"
		if strings.Contains(host, ":") {
			network = "tcp6"
		}

		addr := net.JoinHostPort(host, strconv.Itoa(key.ListenPort))
		ln, err := net.Listen(network, addr)
		if err != nil {
			if network == "tcp6" {
				if event := logger.DebugEvent("stream", "listener_ipv6_unavailable"); event != nil {
					event.Str("protocol", key.Protocol).
						Interface("listen_port", logger.SanitizePort(key.ListenPort)).
						Str("addr", logger.SanitizeLogString(addr)).
						Str("error", logger.SanitizeLogString(err.Error())).
						Send()
				}
				log.Printf("Stream IPv6 listener unavailable on %s for %s: %v", addr, key.String(), err)
				continue
			}
			for _, existing := range listeners {
				_ = existing.Close()
			}
			if isAddrInUseErr(err) {
				return nil, fmt.Errorf("listen_port %d for %s is already in use", key.ListenPort, key.Protocol)
			}
			return nil, fmt.Errorf("failed to listen on %s for %s: %w", addr, key.String(), err)
		}
		listeners = append(listeners, ln)
		listenAddrs = append(listenAddrs, ln.Addr().String())
	}

	if len(listeners) == 0 {
		return nil, fmt.Errorf("no stream listeners started for %s", key.String())
	}

	state := &tcpListenerState{
		key:       key,
		listeners: listeners,
		stop:      make(chan struct{}),
		conns:     make(map[net.Conn]struct{}),
	}

	for _, ln := range listeners {
		state.wg.Add(1)
		go state.acceptLoop(ln, handler)
	}

	log.Printf("Stream listener started for %s on %s", key.String(), strings.Join(listenAddrs, ", "))
	if event := logger.DebugEvent("stream", "listener_started"); event != nil {
		event.Str("protocol", key.Protocol).
			Interface("listen_port", logger.SanitizePort(key.ListenPort)).
			Interface("listen_addrs", debugSanitizeStrings(listenAddrs)).
			Send()
	}
	return state, nil
}

func (s *tcpListenerState) acceptLoop(ln net.Listener, handler func(net.Conn, streamRuleKey)) {
	defer s.wg.Done()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.stop:
				return
			default:
			}

			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if event := logger.DebugEvent("stream", "tcp_accept_temporary_error"); event != nil {
					event.Str("key", logger.SanitizeLogString(s.key.String())).
						Interface("listen_port", logger.SanitizePort(s.key.ListenPort)).
						Str("error", logger.SanitizeLogString(err.Error())).
						Send()
				}
				log.Printf("Temporary stream accept error on %s: %v", s.key.String(), err)
				time.Sleep(streamAcceptBackoff)
				continue
			}
			if isClosedConnErr(err) {
				return
			}
			if event := logger.DebugEvent("stream", "tcp_accept_error"); event != nil {
				event.Str("key", logger.SanitizeLogString(s.key.String())).
					Interface("listen_port", logger.SanitizePort(s.key.ListenPort)).
					Str("error", logger.SanitizeLogString(err.Error())).
					Send()
			}
			log.Printf("Stream accept error on %s: %v", s.key.String(), err)
			return
		}

		if !s.beginConn(conn) {
			_ = conn.Close()
			return
		}
		go func() {
			defer s.endConn(conn)
			handler(conn, s.key)
		}()
	}
}

func (s *tcpListenerState) beginConn(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closing {
		return false
	}

	s.wg.Add(1)
	s.conns[conn] = struct{}{}
	return true
}

func (s *tcpListenerState) endConn(conn net.Conn) {
	s.mu.Lock()
	delete(s.conns, conn)
	s.mu.Unlock()
	s.wg.Done()
}

func (s *tcpListenerState) close() {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return
	}
	s.closing = true
	conns := make([]net.Conn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	s.mu.Unlock()

	select {
	case <-s.stop:
	default:
		close(s.stop)
	}

	for _, ln := range s.listeners {
		_ = ln.Close()
	}
	for _, conn := range conns {
		_ = conn.Close()
	}
	s.wg.Wait()
	if event := logger.DebugEvent("stream", "tcp_listener_closed"); event != nil {
		event.Str("key", logger.SanitizeLogString(s.key.String())).
			Interface("listen_port", logger.SanitizePort(s.key.ListenPort)).
			Int("closed_connection_count", len(conns)).
			Send()
	}
}

func newUDPListenerState(key streamRuleKey, handler func(*udpListenerState, net.PacketConn, net.Addr, udpPacket, streamRuleKey)) (*udpListenerState, error) {
	hosts := []string{"0.0.0.0", "::"}
	packetConns := make([]net.PacketConn, 0, len(hosts))
	listenAddrs := make([]string, 0, len(hosts))

	for _, host := range hosts {
		network := "udp4"
		if strings.Contains(host, ":") {
			network = "udp6"
		}

		addr := net.JoinHostPort(host, strconv.Itoa(key.ListenPort))
		pc, err := net.ListenPacket(network, addr)
		if err != nil {
			if network == "udp6" {
				if event := logger.DebugEvent("stream", "listener_ipv6_unavailable"); event != nil {
					event.Str("protocol", key.Protocol).
						Interface("listen_port", logger.SanitizePort(key.ListenPort)).
						Str("addr", logger.SanitizeLogString(addr)).
						Str("error", logger.SanitizeLogString(err.Error())).
						Send()
				}
				log.Printf("Stream IPv6 packet listener unavailable on %s for %s: %v", addr, key.String(), err)
				continue
			}
			for _, existing := range packetConns {
				_ = existing.Close()
			}
			if isAddrInUseErr(err) {
				return nil, fmt.Errorf("listen_port %d for %s is already in use", key.ListenPort, key.Protocol)
			}
			return nil, fmt.Errorf("failed to listen on %s for %s: %w", addr, key.String(), err)
		}
		packetConns = append(packetConns, pc)
		listenAddrs = append(listenAddrs, pc.LocalAddr().String())
	}

	if len(packetConns) == 0 {
		return nil, fmt.Errorf("no stream listeners started for %s", key.String())
	}
	readPackets := make([]udpPacket, 0, len(packetConns))
	for range packetConns {
		packet, ok := acquireUDPPacketWithBudget(udpLargePacketBufferSize, processUDPBufferBudget)
		if !ok {
			for _, pc := range packetConns {
				_ = pc.Close()
			}
			for _, allocated := range readPackets {
				releaseUDPPacket(allocated)
			}
			return nil, fmt.Errorf("start UDP listener %s: %w", key.String(), errUDPBufferBudgetExhausted)
		}
		readPackets = append(readPackets, packet)
	}

	state := &udpListenerState{
		key:          key,
		packetConns:  packetConns,
		stop:         make(chan struct{}),
		initSlots:    make(chan struct{}, udpSessionInitLimit),
		sessions:     make(map[string]*udpSession),
		bufferBudget: processUDPBufferBudget,
		idleTimeout:  configuredUDPIdleTimeout,
	}

	state.wg.Add(1)
	go state.reaperLoop()
	for i, pc := range packetConns {
		state.wg.Add(1)
		go state.readLoop(pc, readPackets[i], handler)
	}

	log.Printf("Stream listener started for %s on %s", key.String(), strings.Join(listenAddrs, ", "))
	if event := logger.DebugEvent("stream", "listener_started"); event != nil {
		event.Str("protocol", key.Protocol).
			Interface("listen_port", logger.SanitizePort(key.ListenPort)).
			Interface("listen_addrs", debugSanitizeStrings(listenAddrs)).
			Send()
	}
	return state, nil
}

func (s *udpListenerState) readLoop(pc net.PacketConn, readPacket udpPacket, handler func(*udpListenerState, net.PacketConn, net.Addr, udpPacket, streamRuleKey)) {
	defer s.wg.Done()

	defer releaseUDPPacket(readPacket)
	buffer := readPacket.payload[:cap(readPacket.payload)]
	for {
		n, clientAddr, err := pc.ReadFrom(buffer)
		if err != nil {
			select {
			case <-s.stop:
				return
			default:
			}

			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if event := logger.DebugEvent("stream", "udp_read_temporary_error"); event != nil {
					event.Str("key", logger.SanitizeLogString(s.key.String())).
						Interface("listen_port", logger.SanitizePort(s.key.ListenPort)).
						Str("error", logger.SanitizeLogString(err.Error())).
						Send()
				}
				log.Printf("Temporary stream packet read error on %s: %v", s.key.String(), err)
				time.Sleep(streamAcceptBackoff)
				continue
			}
			if isClosedConnErr(err) {
				return
			}
			if event := logger.DebugEvent("stream", "udp_read_error"); event != nil {
				event.Str("key", logger.SanitizeLogString(s.key.String())).
					Interface("listen_port", logger.SanitizePort(s.key.ListenPort)).
					Str("error", logger.SanitizeLogString(err.Error())).
					Send()
			}
			log.Printf("Stream packet read error on %s: %v", s.key.String(), err)
			return
		}
		if n <= 0 || clientAddr == nil {
			continue
		}

		packet, ok := acquireUDPPacketWithBudget(n, s.bufferBudget)
		if !ok {
			s.droppedPackets.Add(1)
			s.droppedBytes.Add(uint64(n))
			continue
		}
		copy(packet.payload, buffer[:n])
		handler(s, pc, clientAddr, packet, s.key)
	}
}

func (s *udpListenerState) reaperLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(udpSessionReaperInterval)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			s.reapIdleSessions(now)
		case <-s.stop:
			return
		}
	}
}

func (s *udpListenerState) reapIdleSessions(now time.Time) {
	timeout := s.idleTimeout
	if timeout <= 0 {
		timeout = udpSessionIdleTimeout
	}
	cutoff := now.Add(-timeout).UnixNano()
	s.mu.Lock()
	sessions := make([]*udpSession, 0, len(s.sessions))
	for _, session := range s.sessions {
		if session.lastActivity.Load() <= cutoff {
			sessions = append(sessions, session)
		}
	}
	s.mu.Unlock()

	for _, session := range sessions {
		session.closeIfIdle(cutoff)
	}
}

func (s *udpListenerState) sessionID(pc net.PacketConn, clientAddr net.Addr) string {
	return pc.LocalAddr().String() + "|" + clientAddr.String()
}

func (s *udpListenerState) getOrCreateSession(packetConn net.PacketConn, clientAddr net.Addr, rule models.StreamRule) (*udpSession, bool, bool) {
	id := s.sessionID(packetConn, clientAddr)
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closing {
		return nil, false, false
	}
	if existing, ok := s.sessions[id]; ok {
		return existing, true, true
	}
	if len(s.sessions) >= udpListenerSessionLimit {
		return nil, false, false
	}
	reserved := false
	if s.initSlots != nil {
		select {
		case s.initSlots <- struct{}{}:
			reserved = true
		default:
			return nil, false, false
		}
	}

	start := time.Now()
	clientIP := extractRemoteIP(clientAddr)
	entry := newStreamEntry(streamRuleKeyFromRule(rule), addrString(clientAddr), clientIP)
	entry.AuthRequired = rule.UseAuth
	entry.Upstream = rule.Target
	entry.ExpectedService = rule.ServiceProfile.ServiceID
	entry.ServiceConfidence = rule.ServiceProfile.ServiceConfidence
	entry.DeviceRole = rule.ServiceProfile.DeviceRole
	ctx, cancel := context.WithCancel(context.Background())
	session := &udpSession{
		id:         id,
		listener:   s,
		packetConn: packetConn,
		clientAddr: clientAddr,
		rule:       rule,
		start:      start,
		ctx:        ctx,
		cancel:     cancel,
		done:       make(chan struct{}),
		notify:     make(chan struct{}, 1),
		entry:      entry,
	}
	session.lastActivity.Store(start.UnixNano())
	session.status.Store(int64(entry.Status))
	session.initReserved.Store(reserved)
	s.sessions[session.id] = session
	diagnostics.OpenUDPSession()
	return session, false, true
}

func (s *udpListenerState) startSession(session *udpSession, run func()) bool {
	s.mu.Lock()
	if s.closing || s.sessions[session.id] != session {
		s.mu.Unlock()
		return false
	}
	s.wg.Add(1)
	s.mu.Unlock()

	go run()
	return true
}

func (s *udpListenerState) removeSession(id string, session *udpSession) {
	s.mu.Lock()
	if current, ok := s.sessions[id]; ok && current == session {
		delete(s.sessions, id)
		diagnostics.CloseUDPSession()
	}
	s.mu.Unlock()
}

func (s *udpListenerState) reserveQueuedBytes(bytes int) bool {
	if bytes <= 0 || bytes > udpListenerQueueByteLimit {
		return false
	}
	for {
		current := s.queuedBytes.Load()
		if current > int64(udpListenerQueueByteLimit-bytes) {
			return false
		}
		if s.queuedBytes.CompareAndSwap(current, current+int64(bytes)) {
			diagnostics.AddUDPQueuedBytes(int64(bytes))
			return true
		}
	}
}

func (s *udpListenerState) releaseQueuedBytes(bytes int) {
	if bytes > 0 {
		s.queuedBytes.Add(-int64(bytes))
		diagnostics.AddUDPQueuedBytes(-int64(bytes))
	}
}

func (s *udpListenerState) dropPacket(packet udpPacket) {
	s.droppedPackets.Add(1)
	s.droppedBytes.Add(uint64(len(packet.payload)))
	releaseUDPPacket(packet)
}

func (s *udpListenerState) close() {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return
	}
	s.closing = true
	sessions := make([]*udpSession, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, session)
	}
	s.mu.Unlock()

	select {
	case <-s.stop:
	default:
		close(s.stop)
	}

	for _, pc := range s.packetConns {
		_ = pc.Close()
	}
	for _, session := range sessions {
		session.close()
	}
	s.wg.Wait()
	if event := logger.DebugEvent("stream", "udp_listener_closed"); event != nil {
		event.Str("key", logger.SanitizeLogString(s.key.String())).
			Interface("listen_port", logger.SanitizePort(s.key.ListenPort)).
			Int("closed_session_count", len(sessions)).
			Send()
	}
}

func (s *udpSession) addBytesIn(bytes int) {
	if bytes <= 0 {
		return
	}
	s.bytesIn.Add(uint64(bytes))
	if s.meter != nil {
		s.meter.recordIn(bytes)
	}
}

func (s *udpSession) addBytesOut(bytes int) {
	if bytes <= 0 {
		return
	}
	s.bytesOut.Add(uint64(bytes))
	if s.meter != nil {
		s.meter.recordOut(bytes)
	}
}

func (s *udpSession) setStatus(status int) {
	if status <= 0 {
		return
	}
	s.status.Store(int64(status))
}

func (s *udpSession) setAuthResult(decision string, loggedIn bool) {
	s.entryMu.Lock()
	s.entry.AuthDecision = decision
	s.entry.LoggedIn = loggedIn
	s.entryMu.Unlock()
}

func (s *udpSession) snapshotEntry() gatewaylog.Entry {
	s.entryMu.Lock()
	entry := s.entry
	s.entryMu.Unlock()
	entry.Status = int(s.status.Load())
	entry.BytesIn = s.bytesIn.Load()
	entry.BytesOut = s.bytesOut.Load()
	entry.DurationMs = time.Since(s.start).Milliseconds()
	return entry
}

func (s *udpSession) routeInfo() (string, string) {
	return s.entry.RouteKey, s.entry.Upstream
}

func (s *udpSession) touch(now time.Time) bool {
	s.queueMu.Lock()
	defer s.queueMu.Unlock()
	if s.queueClosed {
		return false
	}
	s.lastActivity.Store(now.UnixNano())
	return true
}

func (s *udpSession) closeIfIdle(cutoffUnixNano int64) {
	if s == nil {
		return
	}
	s.queueMu.Lock()
	if s.queueClosed || s.lastActivity.Load() > cutoffUnixNano {
		s.queueMu.Unlock()
		return
	}
	s.queueClosed = true
	s.queueMu.Unlock()
	s.close()
}

func (s *udpSession) enqueue(packet udpPacket) bool {
	packetBytes := len(packet.payload)
	if packetBytes == 0 {
		return false
	}
	if packetBytes > udpSessionQueueByteLimit {
		diagnostics.RecordUDPQueueDrop()
		return false
	}

	s.queueMu.Lock()
	if s.queueClosed {
		s.queueMu.Unlock()
		return false
	}
	if s.queueLen >= udpSessionQueuePacketLimit || s.queueBytes > udpSessionQueueByteLimit-packetBytes {
		diagnostics.RecordUDPQueueDrop()
		s.queueMu.Unlock()
		return false
	}
	queueFootprint := udpPacketQueueFootprint(packet)
	if !s.listener.reserveQueuedBytes(queueFootprint) {
		diagnostics.RecordUDPQueueDrop()
		s.queueMu.Unlock()
		return false
	}
	tail := (s.queueHead + s.queueLen) % len(s.queue)
	s.queue[tail] = packet
	s.queueLen++
	s.queueBytes += packetBytes
	s.lastActivity.Store(time.Now().UnixNano())
	s.queueMu.Unlock()

	select {
	case s.notify <- struct{}{}:
	default:
	}
	return true
}

func (s *udpSession) dequeue() (udpPacket, bool) {
	s.queueMu.Lock()
	if s.queueLen == 0 {
		s.queueMu.Unlock()
		return udpPacket{}, false
	}
	packet := s.queue[s.queueHead]
	s.queue[s.queueHead] = udpPacket{}
	s.queueHead = (s.queueHead + 1) % len(s.queue)
	s.queueLen--
	packetBytes := len(packet.payload)
	s.queueBytes -= packetBytes
	s.queueMu.Unlock()

	s.listener.releaseQueuedBytes(udpPacketQueueFootprint(packet))
	return packet, true
}

func (s *udpSession) releaseInitReservation() {
	if s == nil || !s.initReserved.Swap(false) || s.listener == nil || s.listener.initSlots == nil {
		return
	}
	<-s.listener.initSlots
}

func (s *udpSession) setUpstream(upstream net.Conn) bool {
	s.upstreamMu.Lock()
	defer s.upstreamMu.Unlock()
	if s.closed.Load() {
		return false
	}
	s.upstream = upstream
	return true
}

func (s *udpSession) upstreamConn() net.Conn {
	s.upstreamMu.Lock()
	defer s.upstreamMu.Unlock()
	return s.upstream
}

func (s *udpSession) close() {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		s.cancel()
		close(s.done)

		s.queueMu.Lock()
		s.queueClosed = true
		packets := make([]udpPacket, 0, s.queueLen)
		queuedBytes := 0
		for s.queueLen > 0 {
			packet := s.queue[s.queueHead]
			s.queue[s.queueHead] = udpPacket{}
			s.queueHead = (s.queueHead + 1) % len(s.queue)
			s.queueLen--
			queuedBytes += udpPacketQueueFootprint(packet)
			packets = append(packets, packet)
		}
		s.queueBytes = 0
		s.queueMu.Unlock()
		s.listener.releaseQueuedBytes(queuedBytes)
		for _, packet := range packets {
			releaseUDPPacket(packet)
		}

		s.upstreamMu.Lock()
		upstream := s.upstream
		s.upstream = nil
		s.upstreamMu.Unlock()
		if upstream != nil {
			_ = upstream.Close()
		}
	})
}

func (m *Manager) handleConn(client net.Conn, key streamRuleKey) {
	start := time.Now()
	remoteAddr := ""
	clientIP := ""
	if client != nil {
		remoteAddr = client.RemoteAddr().String()
		clientIP = extractRemoteIP(client.RemoteAddr())
	}
	if event := logger.DebugEvent("stream", "tcp_connection_start"); event != nil {
		event.Str("key", logger.SanitizeLogString(key.String())).
			Interface("listen_port", logger.SanitizePort(key.ListenPort)).
			Str("remote_addr", logger.SanitizeLogString(remoteAddr)).
			Str("client_ip", logger.SanitizeLogString(clientIP)).
			Send()
	}

	entry := newStreamEntry(key, remoteAddr, clientIP)

	var meter *streamTrafficMeter

	defer func() {
		m.logStreamEntry(entry, key, start, meter)
		if event := logger.DebugEvent("stream", "tcp_connection_end"); event != nil {
			event.Str("key", logger.SanitizeLogString(key.String())).
				Interface("listen_port", logger.SanitizePort(key.ListenPort)).
				Str("remote_addr", logger.SanitizeLogString(remoteAddr)).
				Str("client_ip", logger.SanitizeLogString(clientIP)).
				Str("upstream", logger.SanitizeLogString(entry.Upstream)).
				Int("status", entry.Status).
				Str("auth_decision", logger.SanitizeLogString(entry.AuthDecision)).
				Bool("logged_in", entry.LoggedIn).
				Uint64("bytes_in", entry.BytesIn).
				Uint64("bytes_out", entry.BytesOut).
				Int64("duration_ms", time.Since(start).Milliseconds()).
				Send()
		}
		if client != nil {
			_ = client.Close()
		}
	}()

	rule, availability, ok := m.currentRuleConfig(key)
	if !ok {
		entry.Matched = false
		entry.Status = http.StatusNotFound
		entry.AuthDecision = "rule_missing"
		if event := logger.DebugEvent("stream", "tcp_rule_missing"); event != nil {
			event.Str("key", logger.SanitizeLogString(key.String())).
				Interface("listen_port", logger.SanitizePort(key.ListenPort)).
				Send()
		}
		return
	}

	entry.AuthRequired = rule.UseAuth
	entry.Upstream = rule.Target
	entry.ExpectedService = rule.ServiceProfile.ServiceID
	entry.ServiceConfidence = rule.ServiceProfile.ServiceConfidence
	entry.DeviceRole = rule.ServiceProfile.DeviceRole
	if event := logger.DebugEvent("stream", "tcp_rule_matched"); event != nil {
		event.Str("key", logger.SanitizeLogString(key.String())).
			Interface("listen_port", logger.SanitizePort(key.ListenPort)).
			Str("target", logger.SanitizeLogString(rule.Target)).
			Bool("auth_required", rule.UseAuth).
			Send()
	}
	if !m.availabilityOpenNow(availability) {
		entry.Status = http.StatusServiceUnavailable
		entry.AuthDecision = "schedule_closed"
		if event := logger.DebugEvent("stream", "tcp_schedule_closed"); event != nil {
			event.Str("key", logger.SanitizeLogString(key.String())).
				Interface("listen_port", logger.SanitizePort(key.ListenPort)).
				Send()
		}
		return
	}

	if !m.handler.IsClientIPVisible(clientIP) {
		entry.Status = 499
		entry.AuthDecision = "visibility_denied"
		if event := logger.DebugEvent("stream", "tcp_visibility_denied"); event != nil {
			event.Str("key", logger.SanitizeLogString(key.String())).
				Str("client_ip", logger.SanitizeLogString(clientIP)).
				Send()
		}
		return
	}

	if bypassed, groupID := m.matchStreamBypass(rule, clientIP); bypassed {
		diagnostics.RecordStreamBypassHit()
		entry.AuthDecision = "advanced_bypass"
		entry.BypassPolicyVersion = rule.BypassPolicy.PolicyVersion
		entry.BypassGroupID = groupID
	} else if rule.UseAuth {
		allowed, status, decision, err := m.verify(rule, clientIP)
		entry.AuthDecision = decision
		entry.LoggedIn = allowed
		if !allowed {
			entry.Status = status
			if err != nil {
				if event := logger.DebugEvent("stream", "tcp_auth_rejected"); event != nil {
					event.Str("key", logger.SanitizeLogString(key.String())).
						Str("client_ip", logger.SanitizeLogString(clientIP)).
						Int("status", status).
						Str("decision", logger.SanitizeLogString(decision)).
						Str("error", logger.SanitizeLogString(err.Error())).
						Send()
				}
				log.Printf("Stream auth rejected on %s for %s: %v", key.String(), clientIP, err)
			} else if event := logger.DebugEvent("stream", "tcp_auth_rejected"); event != nil {
				event.Str("key", logger.SanitizeLogString(key.String())).
					Str("client_ip", logger.SanitizeLogString(clientIP)).
					Int("status", status).
					Str("decision", logger.SanitizeLogString(decision)).
					Send()
			}
			return
		}
		if event := logger.DebugEvent("stream", "tcp_auth_allowed"); event != nil {
			event.Str("key", logger.SanitizeLogString(key.String())).
				Str("client_ip", logger.SanitizeLogString(clientIP)).
				Str("decision", logger.SanitizeLogString(decision)).
				Send()
		}
		m.handler.MarkLoggedInActiveByClientIP(clientIP, time.Now())
	} else {
		entry.AuthDecision = "public"
	}

	var clientInitial []byte
	_, validationDirection, _, strictKnown := streamprobe.Definition(rule.ServiceProfile.ServiceID)
	if rule.ValidationMode == models.StreamValidationStrict && !strictKnown {
		entry.Status = http.StatusMisdirectedRequest
		entry.ValidationDecision = "unknown_service"
		return
	}
	if rule.ValidationMode == models.StreamValidationStrict && validationDirection == streamprobe.DirectionClient {
		initial, detected, evidence, validationErr := validateTCPInitial(client, rule.ServiceProfile.ServiceID, streamprobe.DirectionClient)
		entry.DetectedService = detected
		entry.ValidationEvidence = evidence
		if validationErr != nil {
			entry.ValidationDecision = "mismatch"
			entry.Status = http.StatusMisdirectedRequest
			var failure *streamValidationFailure
			if errors.As(validationErr, &failure) {
				entry.ValidationDecision = failure.decision
				if failure.decision == "timeout" {
					entry.Status = http.StatusRequestTimeout
				}
			}
			diagnostics.RecordStreamValidation(entry.ValidationDecision)
			return
		}
		entry.ValidationDecision = "matched"
		clientInitial = initial
	}

	dialer := &net.Dialer{
		Timeout:   streamDialTimeout,
		KeepAlive: 30 * time.Second,
	}
	upstream, err := dialer.Dial(rule.Protocol, rule.Target)
	if err != nil {
		entry.Status = http.StatusBadGateway
		if event := logger.DebugEvent("stream", "tcp_upstream_dial_failed"); event != nil {
			event.Str("key", logger.SanitizeLogString(key.String())).
				Str("target", logger.SanitizeLogString(rule.Target)).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		log.Printf("Stream upstream dial failed on %s to %s: %v", key.String(), rule.Target, err)
		return
	}
	if event := logger.DebugEvent("stream", "tcp_upstream_dialed"); event != nil {
		event.Str("key", logger.SanitizeLogString(key.String())).
			Str("target", logger.SanitizeLogString(rule.Target)).
			Send()
	}
	defer upstream.Close()

	meter = newStreamTrafficMeter(m.handler, key)

	var serverInitial []byte
	if rule.ValidationMode == models.StreamValidationStrict && validationDirection == streamprobe.DirectionServer {
		initial, detected, evidence, validationErr := validateTCPInitial(upstream, rule.ServiceProfile.ServiceID, streamprobe.DirectionServer)
		entry.DetectedService = detected
		entry.ValidationEvidence = evidence
		if validationErr != nil {
			entry.ValidationDecision = "mismatch"
			entry.Status = http.StatusMisdirectedRequest
			var failure *streamValidationFailure
			if errors.As(validationErr, &failure) {
				entry.ValidationDecision = failure.decision
				if failure.decision == "timeout" {
					entry.Status = http.StatusRequestTimeout
				}
			}
			diagnostics.RecordStreamValidation(entry.ValidationDecision)
			return
		}
		entry.ValidationDecision = "matched"
		serverInitial = initial
		if err := writeInitial(client, serverInitial); err != nil {
			entry.Status = http.StatusBadGateway
			entry.ValidationDecision = "replay_failed"
			return
		}
		entry.BytesOut += uint64(len(serverInitial))
		meter.recordOut(len(serverInitial))
		if rule.ServiceProfile.ServiceID == "rfb" {
			response, detected, evidence, validationErr := validateTCPInitial(client, "rfb", streamprobe.DirectionClient)
			entry.DetectedService = detected
			entry.ValidationEvidence = evidence
			if validationErr != nil {
				entry.Status = http.StatusMisdirectedRequest
				entry.ValidationDecision = "client_response_mismatch"
				diagnostics.RecordStreamValidation(entry.ValidationDecision)
				return
			}
			if err := writeInitial(upstream, response); err != nil {
				entry.Status = http.StatusBadGateway
				entry.ValidationDecision = "replay_failed"
				return
			}
			entry.BytesIn += uint64(len(response))
			meter.recordIn(len(response))
		}
	}
	if len(clientInitial) > 0 {
		if err := writeInitial(upstream, clientInitial); err != nil {
			entry.Status = http.StatusBadGateway
			entry.ValidationDecision = "replay_failed"
			return
		}
		entry.BytesIn += uint64(len(clientInitial))
		meter.recordIn(len(clientInitial))
	}

	meter.activate(clientIP, time.Now())

	bytesIn, bytesOut, relayErr := relayBidirectional(client, upstream, meter)
	entry.BytesIn += bytesIn
	entry.BytesOut += bytesOut
	if relayErr != nil {
		entry.Status = http.StatusBadGateway
		if event := logger.DebugEvent("stream", "tcp_relay_failed"); event != nil {
			event.Str("key", logger.SanitizeLogString(key.String())).
				Str("target", logger.SanitizeLogString(rule.Target)).
				Uint64("bytes_in", bytesIn).
				Uint64("bytes_out", bytesOut).
				Str("error", logger.SanitizeLogString(relayErr.Error())).
				Send()
		}
		log.Printf("Stream relay failed on %s to %s: %v", key.String(), rule.Target, relayErr)
	} else if event := logger.DebugEvent("stream", "tcp_relay_completed"); event != nil {
		event.Str("key", logger.SanitizeLogString(key.String())).
			Str("target", logger.SanitizeLogString(rule.Target)).
			Uint64("bytes_in", bytesIn).
			Uint64("bytes_out", bytesOut).
			Send()
	}
}

func (m *Manager) handleUDPPacket(listener *udpListenerState, packetConn net.PacketConn, clientAddr net.Addr, packet udpPacket, key streamRuleKey) {
	if len(packet.payload) == 0 {
		releaseUDPPacket(packet)
		return
	}

	rule, availability, ok := m.currentRuleConfig(key)
	if !ok {
		releaseUDPPacket(packet)
		entry := newStreamEntry(key, addrString(clientAddr), extractRemoteIP(clientAddr))
		entry.Matched = false
		entry.Status = http.StatusNotFound
		entry.AuthDecision = "rule_missing"
		if event := logger.DebugEvent("stream", "udp_rule_missing"); event != nil {
			event.Str("key", logger.SanitizeLogString(key.String())).
				Interface("listen_port", logger.SanitizePort(key.ListenPort)).
				Str("client_addr", logger.SanitizeLogString(addrString(clientAddr))).
				Send()
		}
		m.logStreamEntry(entry, key, time.Now(), nil)
		return
	}
	if !m.availabilityOpenNow(availability) {
		releaseUDPPacket(packet)
		if event := logger.DebugEvent("stream", "udp_schedule_closed"); event != nil {
			event.Str("key", logger.SanitizeLogString(key.String())).
				Interface("listen_port", logger.SanitizePort(key.ListenPort)).
				Str("client_addr", logger.SanitizeLogString(addrString(clientAddr))).
				Send()
		}
		return
	}

	session, loaded, ok := listener.getOrCreateSession(packetConn, clientAddr, rule)
	if !ok {
		diagnostics.RecordUDPQueueDrop()
		listener.dropPacket(packet)
		return
	}
	if !session.enqueue(packet) {
		listener.dropPacket(packet)
		if !loaded {
			session.close()
			listener.removeSession(session.id, session)
			session.releaseInitReservation()
		}
		return
	}
	if loaded {
		return
	}
	if !listener.startSession(session, func() { m.runUDPSession(listener, session) }) {
		session.close()
		listener.removeSession(session.id, session)
		session.releaseInitReservation()
	}
}

func (m *Manager) initializeUDPSession(session *udpSession) bool {
	rule := session.rule
	key := streamRuleKeyFromRule(rule)
	clientIP := extractRemoteIP(session.clientAddr)
	if event := logger.DebugEvent("stream", "udp_session_start"); event != nil {
		event.Str("key", logger.SanitizeLogString(key.String())).
			Interface("listen_port", logger.SanitizePort(key.ListenPort)).
			Str("target", logger.SanitizeLogString(rule.Target)).
			Str("client_addr", logger.SanitizeLogString(addrString(session.clientAddr))).
			Str("client_ip", logger.SanitizeLogString(clientIP)).
			Bool("auth_required", rule.UseAuth).
			Send()
	}

	if !m.handler.IsClientIPVisible(clientIP) {
		session.setStatus(499)
		session.setAuthResult("visibility_denied", false)
		if event := logger.DebugEvent("stream", "udp_visibility_denied"); event != nil {
			event.Str("key", logger.SanitizeLogString(key.String())).
				Str("client_ip", logger.SanitizeLogString(clientIP)).
				Send()
		}
		return false
	}

	if bypassed, groupID := m.matchStreamBypass(rule, clientIP); bypassed {
		diagnostics.RecordStreamBypassHit()
		session.entryMu.Lock()
		session.entry.AuthDecision = "advanced_bypass"
		session.entry.BypassPolicyVersion = rule.BypassPolicy.PolicyVersion
		session.entry.BypassGroupID = groupID
		session.entryMu.Unlock()
	} else if rule.UseAuth {
		allowed, status, decision, err := m.verifyContext(session.ctx, rule, clientIP)
		if session.ctx.Err() != nil {
			return false
		}
		session.setAuthResult(decision, allowed)
		if !allowed {
			session.setStatus(status)
			if err != nil {
				if event := logger.DebugEvent("stream", "udp_auth_rejected"); event != nil {
					event.Str("key", logger.SanitizeLogString(key.String())).
						Str("client_ip", logger.SanitizeLogString(clientIP)).
						Int("status", status).
						Str("decision", logger.SanitizeLogString(decision)).
						Str("error", logger.SanitizeLogString(err.Error())).
						Send()
				}
				log.Printf("Stream auth rejected on %s for %s: %v", key.String(), clientIP, err)
			} else if event := logger.DebugEvent("stream", "udp_auth_rejected"); event != nil {
				event.Str("key", logger.SanitizeLogString(key.String())).
					Str("client_ip", logger.SanitizeLogString(clientIP)).
					Int("status", status).
					Str("decision", logger.SanitizeLogString(decision)).
					Send()
			}
			return false
		}
		if event := logger.DebugEvent("stream", "udp_auth_allowed"); event != nil {
			event.Str("key", logger.SanitizeLogString(key.String())).
				Str("client_ip", logger.SanitizeLogString(clientIP)).
				Str("decision", logger.SanitizeLogString(decision)).
				Send()
		}
		m.handler.MarkLoggedInActiveByClientIP(clientIP, time.Now())
	} else {
		session.setAuthResult("public", false)
	}

	if rule.ValidationMode == models.StreamValidationStrict {
		detected, evidence, validationErr := validateUDPInitial(rule, session.firstQueuedPayload())
		session.entryMu.Lock()
		session.entry.DetectedService = detected
		session.entry.ValidationEvidence = evidence
		session.entry.ValidationDecision = "matched"
		if validationErr != nil {
			session.entry.ValidationDecision = "mismatch"
			var failure *streamValidationFailure
			if errors.As(validationErr, &failure) {
				session.entry.ValidationDecision = failure.decision
			}
		}
		session.entryMu.Unlock()
		if validationErr != nil {
			session.setStatus(http.StatusMisdirectedRequest)
			session.entryMu.Lock()
			decision := session.entry.ValidationDecision
			session.entryMu.Unlock()
			diagnostics.RecordStreamValidation(decision)
			return false
		}
	}

	dialer := &net.Dialer{Timeout: streamDialTimeout}
	upstream, err := dialer.DialContext(session.ctx, rule.Protocol, rule.Target)
	if err != nil {
		if session.ctx.Err() != nil {
			return false
		}
		session.setStatus(http.StatusBadGateway)
		if event := logger.DebugEvent("stream", "udp_upstream_dial_failed"); event != nil {
			event.Str("key", logger.SanitizeLogString(key.String())).
				Str("target", logger.SanitizeLogString(rule.Target)).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		log.Printf("Stream upstream dial failed on %s to %s: %v", key.String(), rule.Target, err)
		return false
	}
	if !session.setUpstream(upstream) {
		_ = upstream.Close()
		return false
	}
	if event := logger.DebugEvent("stream", "udp_upstream_dialed"); event != nil {
		event.Str("key", logger.SanitizeLogString(key.String())).
			Str("target", logger.SanitizeLogString(rule.Target)).
			Send()
	}
	if event := logger.DebugEvent("stream", "udp_session_stored"); event != nil {
		event.Str("key", logger.SanitizeLogString(key.String())).
			Str("session_id", logger.SanitizeLogString(session.id)).
			Send()
	}
	return true
}

func (m *Manager) runUDPSession(listener *udpListenerState, session *udpSession) {
	defer listener.wg.Done()
	defer listener.removeSession(session.id, session)
	defer session.close()
	defer session.releaseInitReservation()
	defer func() {
		entry := session.snapshotEntry()
		m.logStreamEntry(entry, streamRuleKeyFromRule(session.rule), session.start, session.meter)
		if event := logger.DebugEvent("stream", "udp_session_end"); event != nil {
			event.Str("route_key", logger.SanitizeLogString(entry.RouteKey)).
				Str("upstream", logger.SanitizeLogString(entry.Upstream)).
				Str("remote_addr", logger.SanitizeLogString(entry.RemoteAddr)).
				Str("remote_ip", logger.SanitizeLogString(entry.RemoteIP)).
				Int("status", entry.Status).
				Str("auth_decision", logger.SanitizeLogString(entry.AuthDecision)).
				Uint64("bytes_in", entry.BytesIn).
				Uint64("bytes_out", entry.BytesOut).
				Int64("duration_ms", entry.DurationMs).
				Send()
		}
	}()

	initialized := m.initializeUDPSession(session)
	session.releaseInitReservation()
	if !initialized {
		return
	}

	session.meter = newStreamTrafficMeter(m.handler, streamRuleKeyFromRule(session.rule))
	session.meter.activate(extractRemoteIP(session.clientAddr), time.Now())
	m.relayUDPSession(session)
}

func (m *Manager) relayUDPSession(session *udpSession) {
	upstream := session.upstreamConn()
	if upstream == nil {
		return
	}

	readerDone := make(chan struct{}, 1)
	go func() {
		m.readUDPUpstream(session, upstream)
		// The writer may be blocked inside upstream.Write and unable to select
		// readerDone. Closing the session here also interrupts that direction.
		session.close()
		readerDone <- struct{}{}
	}()
	readerFinished := false
	defer func() {
		session.close()
		if !readerFinished {
			<-readerDone
		}
	}()

	for {
		select {
		case <-session.done:
			return
		case <-readerDone:
			readerFinished = true
			return
		case <-session.notify:
			for {
				packet, ok := session.dequeue()
				if !ok {
					break
				}
				payloadBytes := len(packet.payload)
				written, err := upstream.Write(packet.payload)
				releaseUDPPacket(packet)
				if written > 0 {
					session.addBytesIn(written)
					session.touch(time.Now())
				}
				if err != nil {
					if !isClosedConnErr(err) && session.ctx.Err() == nil {
						session.setStatus(http.StatusBadGateway)
						routeKey, target := session.routeInfo()
						if event := logger.DebugEvent("stream", "udp_upstream_write_failed"); event != nil {
							event.Str("route_key", logger.SanitizeLogString(routeKey)).
								Str("target", logger.SanitizeLogString(target)).
								Str("client_addr", logger.SanitizeLogString(addrString(session.clientAddr))).
								Int("payload_bytes", payloadBytes).
								Int("written_bytes", written).
								Str("error", logger.SanitizeLogString(err.Error())).
								Send()
						}
						log.Printf("UDP upstream write failed on %s to %s for %s: %v", routeKey, target, addrString(session.clientAddr), err)
					}
					return
				}
				if written != payloadBytes {
					session.setStatus(http.StatusBadGateway)
					routeKey, target := session.routeInfo()
					if event := logger.DebugEvent("stream", "udp_upstream_short_write"); event != nil {
						event.Str("route_key", logger.SanitizeLogString(routeKey)).
							Str("target", logger.SanitizeLogString(target)).
							Str("client_addr", logger.SanitizeLogString(addrString(session.clientAddr))).
							Int("payload_bytes", payloadBytes).
							Int("written_bytes", written).
							Send()
					}
					log.Printf("UDP upstream short write on %s to %s for %s: wrote %d of %d bytes", routeKey, target, addrString(session.clientAddr), written, payloadBytes)
					return
				}

				select {
				case <-session.done:
					return
				case <-readerDone:
					readerFinished = true
					return
				default:
				}
			}
		}
	}
}

func (m *Manager) readUDPUpstream(session *udpSession, upstream net.Conn) {
	readPacket, err := newUDPPacketReader(upstream, session.listener.bufferBudget)
	if err != nil {
		session.setStatus(http.StatusBadGateway)
		return
	}
	for {
		packet, err := readPacket()
		n := len(packet.payload)
		if packet.pooled != nil && (n > 0 || err == nil) {
			if !session.touch(time.Now()) {
				releaseUDPPacket(packet)
				return
			}
			written, writeErr := session.packetConn.WriteTo(packet.payload, session.clientAddr)
			releaseUDPPacket(packet)
			if written > 0 {
				session.addBytesOut(written)
			}
			if writeErr != nil {
				if isClosedConnErr(writeErr) || session.ctx.Err() != nil {
					return
				}
				session.setStatus(http.StatusBadGateway)
				routeKey, target := session.routeInfo()
				if event := logger.DebugEvent("stream", "udp_downstream_write_failed"); event != nil {
					event.Str("route_key", logger.SanitizeLogString(routeKey)).
						Str("target", logger.SanitizeLogString(target)).
						Str("client_addr", logger.SanitizeLogString(addrString(session.clientAddr))).
						Int("payload_bytes", n).
						Int("written_bytes", written).
						Str("error", logger.SanitizeLogString(writeErr.Error())).
						Send()
				}
				log.Printf("UDP downstream write failed on %s to %s for %s: %v", routeKey, target, addrString(session.clientAddr), writeErr)
				return
			}
			if written != n {
				session.setStatus(http.StatusBadGateway)
				routeKey, target := session.routeInfo()
				if event := logger.DebugEvent("stream", "udp_downstream_short_write"); event != nil {
					event.Str("route_key", logger.SanitizeLogString(routeKey)).
						Str("target", logger.SanitizeLogString(target)).
						Str("client_addr", logger.SanitizeLogString(addrString(session.clientAddr))).
						Int("payload_bytes", n).
						Int("written_bytes", written).
						Send()
				}
				log.Printf("UDP downstream short write on %s to %s for %s: wrote %d of %d bytes", routeKey, target, addrString(session.clientAddr), written, n)
				return
			}
		} else {
			releaseUDPPacket(packet)
		}
		if err == nil {
			continue
		}
		if isClosedConnErr(err) || errors.Is(err, io.EOF) || session.ctx.Err() != nil {
			return
		}
		session.setStatus(http.StatusBadGateway)
		routeKey, target := session.routeInfo()
		if event := logger.DebugEvent("stream", "udp_upstream_read_failed"); event != nil {
			event.Str("route_key", logger.SanitizeLogString(routeKey)).
				Str("target", logger.SanitizeLogString(target)).
				Str("client_addr", logger.SanitizeLogString(addrString(session.clientAddr))).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		log.Printf("UDP upstream read failed on %s to %s for %s: %v", routeKey, target, addrString(session.clientAddr), err)
		return
	}
}

func (m *Manager) verify(rule models.StreamRule, clientIP string) (bool, int, string, error) {
	return m.verifyContext(context.Background(), rule, clientIP)
}

func (m *Manager) verifyContext(parent context.Context, rule models.StreamRule, clientIP string) (bool, int, string, error) {
	authConfig := m.handler.GetAuthConfig()
	if strings.TrimSpace(authConfig.AuthURL) == "" {
		if event := logger.DebugEvent("stream", "auth_verify_skipped_missing_auth_url"); event != nil {
			event.Str("protocol", logger.SanitizeLogString(rule.Protocol)).
				Interface("listen_port", logger.SanitizePort(rule.ListenPort)).
				Str("client_ip", logger.SanitizeLogString(clientIP)).
				Send()
		}
		return false, http.StatusBadGateway, "auth_unconfigured", fmt.Errorf("auth_url is not configured")
	}

	start := time.Now()
	if event := logger.DebugEvent("stream", "auth_verify_start"); event != nil {
		event.Str("transport", "auth_bridge").
			Str("protocol", logger.SanitizeLogString(rule.Protocol)).
			Interface("listen_port", logger.SanitizePort(rule.ListenPort)).
			Str("target", logger.SanitizeLogString(rule.Target)).
			Str("client_ip", logger.SanitizeLogString(clientIP)).
			Send()
	}

	ctx, cancel := context.WithTimeout(parent, streamAuthTimeout)
	defer cancel()

	resp, err := m.handler.VerifyStreamAuth(ctx, rule, clientIP)
	if err != nil {
		cause, statusCode := classifyStreamAuthBridgeFailure(err)
		if event := logger.DebugEvent("stream", "auth_verify_failed"); event != nil {
			event.Str("decision", cause).
				Int64("duration_ms", time.Since(start).Milliseconds()).
				Send()
		}
		return false, statusCode, cause, err
	}
	statusCode := int(resp.GetStatus())
	if statusCode <= 0 {
		if resp.GetAllowed() {
			statusCode = http.StatusOK
		} else {
			statusCode = http.StatusForbidden
		}
	}
	decision := strings.TrimSpace(resp.GetDecision())

	if statusCode >= 200 && statusCode < 300 && resp.GetAllowed() {
		if decision == "" {
			decision = "passed"
		}
		if event := logger.DebugEvent("stream", "auth_verify_end"); event != nil {
			event.Int("status", statusCode).
				Bool("allowed", true).
				Str("decision", logger.SanitizeLogString(decision)).
				Int64("duration_ms", time.Since(start).Milliseconds()).
				Send()
		}
		return true, http.StatusOK, decision, nil
	}
	if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
		if decision == "" {
			decision = "denied"
		}
		if event := logger.DebugEvent("stream", "auth_verify_end"); event != nil {
			event.Int("status", statusCode).
				Bool("allowed", false).
				Str("decision", logger.SanitizeLogString(decision)).
				Int64("duration_ms", time.Since(start).Milliseconds()).
				Send()
		}
		return false, http.StatusForbidden, decision, nil
	}
	if statusCode >= 500 {
		if event := logger.DebugEvent("stream", "auth_verify_failed"); event != nil {
			event.Int("status", statusCode).
				Str("decision", "auth_error").
				Int64("duration_ms", time.Since(start).Milliseconds()).
				Send()
		}
		return false, http.StatusBadGateway, "auth_error", fmt.Errorf("auth bridge returned %d", statusCode)
	}
	message := strings.TrimSpace(resp.GetMessage())
	if message == "" {
		message = fmt.Sprintf("auth bridge denied access with status %d", statusCode)
	}
	if decision == "" {
		decision = "denied"
	}
	if event := logger.DebugEvent("stream", "auth_verify_end"); event != nil {
		event.Int("status", statusCode).
			Bool("allowed", false).
			Str("decision", logger.SanitizeLogString(decision)).
			Str("message", logger.SanitizeLogString(message)).
			Int64("duration_ms", time.Since(start).Milliseconds()).
			Send()
	}
	return false, http.StatusForbidden, decision, errors.New(message)

}

func classifyStreamAuthBridgeFailure(err error) (string, int) {
	switch {
	case errors.Is(err, context.DeadlineExceeded) || isTimeoutErr(err):
		return "timeout", http.StatusGatewayTimeout
	case errors.Is(err, rpcbridge.ErrAuthBridgeQueueFull):
		return "queue_full", http.StatusServiceUnavailable
	case errors.Is(err, rpcbridge.ErrAuthBridgeDisconnected):
		return "disconnected", http.StatusServiceUnavailable
	case errors.Is(err, rpcbridge.ErrAuthBridgeUnavailable):
		return "bridge_unavailable", http.StatusServiceUnavailable
	case errors.Is(err, rpcbridge.ErrAuthBridgeInvalidResponse):
		return "invalid_response", http.StatusBadGateway
	default:
		return "internal", http.StatusBadGateway
	}
}

func relayBidirectional(client net.Conn, upstream net.Conn, meter *streamTrafficMeter) (uint64, uint64, error) {
	clientToUpstream := make(chan relayResult, 1)

	var recordIn, recordOut func(int)
	if meter != nil {
		recordIn = meter.recordIn
		recordOut = meter.recordOut
	}

	go func() {
		bytes, err := copyStream(upstream, client, recordIn)
		finishRelayDirection(upstream, client, err)
		clientToUpstream <- relayResult{bytes: bytes, err: err}
	}()

	bytesOut, upstreamToClientErr := copyStream(client, upstream, recordOut)
	finishRelayDirection(client, upstream, upstreamToClientErr)
	inResult := <-clientToUpstream

	firstErr := normalizeRelayError(upstreamToClientErr)
	if err := normalizeRelayError(inResult.err); firstErr == nil {
		firstErr = err
	}
	return inResult.bytes, bytesOut, firstErr
}

func finishRelayDirection(dst, src net.Conn, err error) {
	// Only EOF permits the peer to finish its reply through the other direction.
	// Inspect the raw error: resets and broken pipes are intentionally normalized
	// for logging, but must still unblock the other copy and release its resources.
	if err == nil || errors.Is(err, io.EOF) {
		closeWrite(dst)
		return
	}
	_ = dst.Close()
	_ = src.Close()
}

type countedConn struct {
	net.Conn
	onWrite func(n int)
}

func (c *countedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 && c.onWrite != nil {
		c.onWrite(n)
	}
	return n, err
}

func copyStream(dst net.Conn, src net.Conn, onWrite func(int)) (uint64, error) {
	counted := &countedConn{Conn: dst, onWrite: onWrite}
	buf := make([]byte, 32*1024)
	var written uint64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			wn, werr := counted.Write(buf[:n])
			if wn > 0 {
				written += uint64(wn)
			}
			if werr != nil {
				return written, werr
			}
			if wn != n {
				return written, io.ErrShortWrite
			}
		}
		if rerr != nil {
			// 返回原始读错误，由 relayBidirectional 统一 normalize（与原 io.Copy 语义一致）
			return written, rerr
		}
	}
}

func closeWrite(conn net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}

	if conn == nil {
		return
	}
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

func normalizeRelayError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}

	errText := err.Error()
	if containsFoldASCIIString(errText, "use of closed network connection") ||
		containsFoldASCIIString(errText, "connection reset by peer") ||
		containsFoldASCIIString(errText, "broken pipe") {
		return nil
	}

	return err
}

func extractRemoteIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}

	host, _, err := net.SplitHostPort(addr.String())
	if err == nil {
		return strings.TrimSpace(host)
	}
	return strings.TrimSpace(addr.String())
}

func addrString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return strings.TrimSpace(addr.String())
}

func ensureLeadingSlash(path string) string {
	if path == "" {
		return "/"
	}
	if strings.HasPrefix(path, "/") {
		return path
	}
	return "/" + path
}

const localServiceURLPrefix = "http://127.0.0.1:"

func localServiceURL(port int, urlPath string) string {
	urlPath = ensureLeadingSlash(urlPath)
	var stack [len(localServiceURLPrefix) + 20 + 128]byte
	buf := stack[:0]
	buf = append(buf, localServiceURLPrefix...)
	buf = strconv.AppendInt(buf, int64(port), 10)
	buf = append(buf, urlPath...)
	return string(buf)
}

func isClosedConnErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	return containsFoldASCIIString(err.Error(), "use of closed network connection")
}

func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func (m *Manager) normalizeRules(rules []models.StreamRule) ([]models.StreamRule, error) {
	normalized := make([]models.StreamRule, 0, len(rules))
	seenRules := make(map[streamRuleKey]struct{}, len(rules))

	for _, rule := range rules {
		nextRule, err := m.normalizeRule(rule)
		if err != nil {
			return nil, err
		}
		key := streamRuleKeyFromRule(nextRule)
		if _, exists := seenRules[key]; exists {
			return nil, fmt.Errorf("duplicate stream rule for %s", key.String())
		}
		seenRules[key] = struct{}{}
		normalized = append(normalized, nextRule)
	}

	return normalized, nil
}

func (m *Manager) normalizeRule(rule models.StreamRule) (models.StreamRule, error) {
	rule.Target = strings.TrimSpace(rule.Target)

	protocol, err := normalizeStreamProtocol(rule.Protocol)
	if err != nil {
		return models.StreamRule{}, err
	}
	rule.Protocol = protocol

	if rule.ListenPort <= 0 || rule.ListenPort > 65535 {
		return models.StreamRule{}, fmt.Errorf("listen_port must be between 1 and 65535")
	}
	if reservedName := m.reservedPortName(rule); reservedName != "" {
		return models.StreamRule{}, fmt.Errorf("listen_port %d is reserved for the %s", rule.ListenPort, reservedName)
	}
	if rule.Target == "" {
		return models.StreamRule{}, fmt.Errorf("target cannot be empty")
	}

	targetHost, targetPort, err := parseStreamTarget(rule.Target)
	if err != nil {
		return models.StreamRule{}, fmt.Errorf("invalid target: %v", err)
	}

	if rule.Protocol == models.StreamProtocolTCP && isLoopbackOrUnspecifiedHost(targetHost) {
		if adminPort := m.adminPort(); adminPort > 0 && targetPort == adminPort {
			return models.StreamRule{}, fmt.Errorf("invalid target: cannot target local admin port %d", adminPort)
		}
	}
	if isLoopbackOrUnspecifiedHost(targetHost) && rule.ListenPort == targetPort {
		return models.StreamRule{}, fmt.Errorf("listen_port %d cannot target the same local address %s", rule.ListenPort, rule.Target)
	}
	rule.ValidationMode = strings.ToLower(strings.TrimSpace(rule.ValidationMode))
	if rule.ValidationMode == "" {
		rule.ValidationMode = models.StreamValidationOff
	}
	if rule.ValidationMode != models.StreamValidationOff && rule.ValidationMode != models.StreamValidationStrict {
		return models.StreamRule{}, fmt.Errorf("validation_mode must be off or strict")
	}
	if rule.ValidationMode == models.StreamValidationStrict {
		rule.ServiceProfile.ServiceID = strings.ToLower(strings.TrimSpace(rule.ServiceProfile.ServiceID))
		rule.ServiceProfile.Source = strings.ToLower(strings.TrimSpace(rule.ServiceProfile.Source))
		rule.ServiceProfile.ServiceConfidence = strings.ToLower(strings.TrimSpace(rule.ServiceProfile.ServiceConfidence))
		rule.ProbeStatus = strings.ToLower(strings.TrimSpace(rule.ProbeStatus))
		if descriptor, _, _, known := streamprobe.Definition(rule.ServiceProfile.ServiceID); known {
			rule.ServiceProfile.StrictCapable = descriptor.StrictCapable
		}
		if strictErr := streamprobe.ValidateStrictProfile(
			rule.ServiceProfile,
			rule.Protocol,
			rule.Target,
			rule.ProbeStatus,
		); strictErr != nil && !rule.Disabled {
			return models.StreamRule{}, fmt.Errorf("invalid strict stream profile: %w", strictErr)
		}
	}

	return rule, nil
}

func (m *Manager) reservedPortName(rule models.StreamRule) string {
	if m == nil || m.handler == nil || rule.Protocol != models.StreamProtocolTCP {
		return ""
	}

	switch {
	case m.handler.AdminPort > 0 && rule.ListenPort == m.handler.AdminPort:
		return "admin API"
	case m.handler.ProxyPort > 0 && rule.ListenPort == m.handler.ProxyPort:
		return "reverse proxy"
	default:
		return ""
	}
}

func (m *Manager) adminPort() int {
	if m == nil || m.handler == nil {
		return 0
	}
	return m.handler.AdminPort
}

func parseStreamTarget(target string) (string, int, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(target))
	if err != nil {
		return "", 0, fmt.Errorf("target must be in host:port format")
	}

	if strings.TrimSpace(host) == "" {
		return "", 0, fmt.Errorf("target must include a valid hostname")
	}

	portNum, err := strconv.Atoi(port)
	if err != nil || portNum <= 0 || portNum > 65535 {
		return "", 0, fmt.Errorf("target must include a valid port")
	}

	return host, portNum, nil
}

func normalizeStreamProtocol(protocol string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "", models.StreamProtocolTCP:
		return models.StreamProtocolTCP, nil
	case models.StreamProtocolUDP:
		return models.StreamProtocolUDP, nil
	default:
		return "", fmt.Errorf("protocol must be tcp or udp")
	}
}

func fallbackStreamProtocol(protocol string) string {
	normalized := strings.ToLower(strings.TrimSpace(protocol))
	if normalized == "" {
		return models.StreamProtocolTCP
	}
	return normalized
}

func streamRuleKeyFromRule(rule models.StreamRule) streamRuleKey {
	return streamRuleKey{
		Protocol:   rule.Protocol,
		ListenPort: rule.ListenPort,
	}
}

func compareStreamRuleKeys(a streamRuleKey, b streamRuleKey) int {
	if a.Protocol < b.Protocol {
		return -1
	}
	if a.Protocol > b.Protocol {
		return 1
	}
	switch {
	case a.ListenPort < b.ListenPort:
		return -1
	case a.ListenPort > b.ListenPort:
		return 1
	default:
		return 0
	}
}

func newStreamEntry(key streamRuleKey, remoteAddr string, clientIP string) gatewaylog.Entry {
	return gatewaylog.Entry{
		Method:       "STREAM",
		Protocol:     key.Protocol,
		Status:       http.StatusOK,
		RemoteAddr:   remoteAddr,
		RemoteIP:     clientIP,
		RouteType:    "stream_rule",
		RouteKey:     key.String(),
		Matched:      true,
		AuthDecision: "bypassed",
	}
}

type streamTrafficMeter struct {
	recorder *proxy.StreamTrafficRecorder
}

func newStreamTrafficMeter(h *proxy.Handler, key streamRuleKey) *streamTrafficMeter {
	return &streamTrafficMeter{
		recorder: h.NewStreamTrafficRecorder(key.Protocol, key.ListenPort),
	}
}

func (s *streamTrafficMeter) activate(clientIP string, now time.Time) {
	if s == nil || s.recorder == nil {
		return
	}
	s.recorder.Activate(clientIP, now)
}

func (s *streamTrafficMeter) recordIn(n int) {
	if n <= 0 {
		return
	}
	s.recorder.Add(uint64(n), 0, 0)
}

func (s *streamTrafficMeter) recordOut(n int) {
	if n <= 0 {
		return
	}
	s.recorder.Add(0, uint64(n), 0)
}

func (s *streamTrafficMeter) finalize(status int) {
	if s == nil || s.recorder == nil {
		return
	}
	s.recorder.Finalize(status, time.Now())
}

func (m *Manager) logStreamEntry(entry gatewaylog.Entry, key streamRuleKey, start time.Time, meter *streamTrafficMeter) {
	entry.DurationMs = time.Since(start).Milliseconds()
	if meter != nil {
		meter.finalize(entry.Status)
	} else {
		m.handler.AddStreamTraffic(key.Protocol, key.ListenPort, entry.BytesIn, entry.BytesOut, entry.Status)
	}
	m.handler.LogGatewayEntry(entry)
}

func isLoopbackOrUnspecifiedHost(host string) bool {
	normalizedHost := strings.TrimSpace(strings.Trim(host, "[]"))
	if normalizedHost == "" {
		return false
	}
	if strings.EqualFold(normalizedHost, "localhost") {
		return true
	}

	parsedIP := net.ParseIP(normalizedHost)
	return parsedIP != nil && (parsedIP.IsLoopback() || parsedIP.IsUnspecified())
}

func isAddrInUseErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	return containsFoldASCIIString(err.Error(), "address already in use")
}
