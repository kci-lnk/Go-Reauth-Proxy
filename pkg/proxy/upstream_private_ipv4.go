package proxy

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	upstreamPrivateIPv4HeaderName    = "X-Reauth-Upstream-Private-IPv4"
	upstreamPrivateIPv4CacheTTL      = 30 * time.Second
	upstreamPrivateIPv4LookupTimeout = 300 * time.Millisecond
)

var (
	privateIPv4Detector         = newPreferredPrivateIPv4Detector(upstreamPrivateIPv4CacheTTL, detectPreferredPrivateIPv4)
	hostnamePrivateIPv4Resolver = newCachedPrivateIPv4Resolver(upstreamPrivateIPv4CacheTTL, lookupHostnamePrivateIPv4)
)

type preferredPrivateIPv4Detector struct {
	ttl        time.Duration
	detect     func() string
	value      atomic.Pointer[cachedPrivateIPv4Entry]
	refreshing atomic.Bool
}

type cachedPrivateIPv4Resolver struct {
	ttl             time.Duration
	resolve         func(string) string
	entries         sync.Map
	lastCleanupNano atomic.Int64
}

type cachedPrivateIPv4Entry struct {
	value     string
	expiresAt time.Time
}

type cachedPrivateIPv4ResolverEntry struct {
	value      atomic.Pointer[cachedPrivateIPv4Entry]
	refreshing atomic.Bool
}

func newPreferredPrivateIPv4Detector(ttl time.Duration, detect func() string) *preferredPrivateIPv4Detector {
	if ttl <= 0 {
		ttl = upstreamPrivateIPv4CacheTTL
	}
	if detect == nil {
		detect = detectPreferredPrivateIPv4
	}
	return &preferredPrivateIPv4Detector{
		ttl:    ttl,
		detect: detect,
	}
}

func (d *preferredPrivateIPv4Detector) get() string {
	entry := d.value.Load()
	if entry == nil || !entry.expiresAt.After(time.Now()) {
		d.refreshAsync()
	}
	if entry == nil {
		return ""
	}
	return entry.value
}

func (d *preferredPrivateIPv4Detector) refreshAsync() {
	if d == nil || !d.refreshing.CompareAndSwap(false, true) {
		return
	}
	if entry := d.value.Load(); entry != nil && entry.expiresAt.After(time.Now()) {
		d.refreshing.Store(false)
		return
	}
	go func() {
		defer d.refreshing.Store(false)
		d.value.Store(&cachedPrivateIPv4Entry{
			value:     d.detect(),
			expiresAt: time.Now().Add(d.ttl),
		})
	}()
}

func newCachedPrivateIPv4Resolver(ttl time.Duration, resolve func(string) string) *cachedPrivateIPv4Resolver {
	if ttl <= 0 {
		ttl = upstreamPrivateIPv4CacheTTL
	}
	if resolve == nil {
		resolve = func(string) string { return "" }
	}
	return &cachedPrivateIPv4Resolver{ttl: ttl, resolve: resolve}
}

func (r *cachedPrivateIPv4Resolver) get(hostname string) string {
	key := normalizeUpstreamHostname(hostname)
	if key == "" {
		return ""
	}

	holder := r.loadEntry(key)
	entry := holder.value.Load()
	now := time.Now()
	if entry == nil || !entry.expiresAt.After(now) {
		r.refreshAsync(key, holder)
	}
	r.cleanupExpiredAsync(now)
	if entry == nil {
		return ""
	}
	return entry.value
}

func (r *cachedPrivateIPv4Resolver) loadEntry(key string) *cachedPrivateIPv4ResolverEntry {
	if value, ok := r.entries.Load(key); ok {
		return value.(*cachedPrivateIPv4ResolverEntry)
	}
	candidate := &cachedPrivateIPv4ResolverEntry{}
	actual, _ := r.entries.LoadOrStore(key, candidate)
	return actual.(*cachedPrivateIPv4ResolverEntry)
}

func (r *cachedPrivateIPv4Resolver) refreshAsync(key string, holder *cachedPrivateIPv4ResolverEntry) {
	if holder == nil || !holder.refreshing.CompareAndSwap(false, true) {
		return
	}
	if entry := holder.value.Load(); entry != nil && entry.expiresAt.After(time.Now()) {
		holder.refreshing.Store(false)
		return
	}

	go func() {
		defer holder.refreshing.Store(false)
		holder.value.Store(&cachedPrivateIPv4Entry{
			value:     r.resolve(key),
			expiresAt: time.Now().Add(r.ttl),
		})
	}()
}

func (r *cachedPrivateIPv4Resolver) cleanupExpiredAsync(now time.Time) {
	interval := r.ttl
	if interval <= 0 {
		interval = upstreamPrivateIPv4CacheTTL
	}
	nowNano := now.UnixNano()
	last := r.lastCleanupNano.Load()
	if last > 0 && nowNano-last < int64(interval) {
		return
	}
	if !r.lastCleanupNano.CompareAndSwap(last, nowNano) {
		return
	}
	go func(cutoff time.Time, staleFor time.Duration) {
		r.entries.Range(func(key, value any) bool {
			holder, ok := value.(*cachedPrivateIPv4ResolverEntry)
			if !ok || holder == nil {
				r.entries.CompareAndDelete(key, value)
				return true
			}
			if holder.refreshing.Load() {
				return true
			}
			entry := holder.value.Load()
			if entry == nil || entry.expiresAt.Add(staleFor).Before(cutoff) {
				r.entries.CompareAndDelete(key, holder)
			}
			return true
		})
	}(now, interval)
}

func applyUpstreamPrivateIPv4HintHeader(out *http.Request, targetURL *url.URL) {
	if out == nil {
		return
	}

	if hint := resolveUpstreamPrivateIPv4Hint(targetURL); hint != "" {
		out.Header.Set(upstreamPrivateIPv4HeaderName, hint)
		return
	}

	out.Header.Del(upstreamPrivateIPv4HeaderName)
}

func resolveUpstreamPrivateIPv4Hint(targetURL *url.URL) string {
	if targetURL == nil {
		return ""
	}

	hostname := normalizeUpstreamHostname(targetURL.Hostname())
	if hostname == "" {
		return ""
	}

	if isUsablePrivateIPv4(hostname) {
		return hostname
	}

	if isLoopbackOrLocalHostname(hostname) {
		return privateIPv4Detector.get()
	}

	return hostnamePrivateIPv4Resolver.get(hostname)
}

func lookupHostnamePrivateIPv4(hostname string) string {
	ctx, cancel := context.WithTimeout(context.Background(), upstreamPrivateIPv4LookupTimeout)
	defer cancel()

	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return ""
	}

	for _, item := range addresses {
		if ip := normalizeIPv4(item.IP); ip != "" && isUsablePrivateIPv4(ip) {
			return ip
		}
	}

	return ""
}

func normalizeUpstreamHostname(value string) string {
	normalized := strings.TrimSpace(strings.ToLower(value))
	return strings.TrimSuffix(normalized, ".")
}

func detectPreferredPrivateIPv4() string {
	for _, remoteAddr := range []string{"1.1.1.1:53", "8.8.8.8:53"} {
		if ip := detectOutboundPrivateIPv4(remoteAddr); ip != "" {
			return ip
		}
	}

	return detectInterfacePrivateIPv4()
}

func detectOutboundPrivateIPv4(remoteAddr string) string {
	conn, err := net.Dial("udp4", remoteAddr)
	if err != nil {
		return ""
	}
	defer conn.Close()

	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || udpAddr == nil {
		return ""
	}

	ip := normalizeIPv4(udpAddr.IP)
	if !isUsablePrivateIPv4(ip) {
		return ""
	}

	return ip
}

func detectInterfacePrivateIPv4() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	sort.Slice(interfaces, func(i, j int) bool {
		return interfaces[i].Name < interfaces[j].Name
	})

	for _, iface := range interfaces {
		if shouldSkipPrivateIPv4Interface(iface.Name) {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch value := addr.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			default:
				continue
			}

			normalized := normalizeIPv4(ip)
			if isUsablePrivateIPv4(normalized) {
				return normalized
			}
		}
	}

	return ""
}

func shouldSkipPrivateIPv4Interface(name string) bool {
	normalized := strings.TrimSpace(strings.ToLower(name))
	if normalized == "" {
		return true
	}

	for _, prefix := range []string{
		"lo",
		"docker",
		"br-",
		"veth",
		"tailscale",
		"zt",
		"tun",
		"tap",
		"wg",
		"vmnet",
	} {
		if strings.HasPrefix(normalized, prefix) {
			return true
		}
	}

	return false
}

func isLoopbackOrLocalHostname(value string) bool {
	normalized := strings.TrimSpace(strings.ToLower(value))
	if normalized == "" {
		return false
	}

	if normalized == "localhost" {
		return true
	}

	ip := net.ParseIP(normalized)
	return ip != nil && ip.IsLoopback()
}

func normalizeIPv4(value net.IP) string {
	if value == nil {
		return ""
	}

	ipv4 := value.To4()
	if ipv4 == nil {
		return ""
	}

	return ipv4.String()
}

func isUsablePrivateIPv4(value string) bool {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return false
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return false
	}

	if ipv4[0] == 10 {
		return true
	}
	if ipv4[0] == 172 && ipv4[1] >= 16 && ipv4[1] <= 31 {
		return true
	}
	if ipv4[0] == 192 && ipv4[1] == 168 {
		return true
	}

	return false
}
