package proxy

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

const traceIDHeader = "X-Fn-Knock-Trace-ID"

type requestTraceIDContextKey struct{}

var traceIDFallbackCounter atomic.Uint64

func newRequestTraceID() string {
	var uuid [16]byte
	if _, err := rand.Read(uuid[:]); err != nil {
		binary.BigEndian.PutUint64(uuid[0:8], uint64(time.Now().UnixNano()))
		binary.BigEndian.PutUint64(uuid[8:16], traceIDFallbackCounter.Add(1))
	}
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80

	var buf [40]byte
	copy(buf[:], "trc_")
	hex.Encode(buf[4:12], uuid[0:4])
	buf[12] = '-'
	hex.Encode(buf[13:17], uuid[4:6])
	buf[17] = '-'
	hex.Encode(buf[18:22], uuid[6:8])
	buf[22] = '-'
	hex.Encode(buf[23:27], uuid[8:10])
	buf[27] = '-'
	hex.Encode(buf[28:40], uuid[10:16])
	return string(buf[:])
}

func withRequestTraceID(r *http.Request, traceID string) *http.Request {
	if r == nil {
		return nil
	}
	return r.WithContext(context.WithValue(r.Context(), requestTraceIDContextKey{}, traceID))
}

func requestTraceID(r *http.Request) string {
	if r == nil {
		return ""
	}
	traceID, _ := r.Context().Value(requestTraceIDContextKey{}).(string)
	return traceID
}

func stripTraceResponseHeaders(header http.Header) {
	for name, values := range header {
		if isTraceResponseHeader(name) {
			delete(header, name)
			continue
		}
		if strings.EqualFold(name, "Trailer") {
			values = stripTraceTrailerNames(values)
			if len(values) == 0 {
				delete(header, name)
			} else {
				header[name] = values
			}
		}
	}
}

func isTraceResponseHeader(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimSpace(strings.TrimPrefix(name, strings.ToLower(http.TrailerPrefix)))
	if strings.Contains(name, "trace") {
		return true
	}

	// B3 and OpenTracing also use span-only header names that belong to the
	// same distributed-tracing context as their trace ID.
	switch name {
	case "b3", "x-b3-spanid", "x-b3-parentspanid", "x-b3-sampled", "x-b3-flags", "x-ot-span-context":
		return true
	default:
		return false
	}
}

func stripTraceTrailerNames(values []string) []string {
	kept := values[:0]
	for _, value := range values {
		for _, name := range strings.Split(value, ",") {
			name = strings.TrimSpace(name)
			if name != "" && !isTraceResponseHeader(name) {
				kept = append(kept, name)
			}
		}
	}
	return kept
}
