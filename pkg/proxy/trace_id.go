package proxy

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"net/http"
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
