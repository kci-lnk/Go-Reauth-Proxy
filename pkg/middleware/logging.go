package middleware

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

type LogEntry struct {
	Time      string `json:"time"`
	Level     string `json:"level"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	Duration  string `json:"duration"`
	UserAgent string `json:"user_agent"`
	RemoteIP  string `json:"remote_ip"`
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := rw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("the ResponseWriter doesn't support the Hijacker interface")
	}
	return hijacker.Hijack()
}

func (rw *responseWriter) Flush() {
	if flusher, ok := rw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)

		duration := time.Since(start)

		entry := LogEntry{
			Time:      start.Format(time.RFC3339),
			Level:     "INFO",
			Method:    r.Method,
			Path:      r.URL.Path,
			Status:    rw.status,
			Duration:  duration.String(),
			UserAgent: r.UserAgent(),
			RemoteIP:  r.RemoteAddr,
		}

		if rw.status >= 400 {
			entry.Level = "ERROR"
		}
		jsonBytes, _ := json.Marshal(entry)
		fmt.Println(string(jsonBytes))
	})
}
