package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
)

type trafficReadCloser struct {
	io.ReadCloser
	handler *Handler
	metrics *requestTrafficMetrics
}

func (trc *trafficReadCloser) Read(p []byte) (int, error) {
	n, err := trc.ReadCloser.Read(p)
	if n > 0 {
		trc.metrics.addIn(trc.handler, uint64(n))
	}
	return n, err
}

type trafficResponseWriter struct {
	http.ResponseWriter
	handler            *Handler
	traceID            string
	metrics            requestTrafficMetrics
	deepMonitor        *deepMonitorRequest
	skipAccessLog      bool
	upstreamErrorClass string
}

func (tw *trafficResponseWriter) WriteHeader(statusCode int) {
	if tw.traceID != "" {
		tw.Header().Set(traceIDHeader, tw.traceID)
	}
	if !tw.metrics.wroteHeader {
		tw.metrics.wroteHeader = true
		tw.metrics.statusCode = statusCode
		if tw.deepMonitor != nil {
			tw.deepMonitor.captureClientHeader(tw.Header())
		}
	}
	tw.ResponseWriter.WriteHeader(statusCode)
}

func (tw *trafficResponseWriter) Write(p []byte) (int, error) {
	if !tw.metrics.wroteHeader {
		tw.WriteHeader(http.StatusOK)
	}
	n, err := tw.ResponseWriter.Write(p)
	if n > 0 {
		tw.metrics.addOut(tw.handler, uint64(n))
		if tw.deepMonitor != nil {
			tw.deepMonitor.captureClientBody(p[:n])
		}
	}
	return n, err
}

func (tw *trafficResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := tw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hj.Hijack()
}

func (tw *trafficResponseWriter) Flush() {
	if !tw.metrics.wroteHeader {
		tw.WriteHeader(http.StatusOK)
	}
	if fl, ok := tw.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}

func (tw *trafficResponseWriter) Push(target string, opts *http.PushOptions) error {
	ps, ok := tw.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return ps.Push(target, opts)
}

func (tw *trafficResponseWriter) SuppressAccessLog() {
	tw.skipAccessLog = true
}

type accessLogSuppressor interface {
	SuppressAccessLog()
}

func suppressAccessLog(w http.ResponseWriter) {
	if suppressor, ok := w.(accessLogSuppressor); ok {
		suppressor.SuppressAccessLog()
	}
}

func wrapRequestBodyForTraffic(r *http.Request, h *Handler, metrics *requestTrafficMetrics) {
	if r == nil || r.Body == nil || r.Body == http.NoBody {
		return
	}
	if _, ok := r.Body.(*trafficReadCloser); ok {
		return
	}
	r.Body = &trafficReadCloser{ReadCloser: r.Body, handler: h, metrics: metrics}
}
