package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go-reauth-proxy/pkg/logger"
)

func TestCORSOptionsReturnsOKWithoutCallingNext(t *testing.T) {
	called := false
	handler := CORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodOptions, "/api", nil))

	if rec.Code != http.StatusOK || called {
		t.Fatalf("OPTIONS status=%d called=%v", rec.Code, called)
	}
}

func TestCORSGetCallsNextHandler(t *testing.T) {
	handler := CORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api", nil))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}
}

func TestCORSAllowsAllOrigins(t *testing.T) {
	handler := CORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api", nil))

	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("allow origin = %q", rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCORSAllowsExpectedMethods(t *testing.T) {
	handler := CORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api", nil))

	if got := rec.Header().Get("Access-Control-Allow-Methods"); got != "POST, GET, OPTIONS, PUT, DELETE" {
		t.Fatalf("allow methods = %q", got)
	}
}

func TestCORSAllowsAuthorizationHeader(t *testing.T) {
	handler := CORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api", nil))

	if got := rec.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "Authorization") {
		t.Fatalf("allow headers missing Authorization: %q", got)
	}
}

func TestResponseWriterWriteHeaderRecordsStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: rec, status: http.StatusOK}

	rw.WriteHeader(http.StatusAccepted)

	if rw.status != http.StatusAccepted || rec.Code != http.StatusAccepted {
		t.Fatalf("status not recorded: rw=%d rec=%d", rw.status, rec.Code)
	}
}

func TestResponseWriterFlushWithoutFlusherDoesNotPanic(t *testing.T) {
	rw := &responseWriter{ResponseWriter: httptest.NewRecorder(), status: http.StatusOK}

	rw.Flush()
}

func TestResponseWriterHijackUnsupportedReturnsError(t *testing.T) {
	rw := &responseWriter{ResponseWriter: httptest.NewRecorder(), status: http.StatusOK}

	conn, bufrw, err := rw.Hijack()

	if err == nil || conn != nil || bufrw != nil {
		t.Fatalf("expected unsupported hijack error, conn=%v bufrw=%v err=%v", conn, bufrw, err)
	}
}

func TestLoggerRecordsWarnLevelForClientErrors(t *testing.T) {
	t.Setenv(AdminHTTPLogEnv, "1")
	t.Setenv(logger.ConsoleLogEnv, "")
	var buf bytes.Buffer
	restoreLogger(t, &buf)

	handler := Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if got := buf.String(); !strings.Contains(got, `"level":"warn"`) || !strings.Contains(got, `"status":404`) {
		t.Fatalf("expected warn log for 404, got %q", got)
	}
}

func TestLoggerRecordsErrorLevelForServerErrors(t *testing.T) {
	t.Setenv(AdminHTTPLogEnv, "1")
	t.Setenv(logger.ConsoleLogEnv, "")
	var buf bytes.Buffer
	restoreLogger(t, &buf)

	handler := Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	req := httptest.NewRequest(http.MethodGet, "/boom", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if got := buf.String(); !strings.Contains(got, `"level":"error"`) || !strings.Contains(got, `"status":500`) {
		t.Fatalf("expected error log for 500, got %q", got)
	}
}

func TestLoggerDefaultsStatusOKWhenHandlerDoesNotWriteHeader(t *testing.T) {
	t.Setenv(AdminHTTPLogEnv, "1")
	t.Setenv(logger.ConsoleLogEnv, "")
	var buf bytes.Buffer
	restoreLogger(t, &buf)

	handler := Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if got := buf.String(); !strings.Contains(got, `"status":200`) {
		t.Fatalf("expected default status 200 log, got %q", got)
	}
}

func TestLoggerKeepsRemoteAddrWhenSplitFails(t *testing.T) {
	t.Setenv(AdminHTTPLogEnv, "1")
	t.Setenv(logger.ConsoleLogEnv, "")
	var buf bytes.Buffer
	restoreLogger(t, &buf)

	handler := Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	req.RemoteAddr = "not-a-host-port"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if got := buf.String(); !strings.Contains(got, `"remote_ip":"not-a-host-port"`) {
		t.Fatalf("expected unsplit remote addr in log, got %q", got)
	}
}

func TestAdminHTTPLoggingEnabledFalseWhenEnvsUnset(t *testing.T) {
	t.Setenv(AdminHTTPLogEnv, "")
	t.Setenv(logger.ConsoleLogEnv, "")

	if adminHTTPLoggingEnabled() {
		t.Fatal("admin HTTP logging should be disabled")
	}
}

func TestAdminHTTPLoggingEnabledTrueForAdminEnv(t *testing.T) {
	t.Setenv(AdminHTTPLogEnv, "true")
	t.Setenv(logger.ConsoleLogEnv, "")

	if !adminHTTPLoggingEnabled() {
		t.Fatal("admin HTTP logging should be enabled by admin env")
	}
}

func TestAdminHTTPLoggingEnabledTrueForConsoleEnv(t *testing.T) {
	t.Setenv(AdminHTTPLogEnv, "")
	t.Setenv(logger.ConsoleLogEnv, "true")

	if !adminHTTPLoggingEnabled() {
		t.Fatal("admin HTTP logging should be enabled by console env")
	}
}
