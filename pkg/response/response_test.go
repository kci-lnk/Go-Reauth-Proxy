package response

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

var responseBenchmarkBytesSink []byte

func TestAppendJSONResponseNoDataMatchesEncodingJSON(t *testing.T) {
	tests := []struct {
		name    string
		success bool
		code    int
		message string
	}{
		{name: "plain", success: false, code: 400, message: "Invalid JSON object"},
		{name: "quotes and slash", success: false, code: 500, message: `bad "token" \ path`},
		{name: "html escaped", success: false, code: 403, message: "<script>&denied</script>"},
		{name: "controls", success: false, code: 500, message: "line\nnext\t\u0001"},
		{name: "unicode separators", success: true, code: 200, message: "line\u2028para\u2029"},
		{name: "invalid utf8", success: false, code: 500, message: string([]byte{'b', 'a', 'd', 0xff})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := appendJSONResponseNoData(nil, tt.success, tt.code, tt.message, 123456789)
			want := legacyJSONResponseNoDataForTest(t, tt.success, tt.code, tt.message, 123456789)
			if !bytes.Equal(got, want) {
				t.Fatalf("JSON mismatch\ngot:  %s\nwant: %s", got, want)
			}
		})
	}
}

func TestJSONNoDataResponseDecodes(t *testing.T) {
	rec := httptest.NewRecorder()
	JSON(rec, false, 10003, "Invalid JSON object", nil)

	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var body Response
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	if body.Success || body.Code != 10003 || body.Message != "Invalid JSON object" || body.Data != nil || body.Timestamp <= 0 {
		t.Fatalf("unexpected response body: %#v", body)
	}
}

func BenchmarkAppendJSONResponseNoData(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		responseBenchmarkBytesSink = appendJSONResponseNoData(nil, false, 10003, "Invalid JSON object", 123456789)
	}
}

func BenchmarkAppendJSONResponseNoDataOld(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		responseBenchmarkBytesSink = legacyJSONResponseNoDataForBenchmark(false, 10003, "Invalid JSON object", 123456789)
	}
}

func legacyJSONResponseNoDataForTest(t testing.TB, success bool, code int, message string, timestamp int64) []byte {
	t.Helper()
	out := legacyJSONResponseNoDataForBenchmark(success, code, message, timestamp)
	if len(out) == 0 {
		t.Fatal("legacy response is empty")
	}
	return out
}

func legacyJSONResponseNoDataForBenchmark(success bool, code int, message string, timestamp int64) []byte {
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(Response{
		Success:   success,
		Code:      code,
		Message:   message,
		Data:      nil,
		Timestamp: timestamp,
	})
	return buf.Bytes()
}
