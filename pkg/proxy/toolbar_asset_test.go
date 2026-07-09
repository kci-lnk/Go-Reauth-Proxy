package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go-reauth-proxy/pkg/response"
)

func TestHandlerServesReservedToolbarAsset(t *testing.T) {
	handler := &Handler{
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.test"+response.ToolbarAssetPath(), nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "public,max-age=31536000,immutable" {
		t.Fatalf("Cache-Control = %q", got)
	}
}
