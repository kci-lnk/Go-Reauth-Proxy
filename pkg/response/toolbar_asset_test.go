package response

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go-reauth-proxy/pkg/models"
)

func TestToolbarRuntimeUsesContentAddressedAsset(t *testing.T) {
	digest := sha256.Sum256(toolbarRuntime)
	wantPath := "/__assets__/toolbar/toolbar." + hex.EncodeToString(digest[:]) + ".js"
	if got := ToolbarAssetPath(); got != wantPath {
		t.Fatalf("ToolbarAssetPath() = %q, want %q", got, wantPath)
	}
	if !IsToolbarAssetPath(wantPath) || IsToolbarAssetPath(wantPath+".old") {
		t.Fatal("IsToolbarAssetPath did not require the exact content-addressed path")
	}
}

func TestGenerateToolbarInjectsOnlyPayloadAndRuntimeLoader(t *testing.T) {
	toolbar := GenerateToolbarWithHosts(
		[]models.Rule{{Path: "/app", Target: "http://127.0.0.1:3000"}},
		nil,
		"/app",
		"",
		"",
		models.GatewayPortalConfig{},
	)

	if !strings.Contains(toolbar, ToolbarAssetPath()) {
		t.Fatalf("toolbar loader does not reference runtime asset: %s", toolbar)
	}
	if strings.Contains(toolbar, "container.attachShadow") {
		t.Fatal("toolbar HTML still embeds the static runtime")
	}
	if len(toolbar) >= len(toolbarRuntime) {
		t.Fatalf("toolbar loader size = %d, runtime size = %d", len(toolbar), len(toolbarRuntime))
	}
}

func TestServeToolbarAssetIsImmutableJavaScript(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.test"+ToolbarAssetPath(), nil)
	rec := httptest.NewRecorder()

	ServeToolbarAsset(rec, req)
	result := rec.Result()
	defer result.Body.Close()
	body, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("read toolbar asset: %v", err)
	}
	if result.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", result.StatusCode)
	}
	if got := result.Header.Get("Cache-Control"); got != toolbarAssetCacheControl {
		t.Fatalf("Cache-Control = %q, want %q", got, toolbarAssetCacheControl)
	}
	if got := result.Header.Get("Content-Type"); got != "text/javascript; charset=utf-8" {
		t.Fatalf("Content-Type = %q", got)
	}
	if string(body) != string(toolbarRuntime) {
		t.Fatal("served toolbar runtime differs from hashed content")
	}
}
