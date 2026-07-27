package response

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
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

func TestToolbarV2RuntimeUsesDistinctContentAddressedAsset(t *testing.T) {
	digest := sha256.Sum256(toolbarV2Runtime)
	wantPath := "/__assets__/toolbar/toolbar-v2." + hex.EncodeToString(digest[:]) + ".js"
	if got := ToolbarAssetPathForVersion(models.GatewayPortalVersionV2); got != wantPath {
		t.Fatalf("ToolbarAssetPathForVersion(v2) = %q, want %q", got, wantPath)
	}
	if wantPath == ToolbarAssetPath() {
		t.Fatal("v2 toolbar asset path must differ from v1")
	}
	if !IsToolbarAssetPath(wantPath) {
		t.Fatal("IsToolbarAssetPath rejected the v2 content-addressed path")
	}
}

func TestToolbarV2RuntimeKeepsFixedDesktopScaleAndCoversTabletViewport(t *testing.T) {
	runtime := string(toolbarV2Runtime)
	for _, expected := range []string{
		"width: min(844px, calc(100vw - 96px), 132dvh)",
		"aspect-ratio: 844 / 577",
		"grid-template-columns: repeat(7, minmax(0, 1fr))",
		"width: 60px",
		"font-size: 12px",
		"@media (max-width: 768px)",
	} {
		if !strings.Contains(runtime, expected) {
			t.Fatalf("v2 runtime is missing responsive invariant %q", expected)
		}
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

func TestGenerateToolbarV2SelectsV2RuntimeLoader(t *testing.T) {
	toolbar := GenerateToolbarWithHosts(
		nil,
		[]models.HostRule{{Host: "app.example.com", Target: "http://127.0.0.1:3000"}},
		"",
		"",
		"",
		models.GatewayPortalConfig{Version: models.GatewayPortalVersionV2},
	)
	if !strings.Contains(toolbar, ToolbarAssetPathForVersion(models.GatewayPortalVersionV2)) {
		t.Fatalf("v2 toolbar loader does not reference v2 runtime: %s", toolbar)
	}
	if strings.Contains(toolbar, ToolbarAssetPath()) {
		t.Fatalf("v2 toolbar loader references v1 runtime: %s", toolbar)
	}
}

func TestGenerateToolbarV2PreservesEscapedGroupMetadataAndLabels(t *testing.T) {
	toolbar := GenerateToolbarWithPrefilteredHostsForLocale(
		"zh-CN",
		nil,
		[]models.HostRule{{
			Host:      "app.example.com",
			Title:     `应用</script>`,
			GroupID:   `tools"internal`,
			GroupName: `工具</script>`,
		}},
		"",
		"app.example.com",
		"",
		models.GatewayPortalConfig{
			DisplayStyle: models.GatewayPortalDisplayStyleTitle,
			Version:      models.GatewayPortalVersionV2,
		},
	)
	if !strings.HasPrefix(toolbar, toolbarV2TemplatePrefix) || !strings.HasSuffix(toolbar, toolbarV2TemplateSuffix) {
		t.Fatalf("v2 toolbar does not use the v2 template wrapper: %s", toolbar)
	}
	if count := strings.Count(toolbar, "</script>"); count != 1 {
		t.Fatalf("v2 toolbar contains %d raw closing script tags, want only wrapper close: %s", count, toolbar)
	}

	var payload struct {
		HostRules []struct {
			Label     string `json:"label"`
			GroupID   string `json:"group_id"`
			GroupName string `json:"group_name"`
		} `json:"host_rules"`
		Labels toolbarLabels `json:"labels"`
	}
	raw := toolbar[len(toolbarV2TemplatePrefix) : len(toolbar)-len(toolbarV2TemplateSuffix)]
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("v2 toolbar payload is not valid JSON: %v\n%s", err, toolbar)
	}
	if len(payload.HostRules) != 1 ||
		payload.HostRules[0].Label != `应用</script>` ||
		payload.HostRules[0].GroupID != `tools"internal` ||
		payload.HostRules[0].GroupName != `工具</script>` {
		t.Fatalf("unexpected v2 host metadata: %#v", payload.HostRules)
	}
	if payload.Labels.Applications != "应用程序" || payload.Labels.All != "全部" {
		t.Fatalf("unexpected v2 launchpad labels: %#v", payload.Labels)
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

func TestServeToolbarV2AssetIsImmutableJavaScript(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.test"+ToolbarAssetPathForVersion(models.GatewayPortalVersionV2), nil)
	rec := httptest.NewRecorder()

	ServeToolbarAsset(rec, req)
	result := rec.Result()
	defer result.Body.Close()
	body, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("read v2 toolbar asset: %v", err)
	}
	if result.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", result.StatusCode)
	}
	if string(body) != string(toolbarV2Runtime) {
		t.Fatal("served v2 toolbar runtime differs from hashed content")
	}
}

func TestToolbarV2RuntimeIsValidJavaScript(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed")
	}
	cmd := exec.Command("node", "--check")
	cmd.Stdin = strings.NewReader(string(toolbarV2Runtime))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("v2 toolbar runtime is invalid JavaScript: %v\n%s", err, output)
	}
}
