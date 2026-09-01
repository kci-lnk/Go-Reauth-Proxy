package response

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
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

func TestToolbarBootstrapUsesContentAddressedAssetWithoutDynamicData(t *testing.T) {
	digest := sha256.Sum256(toolbarBootstrapRuntime)
	wantPath := "/__assets__/toolbar/bootstrap." + hex.EncodeToString(digest[:]) + ".js"
	if got := ToolbarBootstrapAssetPath(); got != wantPath {
		t.Fatalf("ToolbarBootstrapAssetPath() = %q, want %q", got, wantPath)
	}
	if !IsToolbarAssetPath(wantPath) || IsToolbarAssetPath(wantPath+".old") {
		t.Fatal("bootstrap asset path matching is not exact")
	}

	loader := GenerateToolbarBootstrap()
	for _, expected := range []string{wantPath, ToolbarDataPath(), `id="reauth-proxy-toolbar-bootstrap"`} {
		if !strings.Contains(loader, expected) {
			t.Fatalf("bootstrap loader is missing %q: %s", expected, loader)
		}
	}
	for _, forbidden := range []string{"data-toolbar", `"rules"`, "dns-prefetch"} {
		if strings.Contains(loader, forbidden) {
			t.Fatalf("bootstrap loader contains dynamic toolbar detail %q: %s", forbidden, loader)
		}
	}
	for _, expected := range []string{
		"credentials: 'same-origin'",
		"cache: 'no-store'",
		"response.status === 204",
		"payload.runtime_url",
		"JSON.stringify(payload.data)",
		"[0-9a-f]{64}",
		"X-Reauth-Toolbar-Page-Query",
	} {
		if !strings.Contains(string(toolbarBootstrapRuntime), expected) {
			t.Fatalf("bootstrap runtime is missing %q", expected)
		}
	}
	if !IsToolbarDataPath(ToolbarDataPath()) || IsToolbarDataPath(ToolbarDataPath()+"/extra") {
		t.Fatal("toolbar data path matching is not exact")
	}
}

func TestGenerateToolbarDataSelectsRuntimeAndPreservesPayloadShape(t *testing.T) {
	body := GenerateToolbarDataWithPrefilteredHostsForLocale(
		"zh-CN",
		[]models.Rule{{Path: "/app"}},
		[]models.HostRule{{Host: "app.example.com", Title: "应用"}},
		"/app",
		"app.example.com",
		"",
		models.GatewayPortalConfig{
			Version:      models.GatewayPortalVersionV2,
			DisplayStyle: models.GatewayPortalDisplayStyleTitle,
		},
	)
	var payload struct {
		RuntimeURL string `json:"runtime_url"`
		Data       struct {
			Rules []struct {
				Path string `json:"path"`
			} `json:"rules"`
			HostRules []struct {
				Host  string `json:"host"`
				Label string `json:"label"`
			} `json:"host_rules"`
			CurrentPath string        `json:"current_path"`
			CurrentHost string        `json:"current_host"`
			Labels      toolbarLabels `json:"labels"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("toolbar data is not valid JSON: %v\n%s", err, body)
	}
	if payload.RuntimeURL != ToolbarAssetPathForVersion(models.GatewayPortalVersionV2) {
		t.Fatalf("runtime_url = %q", payload.RuntimeURL)
	}
	if len(payload.Data.Rules) != 1 || payload.Data.Rules[0].Path != "/app" ||
		len(payload.Data.HostRules) != 1 || payload.Data.HostRules[0].Label != "应用" ||
		payload.Data.CurrentPath != "/app" || payload.Data.CurrentHost != "app.example.com" ||
		payload.Data.Labels.Applications != "应用程序" {
		t.Fatalf("unexpected toolbar payload: %#v", payload.Data)
	}
}

func TestGenerateToolbarDataExternalizesRepeatedFaviconBytes(t *testing.T) {
	icon := "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("icon-bytes", 4096)))
	hostRules := make([]models.HostRule, 16)
	for i := range hostRules {
		hostRules[i] = models.HostRule{
			Host:    fmt.Sprintf("app-%d.example.com", i),
			Favicon: icon,
		}
	}
	body := GenerateToolbarDataWithPrefilteredHostsForLocale(
		"en",
		nil,
		hostRules,
		"/",
		"app-0.example.com",
		"",
		models.GatewayPortalConfig{ShowAppIcon: true},
	)
	if strings.Contains(body, "data:image") {
		t.Fatal("toolbar data still embeds Base64 favicon bytes")
	}
	if got := strings.Count(body, WebsiteIconPathPrefix); got != len(hostRules) {
		t.Fatalf("website icon paths = %d, want %d", got, len(hostRules))
	}
	if len(body) >= 8*1024 {
		t.Fatalf("externalized toolbar data is unexpectedly large: %d bytes", len(body))
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
		".app-icon-shell.has-image",
		"object-fit: contain",
		"@media (max-width: 768px)",
	} {
		if !strings.Contains(runtime, expected) {
			t.Fatalf("v2 runtime is missing responsive invariant %q", expected)
		}
	}
}

func TestToolbarRuntimesKeepWebsiteIconPathsOnCurrentOrigin(t *testing.T) {
	for name, runtime := range map[string]string{
		"v1": string(toolbarRuntime),
		"v2": string(toolbarV2Runtime),
	} {
		for _, expected := range []string{
			"function resolveAppIconSrc(value)",
			"new URL(value, window.location.origin).href",
			"parsed.origin === window.location.origin",
			"/__assets__\\/website_icon\\.",
		} {
			if !strings.Contains(runtime, expected) {
				t.Fatalf("%s runtime is missing same-origin website icon support %q", name, expected)
			}
		}
		for _, forbidden := range []string{
			"resolveAppIconSrc(value, host)",
			"new URL(value, buildHostHref(host)).href",
		} {
			if strings.Contains(runtime, forbidden) {
				t.Fatalf("%s runtime still resolves website icons against a sibling host with %q", name, forbidden)
			}
		}
	}
}

func TestToolbarV2RuntimeUsesNativeSafeNewTabNavigation(t *testing.T) {
	runtime := string(toolbarV2Runtime)
	for _, expected := range []string{
		"link.target = '_blank';",
		"link.rel = 'noopener noreferrer';",
	} {
		if !strings.Contains(runtime, expected) {
			t.Fatalf("v2 runtime is missing new-tab navigation invariant %q", expected)
		}
	}
	for _, forbidden := range []string{
		"window.location.assign(href)",
		"e.preventDefault()",
	} {
		if strings.Contains(runtime, forbidden) {
			t.Fatalf("v2 runtime still hijacks application navigation with %q", forbidden)
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
	if strings.Contains(toolbar, "window.__REAUTH_PROXY_TOOLBAR_DATA__") {
		t.Fatal("toolbar loader still uses an inline script")
	}
	if !strings.Contains(toolbar, toolbarTemplatePrefix) || !strings.HasSuffix(toolbar, toolbarTemplateSuffix) {
		t.Fatalf("toolbar does not use the external-script wrapper: %s", toolbar)
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
	if !strings.Contains(toolbar, toolbarV2TemplatePrefix) || !strings.HasSuffix(toolbar, toolbarV2TemplateSuffix) {
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
	loader := strings.Index(toolbar, toolbarV2TemplatePrefix)
	raw := html.UnescapeString(toolbar[loader+len(toolbarV2TemplatePrefix) : len(toolbar)-len(toolbarV2TemplateSuffix)])
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

func TestServeToolbarBootstrapAssetIsImmutableJavaScript(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.test"+ToolbarBootstrapAssetPath(), nil)
	rec := httptest.NewRecorder()

	ServeToolbarAsset(rec, req)
	result := rec.Result()
	defer result.Body.Close()
	body, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("read toolbar bootstrap asset: %v", err)
	}
	if result.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", result.StatusCode)
	}
	if got := result.Header.Get("Cache-Control"); got != toolbarAssetCacheControl {
		t.Fatalf("Cache-Control = %q, want %q", got, toolbarAssetCacheControl)
	}
	if string(body) != string(toolbarBootstrapRuntime) {
		t.Fatal("served bootstrap differs from hashed content")
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

func TestToolbarRuntimeIsValidJavaScript(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed")
	}
	cmd := exec.Command("node", "--check")
	cmd.Stdin = strings.NewReader(string(toolbarRuntime))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("toolbar runtime is invalid JavaScript: %v\n%s", err, output)
	}
}

func TestToolbarBootstrapRuntimeIsValidJavaScript(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed")
	}
	cmd := exec.Command("node", "--check")
	cmd.Stdin = strings.NewReader(string(toolbarBootstrapRuntime))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("toolbar bootstrap runtime is invalid JavaScript: %v\n%s", err, output)
	}
}

func TestToolbarBootstrapRuntimeFetchesFreshDataAndLoadsValidatedRuntime(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed")
	}
	cmd := exec.Command("node", "-e", toolbarBootstrapNodeFixture, base64.StdEncoding.EncodeToString(toolbarBootstrapRuntime))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("toolbar bootstrap behavior failed: %v\n%s", err, output)
	}
}

const toolbarBootstrapNodeFixture = `
const runtime = Buffer.from(process.argv[1], 'base64').toString('utf8');
function assert(condition, message) {
  if (!condition) throw new Error(message);
}
let inserted = null;
const bootstrap = {
  getAttribute(name) { return name === 'data-endpoint' ? '/__assets__/toolbar/data' : null; },
  parentNode: {insertBefore(node) { inserted = node; }}
};
const document = {
  getElementById(id) { return id === 'reauth-proxy-toolbar-bootstrap' ? bootstrap : null; },
  createElement(tag) {
    assert(tag === 'script', 'bootstrap created a non-script loader');
    return {setAttribute(name, value) { this[name] = value; }};
  }
};
const runtimeURL = '/__assets__/toolbar/toolbar-v2.' + 'a'.repeat(64) + '.js';
const toolbarData = {rules: [{path: '/app'}], host_rules: []};
const window = {
  location: {pathname: '/space path', search: '?tab=recent'},
  fetch(url, options) {
    assert(url === '/__assets__/toolbar/data?page_path=%2Fspace%20path', 'unexpected data URL: ' + url);
    assert(options.credentials === 'same-origin', 'credentials mode was not same-origin');
    assert(options.cache === 'no-store', 'fetch cache mode was not no-store');
	assert(options.headers['X-Reauth-Toolbar-Page-Query'] === 'tab=recent', 'page query was not forwarded');
    return Promise.resolve({
      status: 200,
      ok: true,
      json() { return Promise.resolve({runtime_url: runtimeURL, data: toolbarData}); }
    });
  }
};
new Function('window', 'document', runtime)(window, document);
setTimeout(() => {
  assert(inserted, 'runtime loader was not inserted');
  assert(inserted.src === runtimeURL, 'runtime URL was not applied');
  assert(inserted.id === 'reauth-proxy-toolbar-loader', 'runtime loader id was not applied');
  assert(JSON.stringify(JSON.parse(inserted['data-toolbar'])) === JSON.stringify(toolbarData), 'toolbar data was not transferred');
}, 0);
`

func TestToolbarWarmupRuntimeBehavior(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed")
	}

	tests := []struct {
		name      string
		runtime   []byte
		endMarker string
	}{
		{name: "v1", runtime: toolbarRuntime, endMarker: "var navLinks"},
		{name: "v2", runtime: toolbarV2Runtime, endMarker: "function isAppIconSrc"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			snippet := toolbarWarmupSnippetForTest(t, string(tc.runtime), tc.endMarker)
			cmd := exec.Command("node", "-e", toolbarWarmupNodeFixture, base64.StdEncoding.EncodeToString([]byte(snippet)))
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("toolbar warmup behavior failed: %v\n%s", err, output)
			}
		})
	}
}

func toolbarWarmupSnippetForTest(t *testing.T, runtime string, endMarker string) string {
	t.Helper()
	start := strings.Index(runtime, "function buildHostHref")
	if start < 0 {
		t.Fatal("toolbar runtime has no host URL builder")
	}
	endOffset := strings.Index(runtime[start:], endMarker)
	if endOffset < 0 {
		t.Fatalf("toolbar runtime has no warmup end marker %q", endMarker)
	}
	return runtime[start : start+endOffset]
}

const toolbarWarmupNodeFixture = `
const snippet = Buffer.from(process.argv[1], 'base64').toString('utf8');
function assert(condition, message) {
  if (!condition) throw new Error(message);
}
function makeEnvironment(hostRules, options) {
  options = options || {};
  const storage = Object.assign({}, options.storage || {});
  const links = [];
  const idle = [];
  const head = {appendChild(node) { if (node.rel === 'preconnect') links.push(node); return node; }};
  const document = {
    head,
    documentElement: head,
    readyState: 'complete',
    visibilityState: options.visibility || 'visible',
    createElement() { return {}; },
    getElementsByTagName() { return [head]; }
  };
  const window = {
    location: new URL('https://launcher.example.test:8443/app'),
    requestIdleCallback(callback) { idle.push(callback); },
    setTimeout(callback) { idle.push(callback); },
    localStorage: {
      getItem(key) { return Object.prototype.hasOwnProperty.call(storage, key) ? storage[key] : null; },
      setItem(key, value) { storage[key] = String(value); }
    }
  };
  const navigator = {connection: options.connection || {}};
  const toolbarData = {host_rules: hostRules};
  const safeGetStoredItem = (key) => window.localStorage.getItem(key);
  const safeSetStoredItem = (key, value) => window.localStorage.setItem(key, value);
  const asString = (value) => typeof value === 'string' ? value : '';
  const api = new Function('window', 'document', 'navigator', 'toolbarData', 'safeGetStoredItem', 'safeSetStoredItem', 'asString', snippet + '\nreturn { scheduleToolbarIdleWarmup, attachToolbarWarmup };')(
    window, document, navigator, toolbarData, safeGetStoredItem, safeSetStoredItem, asString
  );
  return {api, links, idle, storage};
}
const hosts = [{host: 'one.example.test'}, {host: 'two.example.test'}, {host: 'three.example.test'}];
const first = makeEnvironment(hosts);
first.api.scheduleToolbarIdleWarmup();
assert(first.idle.length === 1, 'idle warmup was not scheduled');
first.idle.shift()();
assert(first.links.length === 2, 'idle warmup must preconnect at most two origins');
assert(first.links[0].href === 'https://one.example.test:8443', 'first-run order must follow toolbar order');
assert(first.links[1].href === 'https://two.example.test:8443', 'second first-run candidate is wrong');
assert(first.links.every((link) => link.crossOrigin === 'anonymous'), 'preconnect links must be anonymous');

const recentHistory = JSON.stringify({'https://three.example.test:8443': {clicks: 3, last: Date.now()}});
const ranked = makeEnvironment(hosts, {storage: {reauth_proxy_toolbar_warmup: recentHistory}});
ranked.api.scheduleToolbarIdleWarmup();
ranked.idle.shift()();
assert(ranked.links[0].href === 'https://three.example.test:8443', 'recent click history must rank the target first');

const saveData = makeEnvironment(hosts, {connection: {saveData: true}});
saveData.api.scheduleToolbarIdleWarmup();
assert(saveData.idle.length === 0, 'save-data must suppress idle warmup');
const slowNetwork = makeEnvironment(hosts, {connection: {effectiveType: '2g'}});
slowNetwork.api.scheduleToolbarIdleWarmup();
assert(slowNetwork.idle.length === 0, '2g must suppress idle warmup');
const hiddenPage = makeEnvironment(hosts, {visibility: 'hidden'});
hiddenPage.api.scheduleToolbarIdleWarmup();
assert(hiddenPage.idle.length === 0, 'hidden pages must suppress idle warmup');

const intent = makeEnvironment([]);
const listeners = {};
const link = {
  href: 'https://intent.example.test:8443/',
  getAttribute(name) { return name === 'href' ? this.href : null; },
  addEventListener(name, callback) { listeners[name] = callback; }
};
intent.api.attachToolbarWarmup(link);
assert(listeners.pointerenter && listeners.focus && listeners.touchstart && listeners.click, 'intent listeners are incomplete');
listeners.pointerenter();
assert(intent.links.length === 1 && intent.links[0].href === 'https://intent.example.test:8443', 'pointer intent did not preconnect');
listeners.click();
const history = JSON.parse(intent.storage.reauth_proxy_toolbar_warmup);
assert(history['https://intent.example.test:8443'].clicks === 1, 'click history was not persisted');

const bounded = makeEnvironment([]);
for (let index = 0; index < 33; index++) {
  const boundedListeners = {};
  const boundedLink = {
    href: 'https://bounded-' + index + '.example.test:8443/',
    getAttribute(name) { return name === 'href' ? this.href : null; },
    addEventListener(name, callback) { boundedListeners[name] = callback; }
  };
  bounded.api.attachToolbarWarmup(boundedLink);
  boundedListeners.click();
}
assert(Object.keys(JSON.parse(bounded.storage.reauth_proxy_toolbar_warmup)).length === 32, 'click history must stay bounded');
`
