package staticserve

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"go-reauth-proxy/pkg/models"
)

func TestDirectoryListingThemeScriptAndCSPContract(t *testing.T) {
	directory := t.TempDir()
	response := serveRequest(t, models.HostRuleTargetTypeDirectory, listingConfig(directory, false), http.MethodGet, "/", nil, Options{})
	if response.Code != http.StatusOK {
		t.Fatalf("listing = %d %q", response.Code, response.Body.String())
	}

	body := response.Body.String()
	script := listingInlineScriptForTest(t, body)
	if script != listingThemeScript {
		t.Fatal("rendered theme script does not exactly match listingThemeScript")
	}
	if strings.Index(body, "<script>") > strings.Index(body, "<style>") {
		t.Fatal("theme initialization script must run before styles are parsed")
	}

	digest := sha256.Sum256([]byte(script))
	wantHashSource := "'sha256-" + base64.StdEncoding.EncodeToString(digest[:]) + "'"
	directives := listingCSPDirectivesForTest(t, response.Header().Get("Content-Security-Policy"))
	if got := directives["script-src"]; len(got) != 1 || got[0] != wantHashSource {
		t.Fatalf("script-src = %q, want only %q", got, wantHashSource)
	}
	if got := directives["script-src-attr"]; len(got) != 1 || got[0] != "'none'" {
		t.Fatalf("script-src-attr = %q, want only 'none'", got)
	}
	if _, exists := directives["script-src-elem"]; exists {
		t.Fatal("script-src-elem must not override the exact script-src hash policy")
	}
	if got := directives["default-src"]; len(got) != 1 || got[0] != "'none'" {
		t.Fatalf("default-src = %q, want only 'none'", got)
	}
	for _, forbidden := range []string{"'unsafe-inline'", "'unsafe-eval'", "'self'", "http:", "https:", "data:", "blob:", "*"} {
		if strings.Contains(strings.Join(directives["script-src"], " "), forbidden) {
			t.Fatalf("script-src unexpectedly allows %q: %q", forbidden, directives["script-src"])
		}
	}
}

func TestDirectoryListingThemePersistenceFallbackAndButtonContract(t *testing.T) {
	directory := t.TempDir()
	response := serveRequest(t, models.HostRuleTargetTypeDirectory, listingConfig(directory, false), http.MethodGet, "/", nil, Options{})
	if response.Code != http.StatusOK {
		t.Fatalf("listing = %d %q", response.Code, response.Body.String())
	}

	body := response.Body.String()
	script := listingInlineScriptForTest(t, body)
	for _, required := range []string{
		`var storageKey = "fn-knock-index-theme";`,
		`window.localStorage.getItem(storageKey)`,
		`stored !== "light" && stored !== "dark"`,
		`window.localStorage.setItem(storageKey, theme)`,
		`window.matchMedia("(prefers-color-scheme: dark)")`,
		`applyTheme(stored || systemTheme(), false);`,
		`if (!manual)`,
		`media.addEventListener("change", followSystem)`,
		`media.addListener(followSystem)`,
		`toggle.setAttribute("aria-pressed", theme === "dark" ? "true" : "false")`,
		`toggle.addEventListener("click"`,
		`toggle.hidden = false;`,
	} {
		if !strings.Contains(script, required) {
			t.Errorf("theme script is missing contract fragment %q", required)
		}
	}
	if strings.Count(script, `catch (_) {}`) < 2 {
		t.Error("localStorage reads and writes must both degrade safely when storage is unavailable")
	}
	initialApply := strings.Index(script, `applyTheme(stored || systemTheme(), false);`)
	toggleInitialization := strings.Index(script, `function initializeThemeToggle()`)
	if initialApply < 0 || toggleInitialization < 0 || initialApply > toggleInitialization {
		t.Fatal("stored or system theme must be applied before DOM-dependent toggle initialization")
	}
	for _, forbidden := range []string{"innerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("theme script uses unsafe DOM or code API %q", forbidden)
		}
	}

	button := listingThemeButtonForTest(t, body)
	for _, required := range []string{`type="button"`, " hidden", `aria-label="Dark mode"`, `aria-pressed="false"`} {
		if !strings.Contains(button, required) {
			t.Errorf("theme button is missing %q: %s", required, button)
		}
	}
	if strings.Contains(button, "onclick=") || strings.Count(button, `aria-hidden="true"`) != 2 {
		t.Fatalf("theme button must use the hashed script and hide both decorative icons: %s", button)
	}

	style := listingInlineStyleForTest(t, body)
	for _, required := range []string{
		`@media (prefers-color-scheme: dark)`,
		`:root:not([data-theme])`,
		`:root[data-theme="dark"]`,
		`color-scheme: dark;`,
	} {
		if !strings.Contains(style, required) {
			t.Errorf("theme CSS is missing fallback fragment %q", required)
		}
	}
}

func TestDirectoryListingThemeMotionContract(t *testing.T) {
	directory := t.TempDir()
	response := serveRequest(t, models.HostRuleTargetTypeDirectory, listingConfig(directory, false), http.MethodGet, "/", nil, Options{})
	if response.Code != http.StatusOK {
		t.Fatalf("listing = %d %q", response.Code, response.Body.String())
	}

	body := response.Body.String()
	script := listingInlineScriptForTest(t, body)
	style := listingInlineStyleForTest(t, body)
	for _, required := range []string{
		`.theme-ready body,`,
		`transition: background-color 200ms ease-out, color 200ms ease-out, border-color 200ms ease-out;`,
		`.theme-ready .theme-icon { transition: opacity 200ms ease-out, transform 200ms ease-out; }`,
		`@media (prefers-reduced-motion: reduce)`,
		`transition: none !important;`,
	} {
		if !strings.Contains(style, required) {
			t.Errorf("theme motion CSS is missing %q", required)
		}
	}
	if !strings.Contains(script, `window.requestAnimationFrame(function () {`) || !strings.Contains(script, `root.classList.add("theme-ready")`) {
		t.Error("theme transitions must be enabled only after the initial theme has been applied")
	}
	if strings.Contains(style, "transition: all") {
		t.Error("theme animation must not transition unrelated layout properties")
	}
}

func TestDirectoryListingResponsiveSemanticsAndReadmeSeparation(t *testing.T) {
	directory := t.TempDir()
	mustWriteFile(t, filepath.Join(directory, "a-very-long-file-name-for-mobile-layout.txt"), "content")
	mustWriteFile(t, filepath.Join(directory, "README.md"), "# README marker\n\n| Name | Value |\n| --- | --- |\n| A | B |\n")
	response := serveRequest(t, models.HostRuleTargetTypeDirectory, listingConfig(directory, true), http.MethodGet, "/", nil, Options{})
	if response.Code != http.StatusOK {
		t.Fatalf("listing = %d %q", response.Code, response.Body.String())
	}

	body := response.Body.String()
	for _, required := range []string{
		`<meta name="viewport" content="width=device-width, initial-scale=1">`,
		`<main>`,
		`<nav class="breadcrumbs" aria-label="Breadcrumb">`,
		`aria-current="page"`,
		`<div class="mobile-sort" aria-label="Sort directory">`,
		`<table class="listing-table">`,
		`<caption hidden>Directory contents</caption>`,
		`scope="col"`,
		`aria-sort="ascending"`,
		`data-label="Size"`,
		`data-label="Modified"`,
		`<article class="readme" aria-label="README">`,
		`README marker`,
	} {
		if !strings.Contains(body, required) {
			t.Errorf("responsive listing markup is missing %q", required)
		}
	}
	if got := strings.Count(body, `scope="col"`); got != 3 {
		t.Errorf("column header count = %d, want 3", got)
	}
	if got := strings.Count(body, `aria-sort=`); got != 3 {
		t.Errorf("aria-sort count = %d, want 3", got)
	}

	style := listingInlineStyleForTest(t, body)
	for _, required := range []string{
		`.listing-table {`,
		`.listing-table th, .listing-table td {`,
		`.readme table {`,
		`@media (max-width: 42rem)`,
		`.mobile-sort { display: flex;`,
		`.listing-table, .listing-table tbody { display: block; }`,
		`.listing-table thead { display: none; }`,
		`.listing-table tr { display: grid;`,
		`.listing-table td.size::before, .listing-table td.modified::before`,
		`.listing-table td.name { overflow-wrap: anywhere; }`,
		`.readme pre { overflow: auto;`,
		`.readme table { display: block; width: 100%; overflow-x: auto;`,
	} {
		if !strings.Contains(style, required) {
			t.Errorf("responsive or scoped CSS is missing %q", required)
		}
	}
	for _, line := range strings.Split(style, "\n") {
		switch strings.TrimSpace(line) {
		case "table {", "th, td {":
			t.Errorf("directory table CSS leaked into generic README elements: %q", strings.TrimSpace(line))
		}
	}

	readmeRule := listingCSSRuleForTest(t, style, ".readme")
	if strings.Contains(readmeRule, "border") || strings.Contains(readmeRule, "padding-top") {
		t.Fatalf("README container reintroduced a second separator: %q", readmeRule)
	}
	listingPanelRule := listingCSSRuleForTest(t, style, ".listing-panel")
	if !strings.Contains(listingPanelRule, "border: 1px solid var(--border)") {
		t.Fatalf("listing panel must retain the single list/README boundary: %q", listingPanelRule)
	}
	if !strings.Contains(style, `.listing-table tbody tr:last-child td { border-bottom: 0; }`) {
		t.Error("last directory row must not duplicate the panel's bottom separator")
	}
}

func listingInlineScriptForTest(t *testing.T, body string) string {
	t.Helper()
	if strings.Count(body, "<script>") != 1 || strings.Count(body, "</script>") != 1 {
		t.Fatalf("listing must contain exactly one fixed inline script")
	}
	start := strings.Index(body, "<script>") + len("<script>")
	end := strings.Index(body[start:], "</script>")
	if start < len("<script>") || end < 0 {
		t.Fatal("unable to extract listing inline script")
	}
	return body[start : start+end]
}

func listingInlineStyleForTest(t *testing.T, body string) string {
	t.Helper()
	if strings.Count(body, "<style>") != 1 || strings.Count(body, "</style>") != 1 {
		t.Fatal("listing must contain exactly one inline style block")
	}
	start := strings.Index(body, "<style>") + len("<style>")
	end := strings.Index(body[start:], "</style>")
	if start < len("<style>") || end < 0 {
		t.Fatal("unable to extract listing inline style")
	}
	return body[start : start+end]
}

func listingThemeButtonForTest(t *testing.T, body string) string {
	t.Helper()
	start := strings.Index(body, `<button id="theme-toggle"`)
	if start < 0 {
		t.Fatal("theme toggle button is missing")
	}
	end := strings.Index(body[start:], "</button>")
	if end < 0 {
		t.Fatal("theme toggle button is not closed")
	}
	return body[start : start+end+len("</button>")]
}

func listingCSPDirectivesForTest(t *testing.T, value string) map[string][]string {
	t.Helper()
	if value == "" {
		t.Fatal("listing CSP header is missing")
	}
	directives := make(map[string][]string)
	for _, raw := range strings.Split(value, ";") {
		fields := strings.Fields(raw)
		if len(fields) == 0 {
			continue
		}
		if _, duplicate := directives[fields[0]]; duplicate {
			t.Fatalf("duplicate CSP directive %q", fields[0])
		}
		directives[fields[0]] = fields[1:]
	}
	return directives
}

func listingCSSRuleForTest(t *testing.T, style, selector string) string {
	t.Helper()
	marker := selector + " {"
	start := strings.Index(style, marker)
	if start < 0 {
		t.Fatalf("CSS selector %q is missing", selector)
	}
	start += len(marker)
	end := strings.Index(style[start:], "}")
	if end < 0 {
		t.Fatalf("CSS selector %q has no closing brace", selector)
	}
	return style[start : start+end]
}
