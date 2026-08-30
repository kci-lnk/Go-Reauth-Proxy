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
	for _, required := range []string{
		`<svg class="theme-icon theme-icon-sun"`,
		`<svg class="theme-icon theme-icon-moon"`,
		`viewBox="0 0 24 24"`,
		`focusable="false"`,
		`<circle cx="12" cy="12" r="4"></circle>`,
	} {
		if !strings.Contains(button, required) {
			t.Errorf("theme button is missing SVG contract fragment %q: %s", required, button)
		}
	}
	if strings.Count(button, "<svg ") != 2 || strings.Count(button, "</svg>") != 2 {
		t.Fatalf("theme button must contain exactly two inline SVG icons: %s", button)
	}
	if strings.Contains(button, "☀") || strings.Contains(button, "☾") || strings.Contains(button, " src=") || strings.Contains(button, " href=") {
		t.Fatalf("theme button must use self-contained SVG geometry, not glyphs or external resources: %s", button)
	}
	for _, character := range button {
		if character > 127 {
			t.Fatalf("theme button unexpectedly contains a non-ASCII glyph %q: %s", character, button)
		}
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
		`.theme-ready,`,
		`.theme-ready body,`,
		`.theme-ready .breadcrumbs .separator,`,
		`.theme-ready .sort-indicator,`,
		`.theme-ready .listing-table tr,`,
		`.theme-ready .readme blockquote,`,
		`transition: background-color 200ms ease-out, color 200ms ease-out, border-color 200ms ease-out;`,
		`.theme-ready .theme-icon { transition: opacity 200ms ease-out, transform 200ms ease-out; }`,
		`@media (prefers-reduced-motion: reduce)`,
		`.theme-ready, .theme-ready *, .theme-ready *::before, .theme-ready *::after { transition: none !important; }`,
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
		`<nav class="mobile-sort" aria-label="Sort directory">`,
		`<table class="listing-table">`,
		`<caption class="visually-hidden">Directory contents</caption>`,
		`scope="col"`,
		`aria-sort="ascending"`,
		`<span class="mobile-cell-label">Size</span>`,
		`<span class="mobile-cell-label">Modified</span>`,
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
	if got := strings.Count(body, `aria-sort=`); got != 1 {
		t.Errorf("aria-sort count = %d, want only the active column", got)
	}
	if strings.Contains(body, `data-label=`) {
		t.Error("mobile metadata must use real text, not CSS-generated data-label content")
	}

	style := listingInlineStyleForTest(t, body)
	for _, required := range []string{
		`max-width: 70rem;`,
		`font-size: clamp(2rem, 5vw, 2.7rem); font-weight: 650;`,
		`.breadcrumbs a[aria-current="page"] { color: var(--text); font-weight: 600; }`,
		`.listing-table {`,
		`.listing-table th, .listing-table td {`,
		`.readme table {`,
		`@media (max-width: 42rem)`,
		`.mobile-sort { display: flex;`,
		`.listing-table, .listing-table tbody { display: block; }`,
		`.listing-table thead { display: none; }`,
		`.listing-table tr { display: grid;`,
		`.mobile-cell-label { display: inline;`,
		`.listing-table td.name { overflow-wrap: anywhere; }`,
		`.page-header h1 {`,
		`overflow-wrap: anywhere;`,
		`.readme pre { overflow: auto;`,
		`.readme table { display: block; width: 100%; overflow-x: auto;`,
		`@media (max-width: 26rem)`,
		`.listing-table td.modified { justify-self: start; text-align: left !important; }`,
	} {
		if !strings.Contains(style, required) {
			t.Errorf("responsive or scoped CSS is missing %q", required)
		}
	}
	for _, forbidden := range []string{"linear-gradient(", "radial-gradient(", "backdrop-filter:", "box-shadow:"} {
		if strings.Contains(style, forbidden) {
			t.Errorf("restrained index styling must not introduce %q", forbidden)
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
	if strings.Contains(style, `content: attr(data-label)`) {
		t.Error("mobile metadata labels must not depend on pseudo-element content")
	}
	focusRule := listingCSSRuleForTest(t, style, "a:focus-visible, button:focus-visible")
	if !strings.Contains(focusRule, "outline: 3px solid var(--focus)") || strings.Contains(focusRule, "transparent") || strings.Contains(focusRule, "color-mix") {
		t.Fatalf("focus ring must remain opaque in both themes: %q", focusRule)
	}
	for selector, minimumHeight := range map[string]string{
		".theme-toggle": "height: 2.75rem",
		".pager a":      "min-height: 2.75rem",
		".sort-chip":    "min-height: 2.75rem",
	} {
		rule := listingCSSRuleForTest(t, style, selector)
		if !strings.Contains(rule, minimumHeight) {
			t.Errorf("%s must retain a mobile-friendly target: %q", selector, rule)
		}
	}
}

func TestDirectoryListingOnlyActiveSortHeaderHasAriaSort(t *testing.T) {
	directory := t.TempDir()
	mustWriteFile(t, filepath.Join(directory, "entry.txt"), "content")
	testCases := []struct {
		query string
		label string
		want  string
	}{
		{query: "sort=name&order=asc", label: "Name", want: "ascending"},
		{query: "sort=name&order=desc", label: "Name", want: "descending"},
		{query: "sort=size&order=asc", label: "Size", want: "ascending"},
		{query: "sort=size&order=desc", label: "Size", want: "descending"},
		{query: "sort=modified&order=asc", label: "Modified", want: "ascending"},
		{query: "sort=modified&order=desc", label: "Modified", want: "descending"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.query, func(t *testing.T) {
			response := serveRequest(t, models.HostRuleTargetTypeDirectory, listingConfig(directory, false), http.MethodGet, "/?"+testCase.query, nil, Options{})
			if response.Code != http.StatusOK {
				t.Fatalf("listing = %d %q", response.Code, response.Body.String())
			}
			body := response.Body.String()
			if got := strings.Count(body, `aria-sort=`); got != 1 {
				t.Fatalf("aria-sort count = %d, want 1: %s", got, body)
			}
			if !strings.Contains(body, `aria-sort="`+testCase.want+`"`) {
				t.Fatalf("listing is missing aria-sort=%q: %s", testCase.want, body)
			}
			if got := strings.Count(body, `aria-current="true"`); got != 1 {
				t.Fatalf("mobile current-sort count = %d, want 1: %s", got, body)
			}
			currentLabel := `aria-current="true" aria-label="` + testCase.label + `, currently sorted ` + testCase.want + `; Sort by `
			if !strings.Contains(body, currentLabel) {
				t.Fatalf("mobile sort is missing current field and direction %q: %s", currentLabel, body)
			}
		})
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
