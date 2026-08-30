package staticserve

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"go-reauth-proxy/pkg/models"
)

func TestReadmeGitHubAlertsRenderAllSupportedTypes(t *testing.T) {
	directory := t.TempDir()
	readme := `# Alert examples

> [!NOTE]
> Note content keeps **strong text**.
> ![local](images/logo.png)
> ![external](https://evil.example/track.png)

> [!TIP]
>
> - First tip
> - Second tip

> [!IMPORTANT]
> Read the [documentation](https://example.com/docs).

> [!WARNING]
> Run ` + "`safe-command`" + ` carefully.

> [!CAUTION]
> Unsafe content is removed: [bad](javascript:alert(1)) <img src="x" onerror="alert(1)">
`
	mustWriteFile(t, filepath.Join(directory, "README.md"), readme)

	response := serveRequest(t, models.HostRuleTargetTypeDirectory, listingConfig(directory, true), http.MethodGet, "/", nil, Options{})
	if response.Code != http.StatusOK {
		t.Fatalf("listing = %d %q", response.Code, response.Body.String())
	}
	body := renderedReadmeHTML(response.Body.String())

	alerts := []struct {
		kind  string
		title string
	}{
		{kind: "note", title: "Note"},
		{kind: "tip", title: "Tip"},
		{kind: "important", title: "Important"},
		{kind: "warning", title: "Warning"},
		{kind: "caution", title: "Caution"},
	}
	for _, alert := range alerts {
		class := `class="markdown-alert markdown-alert-` + alert.kind + `"`
		if !strings.Contains(body, class) {
			t.Errorf("README is missing %s alert class: %s", alert.kind, body)
		}
		title := `<p class="markdown-alert-title">` + alert.title + `</p>`
		if !strings.Contains(body, title) {
			t.Errorf("README is missing %s alert title: %s", alert.kind, body)
		}
	}
	if got := strings.Count(body, `class="markdown-alert markdown-alert-`); got != len(alerts) {
		t.Errorf("rendered alert count = %d, want %d: %s", got, len(alerts), body)
	}
	if strings.Contains(body, "[!NOTE]") || strings.Contains(body, "[!TIP]") || strings.Contains(body, "[!IMPORTANT]") || strings.Contains(body, "[!WARNING]") || strings.Contains(body, "[!CAUTION]") {
		t.Errorf("recognized alert marker leaked into rendered content: %s", body)
	}
	for _, retained := range []string{
		`Note content keeps <strong>strong text</strong>.`,
		`<li>First tip</li>`,
		`<li>Second tip</li>`,
		`>documentation</a>`,
		`<code>safe-command</code>`,
		`Unsafe content is removed:`,
	} {
		if !strings.Contains(body, retained) {
			t.Errorf("alert body lost rendered Markdown %q: %s", retained, body)
		}
	}
	if !strings.Contains(body, `rel="nofollow noopener noreferrer"`) {
		t.Errorf("alert link lost mandatory safety relation: %s", body)
	}
	if !strings.Contains(body, `src="images/logo.png"`) {
		t.Errorf("same-origin Markdown image was removed from alert: %s", body)
	}
	for _, forbidden := range []string{"javascript:", "onerror", "evil.example/track.png", "<script"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Errorf("alert content contains unsafe %q: %s", forbidden, body)
		}
	}
}

func TestReadmeGitHubAlertsOnlyConvertTopLevelBlockquotes(t *testing.T) {
	directory := t.TempDir()
	readme := "> [!NOTE]\r\n> First top-level alert.\r\n\r\n" + `> Ordinary quotation.

- > [!TIP]
  > A list-nested marker is not an alert.

> Outer quotation.
>
> > [!WARNING]
> > A quote-nested marker is not an alert.

> [!CAUTION]
> Last top-level alert.
`
	mustWriteFile(t, filepath.Join(directory, "README.md"), readme)

	response := serveRequest(t, models.HostRuleTargetTypeDirectory, listingConfig(directory, true), http.MethodGet, "/", nil, Options{})
	if response.Code != http.StatusOK {
		t.Fatalf("listing = %d %q", response.Code, response.Body.String())
	}
	body := renderedReadmeHTML(response.Body.String())
	if got := strings.Count(body, `class="markdown-alert markdown-alert-`); got != 2 {
		t.Fatalf("top-level alert count = %d, want 2: %s", got, body)
	}
	for _, expected := range []string{
		`class="markdown-alert markdown-alert-note"`,
		`class="markdown-alert markdown-alert-caution"`,
		"First top-level alert.",
		"Last top-level alert.",
		"[!TIP]",
		"A list-nested marker is not an alert.",
		"[!WARNING]",
		"A quote-nested marker is not an alert.",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("nested alert boundary lost %q: %s", expected, body)
		}
	}
	for _, forbidden := range []string{"markdown-alert-tip", "markdown-alert-warning"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("nested marker incorrectly rendered with %q: %s", forbidden, body)
		}
	}
}

func TestReadmeGitHubAlertRewriteFailsClosedOnTypeMismatch(t *testing.T) {
	content := []byte("<blockquote><p>[!WARNING]\nKeep the original marker.</p></blockquote>")
	alerts := []markdownAlertDefinition{markdownAlertDefinitions["[!NOTE]"]}
	rewritten, err := rewriteSanitizedReadme(content, alerts)
	if err != nil {
		t.Fatal(err)
	}
	body := string(rewritten)
	if strings.Contains(body, `class="markdown-alert`) || !strings.Contains(body, "[!WARNING]") {
		t.Fatalf("mismatched AST/HTML alert metadata did not fail closed: %s", body)
	}
}

func TestReadmeGitHubAlertSyntaxBoundaries(t *testing.T) {
	directory := t.TempDir()
	readme := `# Ordinary quotations

> [!DANGER]
> Unknown kinds remain ordinary blockquotes.

> [!IMPORTANT] marker text on the same line
> This also remains an ordinary blockquote.

> Introductory quotation text.
> [!NOTE]
> A marker after the first line is not an alert.

> \[!IMPORTANT]
> An escaped marker remains ordinary quoted text.
`
	mustWriteFile(t, filepath.Join(directory, "README.md"), readme)

	response := serveRequest(t, models.HostRuleTargetTypeDirectory, listingConfig(directory, true), http.MethodGet, "/", nil, Options{})
	if response.Code != http.StatusOK {
		t.Fatalf("listing = %d %q", response.Code, response.Body.String())
	}
	body := renderedReadmeHTML(response.Body.String())
	if strings.Contains(body, `class="markdown-alert`) || strings.Contains(body, `class="markdown-alert-title"`) {
		t.Fatalf("unsupported or misplaced markers became alerts: %s", body)
	}
	for _, retained := range []string{
		"[!DANGER]",
		"[!IMPORTANT] marker text on the same line",
		"Introductory quotation text.",
		"[!NOTE]",
		"An escaped marker remains ordinary quoted text.",
	} {
		if !strings.Contains(body, retained) {
			t.Errorf("ordinary blockquote lost marker text %q: %s", retained, body)
		}
	}
	if got := strings.Count(body, "<blockquote>"); got != 4 {
		t.Errorf("ordinary blockquote count = %d, want 4: %s", got, body)
	}
}

func TestReadmeGitHubAlertThemeContract(t *testing.T) {
	directory := t.TempDir()
	mustWriteFile(t, filepath.Join(directory, "README.md"), "> [!IMPORTANT]\n> Theme contract.\n")
	response := serveRequest(t, models.HostRuleTargetTypeDirectory, listingConfig(directory, true), http.MethodGet, "/", nil, Options{})
	if response.Code != http.StatusOK {
		t.Fatalf("listing = %d %q", response.Code, response.Body.String())
	}
	style := listingInlineStyleForTest(t, response.Body.String())

	for _, required := range []string{
		`--alert-note: #0969da;`,
		`--alert-tip: #1a7f37;`,
		`--alert-important: #8250df;`,
		`--alert-warning: #9a6700;`,
		`--alert-caution: #cf222e;`,
		`--alert-note: #58a6ff;`,
		`--alert-tip: #3fb950;`,
		`--alert-important: #a371f7;`,
		`--alert-warning: #d29922;`,
		`--alert-caution: #f85149;`,
		`.readme .markdown-alert {`,
		`.readme .markdown-alert-note { --alert-color: var(--alert-note); }`,
		`.readme .markdown-alert-tip { --alert-color: var(--alert-tip); }`,
		`.readme .markdown-alert-important { --alert-color: var(--alert-important); }`,
		`.readme .markdown-alert-warning { --alert-color: var(--alert-warning); }`,
		`.readme .markdown-alert-caution { --alert-color: var(--alert-caution); }`,
		`.readme .markdown-alert-title {`,
		`.theme-ready .markdown-alert-title {`,
		`@media (prefers-reduced-motion: reduce)`,
		`transition: none !important;`,
	} {
		if !strings.Contains(style, required) {
			t.Errorf("alert theme CSS is missing %q", required)
		}
	}
	for _, darkToken := range []string{
		`--alert-note: #58a6ff;`,
		`--alert-tip: #3fb950;`,
		`--alert-important: #a371f7;`,
		`--alert-warning: #d29922;`,
		`--alert-caution: #f85149;`,
	} {
		if got := strings.Count(style, darkToken); got < 2 {
			t.Errorf("dark alert token %q occurs %d times, want explicit and system-dark declarations", darkToken, got)
		}
	}
}
