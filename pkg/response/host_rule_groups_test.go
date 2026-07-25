package response

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go-reauth-proxy/pkg/models"
)

func TestBuildHostRuleGroupViewsKeepsFirstSeenOrderAndUngroupedLast(t *testing.T) {
	rules := []models.HostRule{
		{Host: "media.example.test", GroupID: "media", GroupName: "Media"},
		{Host: "tool.example.test", GroupID: "tools", GroupName: "Tools"},
		{Host: "loose.example.test"},
		{Host: "media-2.example.test", GroupID: "media", GroupName: "Media"},
	}
	groups, ok := buildHostRuleGroupViews(rules, "Ungrouped")
	if !ok || len(groups) != 3 {
		t.Fatalf("groups = %#v, ok = %v", groups, ok)
	}
	if groups[0].Name != "Media" || len(groups[0].Rules) != 2 ||
		groups[1].Name != "Tools" || groups[2].Name != "Ungrouped" {
		t.Fatalf("unexpected grouped projection: %#v", groups)
	}
}

func TestBuildHostRuleGroupViewsFallsBackToFlatWithoutEffectiveGroups(t *testing.T) {
	if groups, ok := buildHostRuleGroupViews(
		[]models.HostRule{{Host: "app.example.test"}},
		"Ungrouped",
	); ok || groups != nil {
		t.Fatalf("groups = %#v, ok = %v; want flat fallback", groups, ok)
	}
}

func TestSelectPageRendersEscapedGroupHeadingAndCounts(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.test/__select__", nil)
	rec := httptest.NewRecorder()
	SelectPage(rec, req, nil, []models.HostRule{
		{
			Host:      "app.example.test",
			Target:    "http://127.0.0.1:8080",
			GroupID:   "group-1",
			GroupName: `<img src=x onerror="alert(1)">`,
		},
	}, models.GatewayPortalConfig{})

	body := rec.Body.String()
	if strings.Contains(body, `<img src=x`) ||
		!strings.Contains(body, `&lt;img src=x onerror=&#34;alert(1)&#34;&gt;`) {
		t.Fatalf("group heading was not HTML escaped: %s", body)
	}
	if !strings.Contains(body, `class="route-group-count">1</span>`) {
		t.Fatalf("group count missing: %s", body)
	}
}

func TestToolbarPayloadIncludesGroupMetadataAndUngroupedLabel(t *testing.T) {
	toolbar := GenerateToolbarWithHostsForLocale(
		"en",
		nil,
		[]models.HostRule{{
			Host:      "app.example.test",
			Target:    "http://127.0.0.1:8080",
			GroupID:   "group-1",
			GroupName: `Media </script>`,
		}},
		"",
		"app.example.test",
		"",
		models.GatewayPortalConfig{},
	)
	if !strings.Contains(toolbar, `"group_id":"group-1"`) ||
		!strings.Contains(toolbar, `"group_name":"Media \u003c/script\u003e"`) ||
		!strings.Contains(toolbar, `"ungrouped":"Ungrouped"`) {
		t.Fatalf("toolbar group payload missing or unsafe: %s", toolbar)
	}
}

func TestToolbarGroupChevronUsesAlignedInlineSVG(t *testing.T) {
	runtime := string(toolbarRuntime)
	for _, want := range []string{
		"document.createElementNS(svgNamespace, 'svg')",
		"icon.setAttribute('viewBox', '0 0 16 16')",
		"path.setAttribute('d', 'M5.75 3.5L10.25 8L5.75 12.5')",
		"path.setAttribute('stroke-linecap', 'round')",
		"path.setAttribute('stroke-linejoin', 'round')",
		"transform-origin: 8px 8px",
		".menu-group:not(.collapsed) .menu-group-chevron",
	} {
		if !strings.Contains(runtime, want) {
			t.Fatalf("toolbar runtime missing SVG chevron detail %q", want)
		}
	}
	if strings.Contains(runtime, "chevron.textContent") || strings.Contains(runtime, "⌄") {
		t.Fatal("toolbar group chevron still depends on a font glyph")
	}
}

func TestToolbarGroupCollapseUsesAccessibleMotion(t *testing.T) {
	runtime := string(toolbarRuntime)
	for _, want := range []string{
		"grid-template-rows: 1fr",
		"grid-template-rows: 0fr",
		"transform: translateY(-4px)",
		"cubic-bezier(0.2, 0.8, 0.2, 1)",
		"@media (prefers-reduced-motion: reduce)",
		"itemsInner.className = 'menu-group-items-inner'",
		"header.setAttribute('aria-controls', items.id)",
		"content.setAttribute('aria-hidden', nextCollapsed ? 'true' : 'false')",
		"content.setAttribute('inert', '')",
		"content.removeAttribute('inert')",
	} {
		if !strings.Contains(runtime, want) {
			t.Fatalf("toolbar runtime missing grouped transition detail %q", want)
		}
	}
	if strings.Contains(runtime, ".menu-group.collapsed .menu-group-items {\n            display: none;") {
		t.Fatal("toolbar group collapse still uses an abrupt display toggle")
	}
}
