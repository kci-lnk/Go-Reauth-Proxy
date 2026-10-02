package response

import (
	"encoding/base64"
	"os/exec"
	"strings"
	"testing"
)

func TestPortalRuntimesUseDirectHrefAndKeepFallback(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed")
	}
	extract := func(runtime, startMarker, endMarker string) string {
		t.Helper()
		start := strings.Index(runtime, startMarker)
		if start < 0 {
			t.Fatalf("missing start marker %s", startMarker)
		}
		end := strings.Index(runtime[start:], endMarker)
		if end < 0 {
			t.Fatalf("missing end marker %s", endMarker)
		}
		return runtime[start : start+end]
	}
	v1 := extract(string(toolbarRuntime), "function createMenuLink", "function buildHostHref") +
		extract(string(toolbarRuntime), "var navLinks", "scheduleToolbarIdleWarmup();") + "\nreturn collect(menuScroll);"
	v2 := extract(string(toolbarV2Runtime), "var apps = [];", "function createApp") + "\nreturn apps;"
	for version, snippet := range map[string]string{"v1": v1, "v2": v2} {
		t.Run(version, func(t *testing.T) {
			cmd := exec.Command("node", "-e", portalNavigationNodeFixture, version, base64.StdEncoding.EncodeToString([]byte(snippet)))
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("navigation runtime failed: %v\n%s", err, output)
			}
		})
	}
}

const portalNavigationNodeFixture = `
const assert = require('node:assert/strict');
const version = process.argv[1];
const snippet = Buffer.from(process.argv[2], 'base64').toString('utf8');
function collect(node) {
  return (node.tag === 'a' ? [node] : []).concat(node.children.flatMap(collect));
}
function run(toolbarData) {
  function element(tag) {
    return {tag, children: [], attrs: {}, events: {},
      appendChild(child) { this.children.push(child); },
      setAttribute(key, value) { this.attrs[key] = value; if (key === 'href') this.href = value; },
      getAttribute(key) { return key === 'href' ? this.href : this.attrs[key]; },
      hasAttribute(key) { return key in this.attrs; },
      removeAttribute(key) { delete this.attrs[key]; },
      addEventListener(key, value) { this.events[key] = value; },
      classList: {remove() {}, contains() { return false; }, toggle() {}}
    };
  }
  const menuScroll = element('div');
  const document = {createElement: element, createElementNS: (_, tag) => element(tag)};
  const opened = [];
  const window = {open(href) { opened.push(href); }};
  const shadow = {querySelectorAll() { return collect(menuScroll); }};
  const asString = value => typeof value === 'string' ? value : '';
  const api = new Function('toolbarData', 'document', 'menuScroll', 'shadow', 'window', 'collect',
    'asString', 'buildHostHref', 'ensureSlash', 'label', 'isActiveHost', 'isActivePath',
    'isAppIconSrc', 'resolveAppIconSrc', 'appendRightContent', 'safeGetStoredItem',
    'safeSetStoredItem', 'groupCollapseStorageKey', 'attachToolbarWarmup', 'menu', snippet);
  const links = api(toolbarData, document, menuScroll, shadow, window, collect, asString,
    host => 'https://' + host + ':8443/', path => path.endsWith('/') ? path : path + '/',
    (_, fallback) => fallback, () => false, () => false, () => false, () => '',
    () => {}, () => null, () => {}, 'groups', () => {}, element('div'));
  if (version === 'v1') {
    for (const link of links) link.events.click.call(link, {preventDefault() {}, stopPropagation() {}});
    assert.deepEqual(opened, links.map(link => link.href), 'click must open the rendered href');
  }
  return links.map(link => link.href);
}
for (const grouped of [false, true]) {
  const host_rules = [
    {host: 'lan.example.com', href: 'http://192.168.1.5:9000/base?tab=1',
      ...(grouped ? {group_id: 'apps', group_name: 'Apps'} : {})},
    {host: 'fallback.example.com'}
  ];
  assert.deepEqual(run({host_rules}), [
    'http://192.168.1.5:9000/base?tab=1', 'https://fallback.example.com:8443/'
  ], 'grouped and ungrouped links must prefer direct href without overwriting it');
}
assert.deepEqual(run({rules: [
  {path: '/app', href: 'https://[fd00::1]:9443/base?tab=2'}, {path: '/fallback'}
]}), ['https://[fd00::1]:9443/base?tab=2', '/fallback/'], 'path links must preserve direct URLs and fallback');
`
