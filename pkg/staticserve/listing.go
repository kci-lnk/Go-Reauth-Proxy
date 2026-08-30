package staticserve

import (
	"bytes"
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"go-reauth-proxy/pkg/models"
)

var errDirectoryTooLarge = errors.New("directory exceeds scan limit")

type listingKey struct {
	directory bool
	name      string
	folded    string
}

type listingSortField byte

const (
	listingSortByName listingSortField = iota
	listingSortBySize
	listingSortByModified
)

type listingSortOrder byte

const (
	listingSortAscending listingSortOrder = iota
	listingSortDescending
)

type listingSort struct {
	field listingSortField
	order listingSortOrder
}

var defaultListingSort = listingSort{field: listingSortByName, order: listingSortAscending}

type cursorDirection byte

const (
	cursorAfter cursorDirection = iota
	cursorBefore
)

const (
	listingCursorVersion    = byte(2)
	listingCursorHeaderSize = 25
	maxListingCursorBytes   = 512
)

type listingCursor struct {
	direction cursorDirection
	sort      listingSort
	candidate listingCandidate
}

type listingCandidate struct {
	key      listingKey
	size     int64
	modified time.Time
}

type listingCandidateHeap struct {
	values  []listingCandidate
	sort    listingSort
	minimum bool
}

func (h listingCandidateHeap) Len() int { return len(h.values) }
func (h listingCandidateHeap) Less(i, j int) bool {
	comparison := compareListingCandidates(h.values[i], h.values[j], h.sort)
	if h.minimum {
		return comparison < 0
	}
	return comparison > 0
}
func (h listingCandidateHeap) Swap(i, j int) { h.values[i], h.values[j] = h.values[j], h.values[i] }
func (h *listingCandidateHeap) Push(value any) {
	h.values = append(h.values, value.(listingCandidate))
}
func (h *listingCandidateHeap) Pop() any {
	old := h.values
	last := old[len(old)-1]
	h.values = old[:len(old)-1]
	return last
}

type listingEntryView struct {
	Name         string
	Href         string
	Directory    bool
	Size         string
	Modified     string
	ModifiedTime string
}

type breadcrumbView struct {
	Name    string
	Href    string
	Current bool
}

type listingSortLinkView struct {
	FieldClass string
	Label      string
	Href       string
	AriaLabel  string
	AriaSort   string
	Indicator  string
	Active     bool
}

type listingPageView struct {
	Title        string
	Breadcrumbs  []breadcrumbView
	SortLinks    []listingSortLinkView
	Entries      []listingEntryView
	ParentHref   string
	PreviousHref string
	NextHref     string
	README       template.HTML
}

const listingThemeScript = `(function () {
  "use strict";
  var root = document.documentElement;
  var storageKey = "fn-knock-index-theme";
  var media = window.matchMedia("(prefers-color-scheme: dark)");
  var stored = "";
  try {
    stored = window.localStorage.getItem(storageKey) || "";
  } catch (_) {}
  if (stored !== "light" && stored !== "dark") {
    stored = "";
  }
  var manual = stored !== "";
  function systemTheme() {
    return media.matches ? "dark" : "light";
  }
  function applyTheme(theme, persist) {
    root.dataset.theme = theme;
    var toggle = document.getElementById("theme-toggle");
    if (toggle) {
      toggle.setAttribute("aria-pressed", theme === "dark" ? "true" : "false");
    }
    if (persist) {
      manual = true;
      try {
        window.localStorage.setItem(storageKey, theme);
      } catch (_) {}
    }
  }
  applyTheme(stored || systemTheme(), false);
  function initializeThemeToggle() {
    var toggle = document.getElementById("theme-toggle");
    if (toggle) {
      applyTheme(root.dataset.theme || systemTheme(), false);
      toggle.addEventListener("click", function () {
        applyTheme(root.dataset.theme === "dark" ? "light" : "dark", true);
      });
      toggle.hidden = false;
    }
    function followSystem(event) {
      if (!manual) {
        applyTheme(event.matches ? "dark" : "light", false);
      }
    }
    if (typeof media.addEventListener === "function") {
      media.addEventListener("change", followSystem);
    } else if (typeof media.addListener === "function") {
      media.addListener(followSystem);
    }
    window.requestAnimationFrame(function () {
      root.classList.add("theme-ready");
    });
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initializeThemeToggle, { once: true });
  } else {
    initializeThemeToggle();
  }
}());`

const listingPageTemplatePrefix = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>{{.Title}}</title>
  <script>`

const listingPageTemplateSuffix = `</script>
  <style>
    :root {
      color-scheme: light;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      --background: #f7f8fa;
      --surface: #ffffff;
      --surface-subtle: #f7f9fb;
      --text: #171c26;
      --muted: #697386;
      --border: #e1e5eb;
      --border-strong: #cdd3dd;
      --link: #315ca8;
      --link-hover: #234983;
      --row-hover: #f5f7fa;
      --focus: #426fc5;
      --alert-note: #0969da;
      --alert-tip: #1a7f37;
      --alert-important: #8250df;
      --alert-warning: #9a6700;
      --alert-caution: #cf222e;
    }
    :root[data-theme="dark"] {
      color-scheme: dark;
      --background: #0e1218;
      --surface: #151a22;
      --surface-subtle: #1b212b;
      --text: #edf0f5;
      --muted: #a2acba;
      --border: #2a323e;
      --border-strong: #3c4655;
      --link: #91b4f2;
      --link-hover: #b8cdf5;
      --row-hover: #1b222c;
      --focus: #9bbcf5;
      --alert-note: #58a6ff;
      --alert-tip: #3fb950;
      --alert-important: #a371f7;
      --alert-warning: #d29922;
      --alert-caution: #f85149;
    }
    @media (prefers-color-scheme: dark) {
      :root:not([data-theme]) {
        color-scheme: dark;
        --background: #0e1218;
        --surface: #151a22;
        --surface-subtle: #1b212b;
        --text: #edf0f5;
        --muted: #a2acba;
        --border: #2a323e;
        --border-strong: #3c4655;
        --link: #91b4f2;
        --link-hover: #b8cdf5;
        --row-hover: #1b222c;
        --focus: #9bbcf5;
        --alert-note: #58a6ff;
        --alert-tip: #3fb950;
        --alert-important: #a371f7;
        --alert-warning: #d29922;
        --alert-caution: #f85149;
      }
    }
    * { box-sizing: border-box; }
    html { min-width: 0; background: var(--background); -webkit-font-smoothing: antialiased; text-rendering: optimizeLegibility; }
    body {
      max-width: 70rem;
      min-height: 100vh;
      margin: 0 auto;
      padding: clamp(1.5rem, 4vw, 3.25rem) clamp(1rem, 3vw, 2rem) 4.5rem;
      background: var(--background);
      color: var(--text);
      font-size: .975rem;
      line-height: 1.55;
    }
    a { color: var(--link); text-decoration: none; text-decoration-thickness: .08em; text-underline-offset: .18em; }
    a:hover { color: var(--link-hover); text-decoration: underline; }
    a:focus-visible, button:focus-visible {
      outline: 3px solid var(--focus);
      outline-offset: 2px;
      border-radius: .3rem;
    }
    .page-header { margin-bottom: clamp(1.75rem, 4vw, 2.65rem); }
    .topline { display: flex; align-items: flex-start; justify-content: space-between; gap: 1rem; }
    .breadcrumbs { min-width: 0; margin: 0; color: var(--muted); font-size: .84rem; letter-spacing: .01em; overflow-wrap: anywhere; }
    .breadcrumbs a { color: inherit; }
    .breadcrumbs a:hover { color: var(--text); }
    .breadcrumbs a[aria-current="page"] { color: var(--text); font-weight: 600; }
    .breadcrumbs .separator { padding: 0 .35rem; color: var(--border-strong); }
    .page-header h1 { margin: 1.2rem 0 0; font-size: clamp(2rem, 5vw, 2.7rem); font-weight: 650; line-height: 1.12; letter-spacing: -.035em; overflow-wrap: anywhere; }
    .theme-toggle {
      position: relative;
      flex: 0 0 auto;
      width: 2.75rem;
      height: 2.75rem;
      border: 1px solid transparent;
      border-radius: 999px;
      background: transparent;
      color: var(--text);
      cursor: pointer;
    }
    .theme-toggle:hover { border-color: var(--border-strong); background: var(--surface-subtle); }
    .theme-icon {
      position: absolute;
      top: 50%;
      left: 50%;
      width: 1.15rem;
      height: 1.15rem;
      fill: none;
      stroke: currentColor;
      stroke-width: 1.7;
      stroke-linecap: round;
      stroke-linejoin: round;
      transform-origin: center;
    }
    .theme-icon-sun { opacity: 0; transform: translate(-50%, -50%) rotate(-12deg) scale(.88); }
    .theme-icon-moon { opacity: 1; transform: translate(-50%, -50%) rotate(0) scale(1); }
    :root[data-theme="dark"] .theme-icon-sun { opacity: 1; transform: translate(-50%, -50%) rotate(0) scale(1); }
    :root[data-theme="dark"] .theme-icon-moon { opacity: 0; transform: translate(-50%, -50%) rotate(12deg) scale(.88); }
    .visually-hidden {
      position: absolute !important;
      width: 1px;
      height: 1px;
      padding: 0;
      margin: -1px;
      overflow: hidden;
      clip: rect(0, 0, 0, 0);
      clip-path: inset(50%);
      white-space: nowrap;
      border: 0;
    }
    .mobile-cell-label { display: none; }
    .mobile-sort { display: none; }
    .listing-panel { overflow: hidden; border: 1px solid var(--border); border-radius: .8rem; background: var(--surface); }
    .listing-table { width: 100%; border-collapse: collapse; table-layout: fixed; }
    .listing-table th, .listing-table td { padding: .82rem 1.05rem; text-align: left; border-bottom: 1px solid var(--border); }
    .listing-table th { background: var(--surface-subtle); color: var(--muted); font-size: .8rem; font-weight: 650; letter-spacing: .015em; }
    .listing-table th.size, .listing-table td.size { width: 9rem; text-align: right; white-space: nowrap; }
    .listing-table th.modified, .listing-table td.modified { width: 14.5rem; white-space: nowrap; }
    .listing-table tbody tr:last-child td { border-bottom: 0; }
    .listing-table td.name { overflow-wrap: anywhere; }
    .listing-table td.name a { font-weight: 525; }
    .listing-table .directory-entry td.name a { font-weight: 650; }
    .listing-table td.size, .listing-table td.modified { color: var(--muted); font-size: .875rem; font-variant-numeric: tabular-nums; }
    .sort-link { display: inline-flex; min-height: 2rem; align-items: center; gap: .35rem; color: inherit; }
    .sort-link:hover { color: var(--text); }
    .sort-indicator { display: inline-flex; width: 1em; height: 1em; align-items: center; justify-content: center; color: var(--muted); opacity: .7; }
    .sort-icon { display: block; width: 1em; height: 1em; fill: none; stroke: currentColor; stroke-width: 1.35; stroke-linecap: round; stroke-linejoin: round; }
    .sort-link.is-active { color: var(--text); }
    .sort-link.is-active .sort-indicator { color: var(--link); opacity: 1; }
    .empty-state { color: var(--muted); text-align: center !important; }
    .pager { display: flex; flex-wrap: wrap; justify-content: space-between; gap: .75rem; margin-top: 1rem; }
    .pager a {
      display: inline-flex;
      min-height: 2.75rem;
      align-items: center;
      padding: .45rem .8rem;
      border: 1px solid var(--border);
      border-radius: .6rem;
      background: var(--surface);
    }
    .pager a:hover { border-color: var(--border-strong); background: var(--surface-subtle); text-decoration: none; }
    .readme { margin-top: 2.5rem; overflow-wrap: anywhere; }
    .readme h1, .readme h2, .readme h3 { letter-spacing: -.02em; line-height: 1.25; }
    .readme h1 { font-size: 1.8rem; }
    .readme h2 { margin-top: 1.8rem; font-size: 1.4rem; }
    .readme h3 { margin-top: 1.5rem; font-size: 1.15rem; }
    .readme pre { overflow: auto; padding: 1rem; border: 1px solid var(--border); border-radius: .55rem; background: var(--surface-subtle); }
    .readme code { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
    .readme img { max-width: 100%; height: auto; }
    .readme table { display: block; width: 100%; overflow-x: auto; border-collapse: collapse; }
    .readme th, .readme td { padding: .5rem .65rem; border: 1px solid var(--border); text-align: left; }
    .readme blockquote { margin-left: 0; padding-left: 1rem; border-left: 3px solid var(--border-strong); color: var(--muted); }
    .readme .markdown-alert {
      --alert-color: var(--alert-note);
      margin: 1rem 0;
      padding: .8rem 1rem;
      border-left: .25rem solid var(--alert-color);
      border-radius: 0 .55rem .55rem 0;
      background: color-mix(in srgb, var(--alert-color) 8%, transparent);
      color: var(--text);
    }
    .readme .markdown-alert-note { --alert-color: var(--alert-note); }
    .readme .markdown-alert-tip { --alert-color: var(--alert-tip); }
    .readme .markdown-alert-important { --alert-color: var(--alert-important); }
    .readme .markdown-alert-warning { --alert-color: var(--alert-warning); }
    .readme .markdown-alert-caution { --alert-color: var(--alert-caution); }
    .readme .markdown-alert-title { margin: 0 0 .35rem; color: var(--alert-color); font-weight: 650; }
    .readme .markdown-alert > .markdown-alert-title + p { margin-top: 0; }
    .readme .markdown-alert > :last-child { margin-bottom: 0; }
    @media (hover: hover) {
      .listing-table tbody tr:not(.empty-row):hover { background: var(--row-hover); }
    }
    .theme-ready,
    .theme-ready body,
    .theme-ready a,
    .theme-ready .theme-toggle,
    .theme-ready .breadcrumbs,
    .theme-ready .breadcrumbs .separator,
    .theme-ready .sort-indicator,
    .theme-ready .listing-panel,
    .theme-ready .listing-table tr,
    .theme-ready .listing-table th,
    .theme-ready .listing-table td,
    .theme-ready .pager a,
    .theme-ready .readme pre,
    .theme-ready .readme th,
    .theme-ready .readme td,
    .theme-ready .readme blockquote,
    .theme-ready .markdown-alert-title {
      transition: background-color 200ms ease-out, color 200ms ease-out, border-color 200ms ease-out;
    }
    .theme-ready .theme-icon { transition: opacity 200ms ease-out, transform 200ms ease-out; }
    @media (max-width: 42rem) {
      body { padding: 1rem .8rem 3rem; font-size: .95rem; }
      .topline { align-items: center; }
      .page-header h1 { margin-top: 1rem; font-size: clamp(1.8rem, 10vw, 2.35rem); }
      .mobile-sort { display: flex; flex-wrap: wrap; align-items: center; gap: .45rem; margin-bottom: .7rem; color: var(--muted); font-size: .84rem; }
      .sort-chip { display: inline-flex; min-height: 2.75rem; align-items: center; gap: .25rem; padding: .35rem .7rem; border: 1px solid var(--border); border-radius: 999px; background: var(--surface); }
      .sort-chip:hover { text-decoration: none; background: var(--surface-subtle); }
      .sort-chip.is-active { border-color: var(--border-strong); color: var(--text); }
      .listing-panel { border-radius: .75rem; }
      .listing-table, .listing-table tbody { display: block; }
      .listing-table thead { display: none; }
      .listing-table tr { display: grid; grid-template-columns: auto minmax(0, 1fr); gap: .35rem .8rem; padding: .82rem .85rem; border-bottom: 1px solid var(--border); }
      .listing-table tbody tr:last-child { border-bottom: 0; }
      .listing-table td { display: block; width: auto !important; padding: 0; border: 0; text-align: left !important; white-space: normal !important; }
      .listing-table td.name { grid-column: 1 / -1; font-size: 1rem; }
      .listing-table td.size, .listing-table td.modified { font-size: .8rem; }
      .mobile-cell-label { display: inline; margin-right: .3rem; color: var(--muted); }
      .listing-table td.modified { justify-self: end; text-align: right !important; }
      .listing-table .parent-entry td.size, .listing-table .parent-entry td.modified { display: none; }
      .listing-table .empty-row { display: block; }
      .listing-table .empty-state { text-align: left !important; }
      .pager { align-items: stretch; }
      .pager span { flex: 1 1 auto; }
      .pager span:last-child { text-align: right; }
      .readme { margin-top: 2rem; }
    }
    @media (max-width: 26rem) {
      .listing-table tr { grid-template-columns: 1fr; }
      .listing-table td.modified { justify-self: start; text-align: left !important; }
    }
    @media (prefers-reduced-motion: reduce) {
      .theme-ready, .theme-ready *, .theme-ready *::before, .theme-ready *::after { transition: none !important; }
    }
  </style>
</head>
<body>
  <main>
    <header class="page-header">
      <div class="topline">
        <nav class="breadcrumbs" aria-label="Breadcrumb">{{range $index, $part := .Breadcrumbs}}{{if $index}}<span class="separator" aria-hidden="true">›</span>{{end}}<a href="{{$part.Href}}"{{if $part.Current}} aria-current="page"{{end}}>{{$part.Name}}</a>{{end}}</nav>
        <button id="theme-toggle" class="theme-toggle" type="button" hidden aria-label="Dark mode" aria-pressed="false"><svg class="theme-icon theme-icon-sun" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="4"></circle><path d="M12 2v2M12 20v2M4.93 4.93l1.42 1.42M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.42-1.42M17.66 6.34l1.41-1.41"></path></svg><svg class="theme-icon theme-icon-moon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg></button>
      </div>
      <h1>{{.Title}}</h1>
    </header>
    <nav class="mobile-sort" aria-label="Sort directory"><span>Sort:</span>{{range .SortLinks}}<a class="sort-chip{{if .Active}} is-active{{end}}" href="{{.Href}}"{{if .Active}} aria-current="true" aria-label="{{.Label}}, currently sorted {{.AriaSort}}; {{.AriaLabel}}"{{else}} aria-label="{{.AriaLabel}}"{{end}}>{{.Label}} {{template "sort-indicator" .}}</a>{{end}}</nav>
    <div class="listing-panel">
      <table class="listing-table">
        <caption class="visually-hidden">Directory contents</caption>
        <thead><tr>{{range .SortLinks}}<th class="{{.FieldClass}}" scope="col"{{if .AriaSort}} aria-sort="{{.AriaSort}}"{{end}}><a class="sort-link{{if .Active}} is-active{{end}}" href="{{.Href}}" aria-label="{{.AriaLabel}}">{{.Label}} {{template "sort-indicator" .}}</a></th>{{end}}</tr></thead>
        <tbody>
          {{if .ParentHref}}<tr class="parent-entry"><td class="name"><a href="{{.ParentHref}}" aria-label="Parent directory"><span aria-hidden="true">../</span></a></td><td class="size"><span class="mobile-cell-label">Size</span>—</td><td class="modified"><span class="mobile-cell-label">Modified</span></td></tr>{{end}}
          {{range .Entries}}<tr{{if .Directory}} class="directory-entry"{{end}}><td class="name"><a href="{{.Href}}">{{.Name}}{{if .Directory}}/{{end}}</a></td><td class="size"><span class="mobile-cell-label">Size</span>{{.Size}}</td><td class="modified"><span class="mobile-cell-label">Modified</span><time datetime="{{.ModifiedTime}}" title="Beijing time (UTC+8)">{{.Modified}}</time></td></tr>{{end}}
          {{if not .Entries}}<tr class="empty-row"><td class="empty-state" colspan="3">This directory is empty.</td></tr>{{end}}
        </tbody>
      </table>
    </div>
    {{if or .PreviousHref .NextHref}}<nav class="pager" aria-label="Directory pages"><span>{{if .PreviousHref}}<a rel="prev" href="{{.PreviousHref}}">← Previous page</a>{{end}}</span><span>{{if .NextHref}}<a rel="next" href="{{.NextHref}}">Next page →</a>{{end}}</span></nav>{{end}}
    {{if .README}}<article class="readme" aria-label="README">{{.README}}</article>{{end}}
  </main>
</body>
</html>`

const listingSortIndicatorTemplate = `{{define "sort-indicator"}}<span class="sort-indicator is-{{.Indicator}}" aria-hidden="true"><svg class="sort-icon" viewBox="0 0 12 12" focusable="false">{{if eq .Indicator "ascending"}}<path d="M6 10V2M2.75 5.25 6 2l3.25 3.25"></path>{{else if eq .Indicator "descending"}}<path d="M6 2v8m3.25-3.25L6 10 2.75 6.75"></path>{{else}}<path d="M3.25 9V3m-2 2 2-2 2 2M8.75 3v6m2-2-2 2-2-2"></path>{{end}}</svg></span>{{end}}`

var listingPageTemplate = template.Must(template.New("directory-listing").Parse(listingSortIndicatorTemplate + listingPageTemplatePrefix + listingThemeScript + listingPageTemplateSuffix))

var listingPageCSP = "default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-" + listingThemeScriptHash() + "'; script-src-attr 'none'; img-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

func listingThemeScriptHash() string {
	hash := sha256.Sum256([]byte(listingThemeScript))
	return base64.StdEncoding.EncodeToString(hash[:])
}

func (s *Server) serveDirectoryListing(w http.ResponseWriter, r *http.Request, root rootedFileOpener, directory *os.File, rootName string, cfg *models.StaticServeConfig) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid directory cursor")
		return
	}
	sortSpec, err := parseListingSort(query)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid directory sort")
		return
	}
	cursorValue, cursorPresent, err := listingQueryValue(query, "cursor")
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid directory cursor")
		return
	}
	if !cursorPresent {
		cursorValue = ""
	}
	cursor, err := decodeListingCursor(cursorValue)
	if err != nil || (cursor != nil && cursor.sort != sortSpec) {
		writeError(w, r, http.StatusBadRequest, "Invalid directory cursor")
		return
	}
	candidates, previousCursor, nextCursor, err := scanDirectoryPageWithSort(r.Context(), root, directory, rootName, sortSpec, cursor)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		}
		if errors.Is(err, errDirectoryTooLarge) || rootName == "." {
			writeRootUnavailable(w, r)
		} else {
			writeError(w, r, http.StatusNotFound, "Not found")
		}
		return
	}

	entries := make([]listingEntryView, 0, len(candidates))
	for _, candidate := range candidates {
		href := "./" + url.PathEscape(candidate.key.name)
		size := formatFileSize(candidate.size)
		if candidate.key.directory {
			href += "/"
			href = listingPageHref(href, sortSpec, "")
			size = "—"
		}
		modified, machineTime := formatModifiedTime(candidate.modified)
		entries = append(entries, listingEntryView{Name: candidate.key.name, Href: href, Directory: candidate.key.directory, Size: size, Modified: modified, ModifiedTime: machineTime})
	}

	readme := template.HTML("")
	if cfg.DirectoryListing.RenderReadme {
		readme = s.readme.render(root, joinRootName(rootName, "README.md"))
	}
	view := listingPageView{Title: "Index of " + r.URL.Path, Breadcrumbs: listingBreadcrumbs(r.URL.Path, sortSpec), SortLinks: listingSortLinks(sortSpec), Entries: entries, ParentHref: listingParentHref(r.URL.Path, sortSpec), README: readme}
	if nextCursor != "" {
		view.NextHref = listingPageHref("", sortSpec, nextCursor)
	}
	if previousCursor != "" {
		view.PreviousHref = listingPageHref("", sortSpec, previousCursor)
	}

	var body bytes.Buffer
	if err := listingPageTemplate.Execute(&body, view); err != nil {
		writeRootUnavailable(w, r)
		return
	}
	w.Header().Set("Cache-Control", generatedCacheControl)
	w.Header().Set("Content-Security-Policy", listingPageCSP)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(body.Len()))
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body.Bytes())
	}
}

func parseListingSort(query url.Values) (listingSort, error) {
	field := listingSortByName
	fieldValue, fieldPresent, err := listingQueryValue(query, "sort")
	if err != nil {
		return listingSort{}, err
	}
	if fieldPresent {
		switch fieldValue {
		case "name":
			field = listingSortByName
		case "size":
			field = listingSortBySize
		case "modified":
			field = listingSortByModified
		default:
			return listingSort{}, errors.New("unknown listing sort field")
		}
	}

	order := defaultListingSortOrder(field)
	orderValue, orderPresent, err := listingQueryValue(query, "order")
	if err != nil {
		return listingSort{}, err
	}
	if orderPresent {
		switch orderValue {
		case "asc":
			order = listingSortAscending
		case "desc":
			order = listingSortDescending
		default:
			return listingSort{}, errors.New("unknown listing sort order")
		}
	}
	return listingSort{field: field, order: order}, nil
}

func listingQueryValue(query url.Values, key string) (string, bool, error) {
	values, present := query[key]
	if !present {
		return "", false, nil
	}
	if len(values) != 1 || values[0] == "" {
		return "", false, errors.New("invalid listing query value")
	}
	return values[0], true, nil
}

func defaultListingSortOrder(field listingSortField) listingSortOrder {
	if field == listingSortByName {
		return listingSortAscending
	}
	return listingSortDescending
}

func (spec listingSort) fieldName() string {
	switch spec.field {
	case listingSortBySize:
		return "size"
	case listingSortByModified:
		return "modified"
	default:
		return "name"
	}
}

func (spec listingSort) orderName() string {
	if spec.order == listingSortDescending {
		return "desc"
	}
	return "asc"
}

func scanDirectoryPage(ctx context.Context, root rootedFileOpener, directory *os.File, rootName string, cursor *listingCursor) ([]listingCandidate, string, string, error) {
	sortSpec := defaultListingSort
	if cursor != nil {
		sortSpec = cursor.sort
	}
	return scanDirectoryPageWithSort(ctx, root, directory, rootName, sortSpec, cursor)
}

func scanDirectoryPageWithSort(ctx context.Context, root rootedFileOpener, directory *os.File, rootName string, sortSpec listingSort, cursor *listingCursor) ([]listingCandidate, string, string, error) {
	return scanDirectoryPageWithLimitsAndSort(ctx, root, directory, rootName, sortSpec, cursor, MaxDirectoryScannedEntries, MaxDirectoryVisibleEntries)
}

func scanDirectoryPageWithLimit(ctx context.Context, root rootedFileOpener, directory *os.File, rootName string, cursor *listingCursor, maxEntries int) ([]listingCandidate, string, string, error) {
	sortSpec := defaultListingSort
	if cursor != nil {
		sortSpec = cursor.sort
	}
	return scanDirectoryPageWithLimitsAndSort(ctx, root, directory, rootName, sortSpec, cursor, maxEntries, maxEntries)
}

func scanDirectoryPageWithLimits(ctx context.Context, root rootedFileOpener, directory *os.File, rootName string, cursor *listingCursor, maxScannedEntries, maxVisibleEntries int) ([]listingCandidate, string, string, error) {
	sortSpec := defaultListingSort
	if cursor != nil {
		sortSpec = cursor.sort
	}
	return scanDirectoryPageWithLimitsAndSort(ctx, root, directory, rootName, sortSpec, cursor, maxScannedEntries, maxVisibleEntries)
}

func scanDirectoryPageWithLimitsAndSort(ctx context.Context, root rootedFileOpener, directory *os.File, rootName string, sortSpec listingSort, cursor *listingCursor, maxScannedEntries, maxVisibleEntries int) ([]listingCandidate, string, string, error) {
	const batchSize = 1024
	forward := cursor == nil || cursor.direction == cursorAfter
	forwardValues := &listingCandidateHeap{sort: sortSpec}
	backwardValues := &listingCandidateHeap{sort: sortSpec, minimum: true}
	heap.Init(forwardValues)
	heap.Init(backwardValues)
	scanned := 0
	visible := 0
	for {
		select {
		case <-ctx.Done():
			return nil, "", "", ctx.Err()
		default:
		}
		batch, err := directory.ReadDir(batchSize)
		for _, entry := range batch {
			select {
			case <-ctx.Done():
				return nil, "", "", ctx.Err()
			default:
			}
			scanned++
			if scanned > maxScannedEntries {
				return nil, "", "", errDirectoryTooLarge
			}
			candidate, ok := inspectListingCandidate(root, rootName, entry)
			if !ok {
				continue
			}
			visible++
			if visible > maxVisibleEntries {
				return nil, "", "", errDirectoryTooLarge
			}
			if cursor != nil {
				comparison := compareListingCandidates(candidate, cursor.candidate, sortSpec)
				if (forward && comparison <= 0) || (!forward && comparison >= 0) {
					continue
				}
			}
			if forward {
				if forwardValues.Len() < DefaultPageSize+1 {
					heap.Push(forwardValues, candidate)
				} else if compareListingCandidates(candidate, forwardValues.values[0], sortSpec) < 0 {
					heap.Pop(forwardValues)
					heap.Push(forwardValues, candidate)
				}
			} else {
				if backwardValues.Len() < DefaultPageSize+1 {
					heap.Push(backwardValues, candidate)
				} else if compareListingCandidates(candidate, backwardValues.values[0], sortSpec) > 0 {
					heap.Pop(backwardValues)
					heap.Push(backwardValues, candidate)
				}
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, "", "", err
		}
	}

	var result []listingCandidate
	if forward {
		result = append(result, forwardValues.values...)
	} else {
		result = append(result, backwardValues.values...)
	}
	sort.Slice(result, func(i, j int) bool { return compareListingCandidates(result[i], result[j], sortSpec) < 0 })
	hasPrevious := forward && cursor != nil
	hasNext := false
	if forward && len(result) > DefaultPageSize {
		result = result[:DefaultPageSize]
		hasNext = true
	} else if !forward && len(result) > DefaultPageSize {
		result = result[len(result)-DefaultPageSize:]
		hasPrevious = true
	}
	if !forward {
		hasNext = true
	}
	if len(result) == 0 {
		hasPrevious, hasNext = false, false
	}
	previousCursor := ""
	nextCursor := ""
	if hasPrevious {
		previousCursor = encodeListingCursor(cursorBefore, sortSpec, result[0])
	}
	if hasNext {
		nextCursor = encodeListingCursor(cursorAfter, sortSpec, result[len(result)-1])
	}
	return result, previousCursor, nextCursor, nil
}

func inspectListingCandidate(root rootedFileOpener, rootName string, entry os.DirEntry) (listingCandidate, bool) {
	name := entry.Name()
	if !safeVisibleName(name) || (rootName == "." && strings.HasPrefix(name, "__")) {
		return listingCandidate{}, false
	}
	info, err := entry.Info()
	if err != nil {
		return listingCandidate{}, false
	}
	if info.Mode()&os.ModeSymlink != 0 {
		file, openErr := openRootFileForRead(root, joinRootName(rootName, name))
		if openErr != nil {
			return listingCandidate{}, false
		}
		info, err = file.Stat()
		file.Close()
		if err != nil {
			return listingCandidate{}, false
		}
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return listingCandidate{}, false
	}
	return listingCandidate{key: newListingKey(info.IsDir(), name), size: info.Size(), modified: info.ModTime()}, true
}

func compareListingCandidates(first, second listingCandidate, sortSpec listingSort) int {
	if first.key.directory != second.key.directory {
		if first.key.directory {
			return -1
		}
		return 1
	}
	if sortSpec.field == listingSortByName {
		comparison := compareListingNames(first.key, second.key)
		if sortSpec.order == listingSortDescending {
			return -comparison
		}
		return comparison
	}
	if sortSpec.field == listingSortBySize {
		if first.key.directory {
			return compareListingNames(first.key, second.key)
		}
		comparison := compareInt64(first.size, second.size)
		if comparison != 0 {
			if sortSpec.order == listingSortDescending {
				return -comparison
			}
			return comparison
		}
		return compareListingNames(first.key, second.key)
	}
	comparison := first.modified.Compare(second.modified)
	if comparison != 0 {
		if sortSpec.order == listingSortDescending {
			return -comparison
		}
		return comparison
	}
	return compareListingNames(first.key, second.key)
}

func compareInt64(first, second int64) int {
	switch {
	case first < second:
		return -1
	case first > second:
		return 1
	default:
		return 0
	}
}

func compareListingKeys(first, second listingKey) int {
	if first.directory != second.directory {
		if first.directory {
			return -1
		}
		return 1
	}
	return compareListingNames(first, second)
}

func compareListingNames(first, second listingKey) int {
	if comparison := strings.Compare(first.folded, second.folded); comparison != 0 {
		return comparison
	}
	return strings.Compare(first.name, second.name)
}

func newListingKey(directory bool, name string) listingKey {
	return listingKey{directory: directory, name: name, folded: strings.ToLower(name)}
}

func encodeListingCursor(direction cursorDirection, sortSpec listingSort, candidate listingCandidate) string {
	typeByte := byte(1)
	if candidate.key.directory {
		typeByte = 0
	}
	payload := make([]byte, listingCursorHeaderSize, listingCursorHeaderSize+len(candidate.key.name))
	payload[0] = listingCursorVersion
	payload[1] = byte(direction)
	payload[2] = byte(sortSpec.field)
	payload[3] = byte(sortSpec.order)
	payload[4] = typeByte
	binary.BigEndian.PutUint64(payload[5:13], uint64(candidate.size))
	binary.BigEndian.PutUint64(payload[13:21], uint64(candidate.modified.Unix()))
	binary.BigEndian.PutUint32(payload[21:25], uint32(candidate.modified.Nanosecond()))
	payload = append(payload, candidate.key.name...)
	return base64.RawURLEncoding.EncodeToString(payload)
}

func decodeListingCursor(value string) (*listingCursor, error) {
	if value == "" {
		return nil, nil
	}
	if len(value) > maxListingCursorBytes {
		return nil, errors.New("cursor is too long")
	}
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(payload) < 3 {
		return nil, errors.New("cursor is malformed")
	}
	if payload[0] != listingCursorVersion {
		return decodeLegacyListingCursor(payload)
	}
	if len(payload) <= listingCursorHeaderSize || payload[1] > byte(cursorBefore) || payload[2] > byte(listingSortByModified) || payload[3] > byte(listingSortDescending) || payload[4] > 1 {
		return nil, errors.New("cursor is malformed")
	}
	name := string(payload[listingCursorHeaderSize:])
	if !safeVisibleName(name) || len(name) > 255 {
		return nil, errors.New("cursor name is invalid")
	}
	size := int64(binary.BigEndian.Uint64(payload[5:13]))
	nanosecond := binary.BigEndian.Uint32(payload[21:25])
	if size < 0 || nanosecond >= 1_000_000_000 {
		return nil, errors.New("cursor key is invalid")
	}
	modified := time.Unix(int64(binary.BigEndian.Uint64(payload[13:21])), int64(nanosecond)).UTC()
	return &listingCursor{direction: cursorDirection(payload[1]), sort: listingSort{field: listingSortField(payload[2]), order: listingSortOrder(payload[3])}, candidate: listingCandidate{key: newListingKey(payload[4] == 0, name), size: size, modified: modified}}, nil
}

func decodeLegacyListingCursor(payload []byte) (*listingCursor, error) {
	if len(payload) < 3 || payload[0] > byte(cursorBefore) || payload[1] > 1 {
		return nil, errors.New("cursor is malformed")
	}
	name := string(payload[2:])
	if !safeVisibleName(name) || len(name) > 255 {
		return nil, errors.New("cursor name is invalid")
	}
	return &listingCursor{direction: cursorDirection(payload[0]), sort: defaultListingSort, candidate: listingCandidate{key: newListingKey(payload[1] == 0, name)}}, nil
}

func listingSortLinks(active listingSort) []listingSortLinkView {
	fields := []struct {
		field listingSortField
		label string
	}{{listingSortByName, "Name"}, {listingSortBySize, "Size"}, {listingSortByModified, "Modified"}}
	result := make([]listingSortLinkView, 0, len(fields))
	for _, item := range fields {
		order := defaultListingSortOrder(item.field)
		isActive := active.field == item.field
		if isActive {
			if active.order == listingSortAscending {
				order = listingSortDescending
			} else {
				order = listingSortAscending
			}
		}
		target := listingSort{field: item.field, order: order}
		directionLabel := "ascending"
		if order == listingSortDescending {
			directionLabel = "descending"
		}
		ariaSort := ""
		indicator := "unsorted"
		if isActive {
			if active.order == listingSortAscending {
				ariaSort = "ascending"
				indicator = "ascending"
			} else {
				ariaSort = "descending"
				indicator = "descending"
			}
		}
		result = append(result, listingSortLinkView{FieldClass: activeSortFieldClass(item.field), Label: item.label, Href: listingPageHref("", target, ""), AriaLabel: "Sort by " + item.label + ", " + directionLabel, AriaSort: ariaSort, Indicator: indicator, Active: isActive})
	}
	return result
}

func activeSortFieldClass(field listingSortField) string {
	switch field {
	case listingSortBySize:
		return "size"
	case listingSortByModified:
		return "modified"
	default:
		return "name"
	}
}

func listingPageHref(path string, sortSpec listingSort, cursor string) string {
	query := url.Values{}
	query.Set("sort", sortSpec.fieldName())
	query.Set("order", sortSpec.orderName())
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	return path + "?" + query.Encode()
}

func listingBreadcrumbs(requestPath string, sortSpec listingSort) []breadcrumbView {
	result := []breadcrumbView{{Name: "root", Href: listingPageHref("/", sortSpec, "")}}
	trimmed := strings.Trim(requestPath, "/")
	if trimmed != "" {
		components := strings.Split(trimmed, "/")
		var href strings.Builder
		href.WriteByte('/')
		for _, component := range components {
			href.WriteString(url.PathEscape(component))
			href.WriteByte('/')
			result = append(result, breadcrumbView{Name: component, Href: listingPageHref(href.String(), sortSpec, "")})
		}
	}
	result[len(result)-1].Current = true
	return result
}

func listingParentHref(requestPath string, sortSpec listingSort) string {
	if requestPath == "/" {
		return ""
	}
	trimmed := strings.TrimSuffix(requestPath, "/")
	index := strings.LastIndexByte(trimmed, '/')
	if index <= 0 {
		return listingPageHref("/", sortSpec, "")
	}
	return listingPageHref(escapeListingDirectoryPath(trimmed[:index+1]), sortSpec, "")
}

func escapeListingDirectoryPath(path string) string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return "/"
	}
	var escaped strings.Builder
	escaped.WriteByte('/')
	for _, component := range strings.Split(trimmed, "/") {
		escaped.WriteString(url.PathEscape(component))
		escaped.WriteByte('/')
	}
	return escaped.String()
}

func formatFileSize(size int64) string {
	if size < 0 {
		return "—"
	}
	units := [...]string{"B", "KB", "MB", "GB", "TB", "PB", "EB"}
	if size < 1024 {
		return strconv.FormatInt(size, 10) + " B"
	}
	raw := uint64(size)
	unit := 0
	scale := uint64(1)
	for unit < len(units)-1 && raw >= scale*1024 {
		scale *= 1024
		unit++
	}
	whole, remainder := raw/scale, raw%scale
	tenths := whole*10 + (remainder*10+scale/2)/scale
	if tenths >= 1024*10 && unit < len(units)-1 {
		unit++
		tenths = 10
	}
	formatted := strconv.FormatUint(tenths/10, 10)
	if tenths%10 != 0 {
		formatted += "." + strconv.FormatUint(tenths%10, 10)
	}
	return formatted + " " + units[unit]
}

var beijingTimeZone = time.FixedZone("UTC+8", 8*60*60)

func formatModifiedTime(value time.Time) (string, string) {
	if value.IsZero() {
		return "", ""
	}
	value = value.In(beijingTimeZone)
	return value.Format("2006-01-02 15:04:05"), value.Format(time.RFC3339)
}
