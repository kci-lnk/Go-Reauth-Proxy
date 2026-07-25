package response

import (
	"go-reauth-proxy/pkg/i18n"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/version"
	"html/template"
	"net/http"
	"strings"
	"time"
)

var htmlFuncMap = template.FuncMap{
	"ensureSlash": func(path string) string {
		if !strings.HasSuffix(path, "/") {
			return path + "/"
		}
		return path
	},
	"hostDisplayLabel": GatewayPortalHostLabel,
	"hostFaviconURL": func(rule models.HostRule, portalConfig models.GatewayPortalConfig) template.URL {
		return template.URL(GatewayPortalHostFavicon(rule, portalConfig))
	},
}

const selectStyle = `
<style>
  :root {
    --foreground: hsl(220 35% 13%);
    --card: rgba(255, 255, 255, 0.74);
    --card-strong: rgba(255, 255, 255, 0.86);
    --muted: rgba(255, 255, 255, 0.52);
    --muted-foreground: hsl(218 13% 42%);
    --border: rgba(255, 255, 255, 0.72);
    --line: rgba(32, 50, 79, 0.11);
    --shadow: 0 22px 60px rgba(39, 55, 85, 0.14);
    --radius: 8px;
    --destructive: hsl(0 84.2% 60.2%);
    --destructive-foreground: hsl(0 0% 98%);
    --secondary: rgba(243, 247, 250, 0.82);
    --secondary-foreground: hsl(220 35% 13%);
  }

  body.select-page {
    --page-padding-x: clamp(1rem, 4vw, 3rem);
    --page-padding-top: clamp(1.5rem, 4vw, 4.5rem);
    --page-padding-bottom: clamp(1.75rem, 5vw, 4.5rem);
    background: #eef5fb;
    color: var(--foreground);
    font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    height: auto;
    min-height: 100vh;
    min-height: 100dvh;
    width: 100%;
    display: flex;
    flex-direction: column;
    align-items: stretch;
    justify-content: flex-start;
    overflow-x: hidden;
    padding: var(--page-padding-top) var(--page-padding-x) var(--page-padding-bottom);
    padding-top: calc(var(--page-padding-top) + constant(safe-area-inset-top));
    padding-right: calc(var(--page-padding-x) + constant(safe-area-inset-right));
    padding-bottom: calc(var(--page-padding-bottom) + constant(safe-area-inset-bottom));
    padding-left: calc(var(--page-padding-x) + constant(safe-area-inset-left));
    padding-top: calc(var(--page-padding-top) + env(safe-area-inset-top, 0px));
    padding-right: calc(var(--page-padding-x) + env(safe-area-inset-right, 0px));
    padding-bottom: calc(var(--page-padding-bottom) + env(safe-area-inset-bottom, 0px));
    padding-left: calc(var(--page-padding-x) + env(safe-area-inset-left, 0px));
    position: relative;
    isolation: isolate;
  }

  body.select-page::before {
    content: "";
    position: fixed;
    inset: -18vmax;
    z-index: 0;
    pointer-events: none;
    background:
      linear-gradient(118deg,
        rgba(87, 172, 236, 0.92) 0%,
        rgba(126, 224, 188, 0.88) 29%,
        rgba(255, 205, 154, 0.86) 55%,
        rgba(205, 187, 255, 0.78) 78%,
        rgba(95, 201, 224, 0.9) 100%);
    background-size: 220% 220%;
    filter: blur(46px) saturate(1.12);
    opacity: 0.9;
    transform: translate3d(0, 0, 0) scale(1.02);
    animation: selectGradientShift 18s ease-in-out infinite alternate;
  }

  body.select-page::after {
    content: "";
    position: fixed;
    inset: 0;
    z-index: 0;
    pointer-events: none;
    background:
      linear-gradient(180deg,
        rgba(255, 255, 255, 0.8) 0%,
        rgba(255, 255, 255, 0.58) 45%,
        rgba(255, 255, 255, 0.76) 100%);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
  }

  @keyframes selectGradientShift {
    0% {
      background-position: 0% 35%;
      transform: translate3d(-1.5%, -1%, 0) scale(1.02);
    }
    50% {
      background-position: 85% 55%;
    }
    100% {
      background-position: 100% 68%;
      transform: translate3d(1.5%, 1%, 0) scale(1.05);
    }
  }

  @media (prefers-reduced-motion: reduce) {
    body.select-page::before {
      animation: none;
    }
  }

  .select-container {
    position: relative;
    z-index: 1;
    width: 100%;
    max-width: 1180px;
    margin: 0 auto;
    min-height: 0;
    flex: 1 1 auto;
    display: flex;
    flex-direction: column;
  }

  /* Header card */
  .header-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: clamp(1.25rem, 3vw, 2rem);
    margin-bottom: 1rem;
    box-shadow: var(--shadow);
    backdrop-filter: blur(18px);
    -webkit-backdrop-filter: blur(18px);
  }
  .header-top {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 1rem;
  }
  .header-brand {
    display: flex;
    min-width: 0;
    align-items: center;
    gap: 1rem;
  }
  .header-logo {
    width: 52px;
    height: 52px;
    border-radius: var(--radius);
    flex-shrink: 0;
    box-shadow: 0 10px 24px rgba(39, 55, 85, 0.12);
  }
  .header-kicker {
    margin-bottom: 0.25rem;
    color: hsl(205 38% 33%);
    font-size: 0.75rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }
  .header-title {
    font-size: 1.75rem;
    color: var(--foreground);
    line-height: 1.2;
    margin: 0;
  }
  .header-desc {
    font-size: 0.875rem;
    color: var(--muted-foreground);
    margin-top: 0.5rem;
    line-height: 1.5;
    max-width: 42rem;
  }

  /* Logout button */
  .btn-logout {
    display: inline-flex;
    align-items: center;
    gap: 0.375rem;
    padding: 0.5rem 1rem;
    font-size: 0.8125rem;
    font-weight: 500;
    border-radius: calc(var(--radius) - 2px);
    border: 1px solid var(--border);
    background: var(--card-strong);
    color: var(--muted-foreground);
    cursor: pointer;
    transition: all 0.15s ease;
    white-space: nowrap;
    font-family: inherit;
    line-height: 1.5;
  }
  .btn-logout:hover {
    background: rgba(255, 255, 255, 0.96);
    color: var(--foreground);
    border-color: rgba(32, 50, 79, 0.18);
    box-shadow: 0 10px 24px rgba(39, 55, 85, 0.1);
  }
  .btn-logout svg {
    width: 14px;
    height: 14px;
    flex-shrink: 0;
  }

  /* Route cards */
  .routes-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(min(100%, 17.5rem), 1fr));
    gap: 1rem;
    align-items: stretch;
  }
  .route-groups {
    grid-column: 1 / -1;
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }
  .route-group {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  .route-group-header {
    display: flex;
    align-items: center;
    gap: 0.625rem;
    padding: 0 0.25rem;
  }
  .route-group-title {
    font-size: 1rem;
    font-weight: 700;
    color: var(--foreground);
  }
  .route-group-count {
    min-width: 1.5rem;
    padding: 0.125rem 0.5rem;
    border-radius: 999px;
    background: var(--card-strong);
    color: var(--muted-foreground);
    font-size: 0.75rem;
    text-align: center;
  }

  .route-card {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 1rem;
    min-height: 7.5rem;
    padding: 1.125rem;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    text-decoration: none;
    color: inherit;
    transition: all 0.2s ease;
    box-shadow: 0 14px 34px rgba(39, 55, 85, 0.1);
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
  }
  .route-card:hover {
    background: rgba(255, 255, 255, 0.9);
    border-color: rgba(32, 50, 79, 0.17);
    box-shadow: 0 20px 42px rgba(39, 55, 85, 0.16);
    transform: translateY(-2px);
  }
  .route-main {
    display: flex;
    flex: 1 1 auto;
    min-width: 0;
    align-items: flex-start;
    gap: 0.875rem;
  }
  .route-icon-shell {
    width: 42px;
    height: 42px;
    flex-shrink: 0;
    display: grid;
    place-items: center;
    overflow: hidden;
    border: 1px solid var(--line);
    border-radius: var(--radius);
    background: rgba(255, 255, 255, 0.62);
  }
  .route-icon-img {
    width: 100%;
    height: 100%;
    padding: 5px;
    object-fit: contain;
  }
  .route-icon-fallback {
    width: 20px;
    height: 20px;
    color: hsl(205 32% 34%);
  }
  .route-copy {
    flex: 1 1 auto;
    min-width: 0;
  }
  .route-path {
    font-size: 0.9375rem;
    font-weight: 600;
    color: var(--foreground);
    margin-bottom: 0.25rem;
    overflow-wrap: anywhere;
  }
  .route-target {
    font-size: 0.8125rem;
    color: var(--muted-foreground);
    line-height: 1.45;
    overflow-wrap: anywhere;
  }
  .route-arrow {
    color: var(--muted-foreground);
    transition: transform 0.2s ease, color 0.2s ease;
    flex-shrink: 0;
  }
  .route-card:hover .route-arrow {
    transform: translateX(3px);
    color: var(--foreground);
  }

  /* Empty state */
  .empty-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 3rem 1.5rem;
    text-align: center;
    color: var(--muted-foreground);
    font-size: 0.875rem;
    box-shadow: var(--shadow);
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
  }
  .empty-icon {
    width: 48px;
    height: 48px;
    margin: 0 auto 1rem;
    color: hsl(0 0% 80%);
  }

  /* Footer */
  .select-footer {
    text-align: center;
    margin-top: auto;
    padding-top: 2rem;
  }
  .select-footer p {
    font-size: 0.75rem;
    color: hsl(218 13% 38%);
  }
  .select-footer a {
    color: hsl(205 35% 30%);
    text-decoration: none;
    transition: color 0.15s;
  }
  .select-footer a:hover {
    color: var(--foreground);
  }

  /* Logout modal */
  .modal-overlay {
    position: fixed;
    top: 0; right: 0; bottom: 0; left: 0;
    background-color: rgba(0, 0, 0, 0.5);
    backdrop-filter: blur(4px);
    -webkit-backdrop-filter: blur(4px);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 50;
    opacity: 0;
    pointer-events: none;
    transition: opacity 0.2s ease-in-out;
  }
  .modal-overlay.active {
    opacity: 1;
    pointer-events: auto;
  }
  .modal-content {
    background-color: rgba(255, 255, 255, 0.94);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 1.5rem;
    width: 100%;
    max-width: 24rem;
    box-shadow: 0 20px 40px -4px rgba(0, 0, 0, 0.15);
    transform: scale(0.95) translateY(10px);
    transition: transform 0.2s cubic-bezier(0.175, 0.885, 0.32, 1.275);
  }
  .modal-overlay.active .modal-content {
    transform: scale(1) translateY(0);
  }
  .modal-title {
    font-size: 1.125rem;
    font-weight: 600;
    color: var(--foreground);
    margin: 0 0 0.5rem;
    letter-spacing: -0.01em;
  }
  .modal-message {
    font-size: 0.875rem;
    color: var(--muted-foreground);
    margin: 0 0 1.5rem;
    line-height: 1.5;
  }
  .modal-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
  }
  .modal-btn {
    padding: 0.5rem 1rem;
    border-radius: calc(var(--radius) - 2px);
    font-size: 0.8125rem;
    font-weight: 500;
    cursor: pointer;
    border: none;
    transition: all 0.15s;
    font-family: inherit;
  }
  .modal-btn-cancel {
    background: var(--secondary);
    color: var(--secondary-foreground);
    border: 1px solid var(--border);
  }
  .modal-btn-cancel:hover {
    background: hsl(0 0% 92%);
  }
  .modal-btn-confirm {
    background: var(--destructive);
    color: var(--destructive-foreground);
  }
  .modal-btn-confirm:hover {
    background: hsl(0 84.2% 55%);
  }

  @media (min-width: 860px) {
    .routes-grid {
      grid-template-columns: repeat(auto-fit, minmax(18.5rem, 1fr));
    }
  }

  @media (max-width: 480px) {
    body.select-page {
      --page-padding-x: 0.75rem;
      --page-padding-top: 1.5rem;
      --page-padding-bottom: 1.25rem;
    }
    .header-card {
      padding: 1.25rem;
    }
    .header-top {
      flex-direction: column;
      gap: 0.75rem;
    }
    .header-brand {
      align-items: flex-start;
    }
    .header-logo {
      width: 44px;
      height: 44px;
    }
    .header-title {
      font-size: 1.375rem;
    }
    .btn-logout {
      width: 100%;
      justify-content: center;
    }
    .route-card {
      padding: 1rem 1.25rem;
      min-height: auto;
    }
    .modal-content {
      margin: 0 1rem;
    }
  }
</style>
`

const selectContent = `
{{define "content"}}
` + selectStyle + `
<div class="select-container">
	<div class="header-card">
		<div class="header-top">
			<div class="header-brand">
				<img class="header-logo" src="/__assets__/favicon/android-chrome-512x512.png" alt="Logo">
				<div>
					<div class="header-kicker">{{.Title}}</div>
					<h1 class="header-title">Go Reauth Proxy</h1>
					<p class="header-desc">{{index .Labels "selectDescription"}}</p>
				</div>
			</div>
			<button onclick="document.getElementById('logout-modal').classList.add('active')" class="btn-logout">
				<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
					<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
					<polyline points="16 17 21 12 16 7"/>
					<line x1="21" y1="12" x2="9" y2="12"/>
				</svg>
				{{index .Labels "logout"}}
			</button>
		</div>
	</div>

	<div class="routes-grid">
		{{if .HostRules}}
			{{if .HasHostRuleGroups}}
			<div class="route-groups">
				{{range .HostRuleGroups}}
				<section class="route-group" data-group-id="{{.ID}}">
					<div class="route-group-header">
						<h2 class="route-group-title">{{.Name}}</h2>
						<span class="route-group-count">{{len .Rules}}</span>
					</div>
					<div class="routes-grid">
						{{range .Rules}}
						<a href="/" data-host="{{.Host}}" class="route-card host-route-card">
							<div class="route-main">
								{{with hostFaviconURL . $.GatewayPortal}}
								<span class="route-icon-shell"><img class="route-icon-img" src="{{.}}" alt=""></span>
								{{else}}
								<span class="route-icon-shell">
									<svg class="route-icon-fallback" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
										<circle cx="12" cy="12" r="10"/>
										<path d="M2 12h20"/>
										<path d="M12 2a15.3 15.3 0 0 1 0 20"/>
										<path d="M12 2a15.3 15.3 0 0 0 0 20"/>
									</svg>
								</span>
								{{end}}
								<div class="route-copy">
									<div class="route-path">{{hostDisplayLabel . $.GatewayPortal}}</div>
									<div class="route-target">{{.Target}}</div>
								</div>
							</div>
							<svg class="route-arrow" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
								<polyline points="9 18 15 12 9 6"/>
							</svg>
						</a>
						{{end}}
					</div>
				</section>
				{{end}}
			</div>
			{{else}}
			{{range .HostRules}}
			<a href="/" data-host="{{.Host}}" class="route-card host-route-card">
				<div class="route-main">
					{{with hostFaviconURL . $.GatewayPortal}}
					<span class="route-icon-shell"><img class="route-icon-img" src="{{.}}" alt=""></span>
					{{else}}
					<span class="route-icon-shell">
						<svg class="route-icon-fallback" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
							<circle cx="12" cy="12" r="10"/>
							<path d="M2 12h20"/>
							<path d="M12 2a15.3 15.3 0 0 1 0 20"/>
							<path d="M12 2a15.3 15.3 0 0 0 0 20"/>
						</svg>
					</span>
					{{end}}
					<div class="route-copy">
					<div class="route-path">{{hostDisplayLabel . $.GatewayPortal}}</div>
					<div class="route-target">{{.Target}}</div>
					</div>
				</div>
				<svg class="route-arrow" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
					<polyline points="9 18 15 12 9 6"/>
				</svg>
			</a>
			{{end}}
			{{end}}
		{{else if .Rules}}
			{{range .Rules}}
			<a href="{{ensureSlash .Path}}" class="route-card">
				<div class="route-main">
					<span class="route-icon-shell">
						<svg class="route-icon-fallback" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
							<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
							<path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
						</svg>
					</span>
					<div class="route-copy">
					<div class="route-path">{{.Path}}</div>
					<div class="route-target">{{.Target}}</div>
					</div>
				</div>
				<svg class="route-arrow" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
					<polyline points="9 18 15 12 9 6"/>
				</svg>
			</a>
			{{end}}
		{{else}}
			<div class="empty-card">
				<svg class="empty-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
					<circle cx="12" cy="12" r="10"/>
					<path d="M16 16s-1.5-2-4-2-4 2-4 2"/>
					<line x1="9" y1="9" x2="9.01" y2="9"/>
					<line x1="15" y1="9" x2="15.01" y2="9"/>
				</svg>
				{{index .Labels "routesEmpty"}}
			</div>
		{{end}}
	</div>

	<div class="select-footer">
		<p>
			© {{.Year}}
			<a href="https://github.com/kci-lnk/Go-Reauth-Proxy" target="_blank">Go Reauth Proxy</a>
			 · 
			<span>v{{.Version}}</span>
		</p>
	</div>
</div>

<script>
	(function() {
		function buildHostHref(host) {
			var port = window.location.port ? ':' + window.location.port : '';
			return window.location.protocol + '//' + host + port + '/';
		}

		var hostLinks = document.querySelectorAll('.host-route-card[data-host]');
		for (var i = 0; i < hostLinks.length; i++) {
			var host = hostLinks[i].getAttribute('data-host');
			if (!host) {
				continue;
			}
			hostLinks[i].setAttribute('href', buildHostHref(host));
		}
	})();
</script>

<div id="logout-modal" class="modal-overlay" onclick="if(event.target===this)this.classList.remove('active')">
	<div class="modal-content">
		<h2 class="modal-title">{{index .Labels "logoutTitle"}}</h2>
		<p class="modal-message">{{index .Labels "logoutMessage"}}</p>
		<div class="modal-actions">
			<button onclick="document.getElementById('logout-modal').classList.remove('active')" class="modal-btn modal-btn-cancel">
				{{index .Labels "cancel"}}
			</button>
			<a href="/__auth__/api/auth/logout" class="modal-btn modal-btn-confirm" style="text-decoration:none;text-align:center;display:inline-flex;align-items:center;justify-content:center;">
				{{index .Labels "confirm"}}
			</a>
		</div>
	</div>
</div>
{{end}}
`

var selectTmpl = template.Must(
	template.New("base").Funcs(htmlFuncMap).
		Parse(baseTemplate + selectContent),
)

func SelectPage(w http.ResponseWriter, r *http.Request, rules []models.Rule, hostRules []models.HostRule, portalConfig models.GatewayPortalConfig) {
	filteredRules := filterToolbarRules(rules)
	filteredHostRules := filterToolbarHostRules(hostRules, "")
	selectPageWithFilteredRoutes(w, r, filteredRules, filteredHostRules, portalConfig)
}

func SelectPageWithPrefilteredRoutes(w http.ResponseWriter, r *http.Request, filteredRules []models.Rule, filteredHostRules []models.HostRule, portalConfig models.GatewayPortalConfig) {
	selectPageWithFilteredRoutes(w, r, filteredRules, filteredHostRules, portalConfig)
}

func selectPageWithFilteredRoutes(w http.ResponseWriter, r *http.Request, filteredRules []models.Rule, filteredHostRules []models.HostRule, portalConfig models.GatewayPortalConfig) {
	locale := i18n.ResolveRequestLocale(r)
	hostRuleGroups, hasHostRuleGroups := buildHostRuleGroupViews(
		filteredHostRules,
		i18n.T(locale, "gateway.ungrouped"),
	)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Language", locale)
	w.WriteHeader(http.StatusOK)

	userAgent := ""
	if r != nil {
		userAgent = r.UserAgent()
	}

	toolbarHTML := ""
	if !ShouldSuppressToolbarForUserAgent(userAgent) {
		toolbarHTML = GenerateToolbarWithPrefilteredHostsForLocale(locale, filteredRules, filteredHostRules, "/__select__", "", "", portalConfig)
	}

	data := pageData{
		Title:             i18n.T(locale, "gateway.selectTitle"),
		Year:              time.Now().Year(),
		Version:           version.Version,
		BodyClass:         "select-page",
		Rules:             filteredRules,
		HostRules:         filteredHostRules,
		HostRuleGroups:    hostRuleGroups,
		HasHostRuleGroups: hasHostRuleGroups,
		GatewayPortal:     models.NormalizeGatewayPortalConfig(portalConfig),
		ToolbarHTML:       template.HTML(toolbarHTML),
		HTMLLang:          i18n.T(locale, "gateway.htmlLang"),
		Labels:            gatewayLabels(locale),
	}

	_ = selectTmpl.ExecuteTemplate(w, "layout", data)
}
