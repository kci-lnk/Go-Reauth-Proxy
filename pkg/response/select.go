package response

import (
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
}

const selectStyle = `
<style>
  :root {
    --background: hsl(0 0% 100%);
    --foreground: hsl(0 0% 3.9%);
    --card: hsl(0 0% 100%);
    --card-foreground: hsl(0 0% 3.9%);
    --muted: hsl(0 0% 96.1%);
    --muted-foreground: hsl(0 0% 45.1%);
    --border: hsl(0 0% 89.8%);
    --ring: hsl(0 0% 3.9%);
    --radius: 0.75rem;
    --destructive: hsl(0 84.2% 60.2%);
    --destructive-foreground: hsl(0 0% 98%);
    --primary: hsl(0 0% 9%);
    --primary-foreground: hsl(0 0% 98%);
    --secondary: hsl(0 0% 96.1%);
    --secondary-foreground: hsl(0 0% 9%);
  }

  body.select-page {
    background: var(--muted);
    min-height: 100vh;
    display: flex;
    align-items: flex-start;
    justify-content: center;
    padding: 3rem 1rem;
  }

  .select-container {
    width: 100%;
    max-width: 640px;
  }

  /* Header card */
  .header-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 2rem;
    margin-bottom: 1.5rem;
    box-shadow: 0 1px 3px 0 rgb(0 0 0 / 0.04);
  }
  .header-top {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 1rem;
  }
  .header-title {
    font-size: 1.75rem;
    letter-spacing: -0.025em;
    color: var(--foreground);
    line-height: 1.2;
    margin: 0;
  }
  .header-desc {
    font-size: 0.875rem;
    color: var(--muted-foreground);
    margin-top: 0.5rem;
    line-height: 1.5;
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
    background: var(--card);
    color: var(--muted-foreground);
    cursor: pointer;
    transition: all 0.15s ease;
    white-space: nowrap;
    font-family: inherit;
    line-height: 1.5;
  }
  .btn-logout:hover {
    background: var(--muted);
    color: var(--foreground);
    border-color: hsl(0 0% 80%);
  }
  .btn-logout svg {
    width: 14px;
    height: 14px;
    flex-shrink: 0;
  }

  /* Route cards */
  .routes-grid {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .route-card {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    padding: 1.25rem 1.5rem;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    text-decoration: none;
    color: inherit;
    transition: all 0.2s ease;
    box-shadow: 0 1px 2px 0 rgb(0 0 0 / 0.03);
  }
  .route-card:hover {
    border-color: hsl(0 0% 78%);
    box-shadow: 0 4px 12px 0 rgb(0 0 0 / 0.08);
    transform: translateY(-1px);
  }
  .route-path {
    font-size: 0.9375rem;
    font-weight: 600;
    color: var(--foreground);
    margin-bottom: 0.25rem;
  }
  .route-target {
    font-size: 0.8125rem;
    color: var(--muted-foreground);
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
    margin-top: 2rem;
    padding-top: 1.5rem;
  }
  .select-footer p {
    font-size: 0.75rem;
    color: var(--muted-foreground);
  }
  .select-footer a {
    color: hsl(0 0% 40%);
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
    background-color: var(--card);
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

  @media (max-width: 480px) {
    body.select-page {
      padding: 1.5rem 0.75rem;
    }
    .header-card {
      padding: 1.25rem;
    }
    .header-top {
      flex-direction: column;
      gap: 0.75rem;
    }
    .header-title {
      font-size: 1.375rem;
    }
    .route-card {
      padding: 1rem 1.25rem;
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
			<div style="display:flex;align-items:center;gap:1rem;">
				<img src="/android-chrome-512x512.png" alt="Logo" style="width:50px;height:50px;border-radius:8px;flex-shrink:0;">
				<div>
				<h1 class="header-title">Go Reauth Proxy</h1>
				<p class="header-desc">Choose a destination to continue</p>
			</div>
			</div>
			<button onclick="document.getElementById('logout-modal').classList.add('active')" class="btn-logout">
				<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
					<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
					<polyline points="16 17 21 12 16 7"/>
					<line x1="21" y1="12" x2="9" y2="12"/>
				</svg>
				Logout
			</button>
		</div>
	</div>

	<div class="routes-grid">
		{{if not .Rules}}
			<div class="empty-card">
				<svg class="empty-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
					<circle cx="12" cy="12" r="10"/>
					<path d="M16 16s-1.5-2-4-2-4 2-4 2"/>
					<line x1="9" y1="9" x2="9.01" y2="9"/>
					<line x1="15" y1="9" x2="15.01" y2="9"/>
				</svg>
				No routes available.
			</div>
		{{else}}
			{{range .Rules}}
			<a href="{{ensureSlash .Path}}" class="route-card">
				<div>
					<div class="route-path">{{.Path}}</div>
					<div class="route-target">{{.Target}}</div>
				</div>
				<svg class="route-arrow" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
					<polyline points="9 18 15 12 9 6"/>
				</svg>
			</a>
			{{end}}
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

<div id="logout-modal" class="modal-overlay" onclick="if(event.target===this)this.classList.remove('active')">
	<div class="modal-content">
		<h2 class="modal-title">Logout</h2>
		<p class="modal-message">Are you sure you want to log out?</p>
		<div class="modal-actions">
			<button onclick="document.getElementById('logout-modal').classList.remove('active')" class="modal-btn modal-btn-cancel">
				Cancel
			</button>
			<a href="/__auth__/logout" class="modal-btn modal-btn-confirm" style="text-decoration:none;text-align:center;display:inline-flex;align-items:center;justify-content:center;">
				Confirm
			</a>
		</div>
	</div>
</div>
{{.ToolbarHTML}}
{{end}}
`

var selectTmpl = template.Must(
	template.New("base").Funcs(htmlFuncMap).
		Parse(baseTemplate + selectContent),
)

func SelectPage(w http.ResponseWriter, rules []models.Rule) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	toolbarHTML := GenerateToolbar(rules, "/__select__")

	data := pageData{
		Title:       "Select Route",
		Year:        time.Now().Year(),
		Version:     version.Version,
		BodyClass:   "select-page",
		Rules:       rules,
		ToolbarHTML: template.HTML(toolbarHTML),
	}

	_ = selectTmpl.ExecuteTemplate(w, "layout", data)
}
