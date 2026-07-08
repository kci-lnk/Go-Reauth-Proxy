package response

import (
	"go-reauth-proxy/pkg/i18n"
	"html/template"
	"net/http"
)

type HostUnavailableOptions struct {
	Reason string
	Window string
}

const hostUnavailableContent = `
{{define "content"}}
<div class="text-center px-5 max-w-2xl">
	<img src="/__assets__/favicon/android-chrome-512x512.png" alt="Logo" style="width:64px;height:64px;margin:0 auto 1.25rem;display:block;border-radius:16px;opacity:.72;">
	<h1 class="text-4xl font-semibold tracking-tight mb-4">{{.Title}}</h1>
	<p class="text-lg text-gray-600 mb-8">{{.Message}}</p>
	<div style="margin:0 auto 2rem;max-width:32rem;text-align:left;border:1px solid #e5e7eb;padding:1rem 1.25rem;background:#fafafa;">
		<div style="font-size:.75rem;color:#6b7280;text-transform:uppercase;letter-spacing:.08em;margin-bottom:.9rem;">{{index .Labels "request"}}</div>
		<div style="display:flex;justify-content:space-between;gap:1rem;align-items:flex-start;margin-bottom:.75rem;">
			<span style="color:#6b7280;">{{index .Labels "host"}}</span>
			<code style="font-size:.875rem;color:#111;word-break:break-all;text-align:right;">{{if .RequestHost}}{{.RequestHost}}{{else}}-{{end}}</code>
		</div>
		<div style="display:flex;justify-content:space-between;gap:1rem;align-items:flex-start;{{if .Detail}}margin-bottom:.75rem;{{end}}">
			<span style="color:#6b7280;">{{index .Labels "path"}}</span>
			<code style="font-size:.875rem;color:#111;word-break:break-all;text-align:right;">{{if .RequestPath}}{{.RequestPath}}{{else}}-{{end}}</code>
		</div>
		{{if .Detail}}
		<div style="display:flex;justify-content:space-between;gap:1rem;align-items:flex-start;">
			<span style="color:#6b7280;">{{index .Labels "openWindow"}}</span>
			<code style="font-size:.875rem;color:#111;word-break:break-all;text-align:right;">{{.Detail}}</code>
		</div>
		{{end}}
	</div>
	<div class="mt-12">
		{{template "footer" .}}
	</div>
</div>
{{end}}
`

var hostUnavailableTmpl = template.Must(
	template.New("base").
		Parse(baseTemplate + footerTemplate + hostUnavailableContent),
)

func HostUnavailable(w http.ResponseWriter, r *http.Request, opts HostUnavailableOptions) {
	locale := i18n.ResolveRequestLocale(r)
	reason := opts.Reason
	if reason == "" {
		reason = "disabled"
	}
	messageKey := "gateway.hostDisabledMessage"
	if reason == "outside_window" {
		messageKey = "gateway.hostOutsideWindowMessage"
	}
	message := i18n.T(locale, messageKey)

	w.Header().Set("X-Fn-Knock-Host-Unavailable", reason)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Language", locale)

	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		var stack [768]byte
		_, _ = w.Write(appendHostUnavailableJSON(stack[:0], message, reason, opts.Window))
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)

	data := buildPageData(r, nil)
	data.Title = i18n.T(locale, "gateway.hostUnavailableTitle")
	data.Message = message
	if reason == "outside_window" {
		data.Detail = opts.Window
	}
	_ = hostUnavailableTmpl.ExecuteTemplate(w, "layout", data)
}

func appendHostUnavailableJSON(buf []byte, message string, reason string, window string) []byte {
	if cap(buf) == 0 {
		buf = make([]byte, 0, len(message)+len(reason)+len(window)+128)
	}
	buf = append(buf, `{"success":false,"code":"HOST_UNAVAILABLE","reason":`...)
	buf = appendJSONString(buf, reason)
	buf = append(buf, `,"message":`...)
	buf = appendJSONString(buf, message)
	if window != "" {
		buf = append(buf, `,"window":`...)
		buf = appendJSONString(buf, window)
	}
	buf = append(buf, "}\n"...)
	return buf
}
