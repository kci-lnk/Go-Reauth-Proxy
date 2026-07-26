package response

import (
	"go-reauth-proxy/pkg/i18n"
	"html/template"
	"net/http"
	"strconv"
)

type WAFBlockPageOptions struct {
	Status  int
	TraceID string
}

const wafBlockedContent = `
{{define "content"}}
<div class="text-center px-5 max-w-md">
	<img src="{{.InlineLogoDataURL}}" alt="Logo" style="width:64px;height:64px;margin:0 auto 1.25rem;display:block;border-radius:16px;">
	<h1 class="text-4xl font-semibold tracking-tight mb-4">{{.Title}}</h1>
	<p class="text-lg text-gray-600 mb-8">{{.Message}}</p>
	<div style="margin:0 auto 2rem;max-width:28rem;text-align:left;border:1px solid #e5e7eb;padding:1rem 1.25rem;background:#fafafa;">
		<div style="font-size:.75rem;color:#6b7280;text-transform:uppercase;letter-spacing:.08em;margin-bottom:.6rem;">{{index .Labels "traceId"}}</div>
		<code style="font-size:.875rem;color:#111;word-break:break-all;">{{.RequestPath}}</code>
	</div>
	<div class="mt-12">
		{{template "footer" .}}
	</div>
</div>
{{end}}
`

var wafBlockedTmpl = template.Must(
	template.New("base").
		Parse(baseTemplate + footerTemplate + wafBlockedContent),
)

func WAFBlocked(w http.ResponseWriter, r *http.Request, opts WAFBlockPageOptions) {
	locale := i18n.ResolveRequestLocale(r)
	status := opts.Status
	if status < 400 || status > 599 {
		status = http.StatusForbidden
	}
	w.Header().Set("X-Fn-Knock-WAF-Blocked", "1")
	w.Header().Set("X-Fn-Knock-WAF-Trace-ID", opts.TraceID)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Language", locale)

	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		var stack [512]byte
		_, _ = w.Write(appendWAFBlockedJSON(stack[:0], i18n.T(locale, "gateway.wafBlockedJson"), opts.TraceID))
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)

	data := buildPageData(r, nil)
	data.Title = i18n.T(locale, "gateway.wafBlockedTitle")
	data.Message = i18n.T(locale, "gateway.wafBlockedMessage")
	data.InlineIconDataURL = inlinePageIconDataURL
	data.InlineLogoDataURL = inlinePageLogoDataURL
	data.RequestPath = opts.TraceID
	if data.RequestPath == "" {
		data.RequestPath = strconv.Itoa(status)
	}
	_ = wafBlockedTmpl.ExecuteTemplate(w, "layout", data)
}

func wantsJSON(r *http.Request) bool {
	if r == nil {
		return false
	}
	accept := r.Header.Get("Accept")
	return containsFoldASCIIString(accept, "application/json") && !containsFoldASCIIString(accept, "text/html")
}

func appendWAFBlockedJSON(buf []byte, message string, traceID string) []byte {
	if cap(buf) == 0 {
		buf = make([]byte, 0, len(message)+len(traceID)+80)
	}
	buf = append(buf, `{"success":false,"code":"WAF_BLOCKED","message":`...)
	buf = appendJSONString(buf, message)
	buf = append(buf, `,"trace_id":`...)
	buf = appendJSONString(buf, traceID)
	buf = append(buf, "}\n"...)
	return buf
}
