package response

import (
	"encoding/json"
	"go-reauth-proxy/pkg/errors"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/version"
	"html/template"
	"net/http"
	"strconv"
	"time"
)

type Response struct {
	Success   bool        `json:"success"`
	Code      int         `json:"code"`
	Message   string      `json:"message"`
	Data      interface{} `json:"data"`
	Timestamp int64       `json:"timestamp"`
}

func JSON(w http.ResponseWriter, success bool, code int, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	resp := Response{
		Success:   success,
		Code:      code,
		Message:   message,
		Data:      data,
		Timestamp: time.Now().UnixMilli(),
	}

	_ = json.NewEncoder(w).Encode(resp)
}

func Success(w http.ResponseWriter, data interface{}) {
	JSON(w, true, 200, "Success", data)
}

func Error(w http.ResponseWriter, code int, message string) {
	JSON(w, false, code, message, nil)
}

type pageData struct {
	Title       string
	Message     string
	Year        int
	ShowBack    bool
	Version     string
	BodyClass   string
	Rules       []models.Rule
	ToolbarHTML template.HTML
}

const baseStyle = `

 @layer properties{@supports (((-webkit-hyphens:none)) and (not (margin-trim:inline))) or ((-moz-orient:inline) and (not (color:rgb(from red r g b)))){*,:before,:after,::backdrop{--tw-border-style:solid;--tw-font-weight:initial;--tw-tracking:initial;--tw-duration:initial}}}@layer theme{:root,:host{--font-sans:ui-sans-serif, system-ui, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol", "Noto Color Emoji";--font-mono:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;--color-gray-200:oklch(87.9% .009 258.338);--color-gray-300:oklch(80.8% .011 258.708);--color-gray-400:oklch(70.7% .022 261.325);--color-gray-500:oklch(55.1% .027 264.364);--color-gray-600:oklch(44.6% .03 256.802);--color-gray-900:oklch(21% .034 264.665);--color-black:#000;--color-white:#fff;--spacing:.25rem;--container-md:28rem;--text-xs:.75rem;--text-xs--line-height:calc(1 / .75);--text-sm:.875rem;--text-sm--line-height:calc(1.25 / .875);--text-lg:1.125rem;--text-lg--line-height:calc(1.75 / 1.125);--text-xl:1.25rem;--text-xl--line-height:calc(1.75 / 1.25);--text-4xl:2.25rem;--text-4xl--line-height:calc(2.5 / 2.25);--text-6xl:3.75rem;--text-6xl--line-height:1;--font-weight-medium:500;--font-weight-semibold:600;--tracking-tight:-.025em;--default-transition-duration:.15s;--default-transition-timing-function:cubic-bezier(.4, 0, .2, 1);--default-font-family:var(--font-sans);--default-mono-font-family:var(--font-mono)}}@layer base{*,:after,:before,::backdrop{box-sizing:border-box;border:0 solid;margin:0;padding:0}::file-selector-button{box-sizing:border-box;border:0 solid;margin:0;padding:0}html,:host{-webkit-text-size-adjust:100%;tab-size:4;line-height:1.5;font-family:var(--default-font-family,ui-sans-serif, system-ui, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol", "Noto Color Emoji");font-feature-settings:var(--default-font-feature-settings,normal);font-variation-settings:var(--default-font-variation-settings,normal);-webkit-tap-highlight-color:transparent}hr{height:0;color:inherit;border-top-width:1px}abbr:where([title]){-webkit-text-decoration:underline dotted;text-decoration:underline dotted}h1,h2,h3,h4,h5,h6{font-size:inherit;font-weight:inherit}a{color:inherit;-webkit-text-decoration:inherit;-webkit-text-decoration:inherit;-webkit-text-decoration:inherit;text-decoration:inherit}b,strong{font-weight:bolder}code,kbd,samp,pre{font-family:var(--default-mono-font-family,ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace);font-feature-settings:var(--default-mono-font-feature-settings,normal);font-variation-settings:var(--default-mono-font-variation-settings,normal);font-size:1em}small{font-size:80%}sub,sup{vertical-align:baseline;font-size:75%;line-height:0;position:relative}sub{bottom:-.25em}sup{top:-.5em}table{text-indent:0;border-color:inherit;border-collapse:collapse}:-moz-focusring{outline:auto}progress{vertical-align:baseline}summary{display:list-item}ol,ul,menu{list-style:none}img,svg,video,canvas,audio,iframe,embed,object{vertical-align:middle;display:block}img,video{max-width:100%;height:auto}button,input,select,optgroup,textarea{font:inherit;font-feature-settings:inherit;font-variation-settings:inherit;letter-spacing:inherit;color:inherit;opacity:1;background-color:#0000;border-radius:0}::file-selector-button{font:inherit;font-feature-settings:inherit;font-variation-settings:inherit;letter-spacing:inherit;color:inherit;opacity:1;background-color:#0000;border-radius:0}:where(select:is([multiple],[size])) optgroup{font-weight:bolder}:where(select:is([multiple],[size])) optgroup option{padding-inline-start:20px}::file-selector-button{margin-inline-end:4px}::placeholder{opacity:1}@supports (not ((-webkit-appearance:-apple-pay-button))) or (contain-intrinsic-size:1px){::placeholder{color:currentColor}@supports (color:color-mix(in lab, red, red)){::placeholder{color:color-mix(in oklab, currentcolor 50%, transparent)}}}textarea{resize:vertical}::-webkit-search-decoration{-webkit-appearance:none}::-webkit-date-and-time-value{min-height:1lh;text-align:inherit}::-webkit-datetime-edit{display:inline-flex}::-webkit-datetime-edit-fields-wrapper{padding:0}::-webkit-datetime-edit{padding-block:0}::-webkit-datetime-edit-year-field{padding-block:0}::-webkit-datetime-edit-month-field{padding-block:0}::-webkit-datetime-edit-day-field{padding-block:0}::-webkit-datetime-edit-hour-field{padding-block:0}::-webkit-datetime-edit-minute-field{padding-block:0}::-webkit-datetime-edit-second-field{padding-block:0}::-webkit-datetime-edit-millisecond-field{padding-block:0}::-webkit-datetime-edit-meridiem-field{padding-block:0}::-webkit-calendar-picker-indicator{line-height:1}:-moz-ui-invalid{box-shadow:none}button,input:where([type=button],[type=reset],[type=submit]){appearance:button}::file-selector-button{appearance:button}::-webkit-inner-spin-button{height:auto}::-webkit-outer-spin-button{height:auto}[hidden]:where(:not([hidden=until-found])){display:none!important}body{color:#111;background:#fff;justify-content:center;align-items:center;height:100vh;margin:0;font-family:Inter,system-ui,sans-serif;display:flex}}@layer components;@layer utilities{.-translate-x-2{--tw-translate-x:calc(var(--spacing) * -2);translate:var(--tw-translate-x) var(--tw-translate-y);}.mb-1{margin-bottom:calc(var(--spacing) * 1)}.mb-10{margin-bottom:calc(var(--spacing) * 10)}.mb-2{margin-bottom:calc(var(--spacing) * 2)}.mb-4{margin-bottom:calc(var(--spacing) * 4)}.mb-8{margin-bottom:calc(var(--spacing) * 8)}.mt-12{margin-top:calc(var(--spacing) * 12)}.mt-16{margin-top:calc(var(--spacing) * 16)}.inline-block{display:inline-block}.block{display:block}.flex{display:flex}.w-full{width:100%}.w-5{width:calc(var(--spacing) * 5)}.max-w-2xl{max-width:42rem}.max-w-md{max-width:var(--container-md)}.flex-col{flex-direction:column}.items-center{align-items:center}.justify-between{justify-content:space-between}.justify-end{justify-content:flex-end}.justify-center{justify-content:center}.gap-3{gap:calc(var(--spacing) * 3)}.border{border-style:var(--tw-border-style);border-width:1px}.border-black{border-color:var(--color-black)}.border-gray-200{border-color:var(--color-gray-200)}.bg-white{background-color:var(--color-white)}.bg-black{background-color:var(--color-black)}.p-5{padding:calc(var(--spacing) * 5)}.px-4{padding-inline:calc(var(--spacing) * 4)}.px-5{padding-inline:calc(var(--spacing) * 5)}.py-12{padding-block:calc(var(--spacing) * 12)}.py-2\.5{padding-block:calc(var(--spacing) * 2.5)}.py-2{padding-block:calc(var(--spacing) * 2)}.text-center{text-align:center}.text-lg{font-size:var(--text-lg);line-height:var(--tw-leading,var(--text-lg--line-height))}.text-4xl{font-size:var(--text-4xl);line-height:var(--tw-leading,var(--text-4xl--line-height))}.text-6xl{font-size:var(--text-6xl);line-height:var(--tw-leading,var(--text-6xl--line-height))}.text-sm{font-size:var(--text-sm);line-height:var(--tw-leading,var(--text-sm--line-height))}.text-xl{font-size:var(--text-xl);line-height:var(--tw-leading,var(--text-xl--line-height))}.text-2xl{font-size:1.5rem;line-height:2rem}.text-xs{font-size:var(--text-xs);line-height:var(--tw-leading,var(--text-xs--line-height))}.font-medium{--tw-font-weight:var(--font-weight-medium);font-weight:var(--font-weight-medium)}.font-semibold{--tw-font-weight:var(--font-weight-semibold);font-weight:var(--font-weight-semibold)}.tracking-tight{--tw-tracking:var(--tracking-tight);letter-spacing:var(--tracking-tight)}.text-black{color:var(--color-black)}.text-gray-400{color:var(--color-gray-400)}.text-gray-500{color:var(--color-gray-500)}.text-gray-600{color:var(--color-gray-600)}.text-white{color:var(--color-white)}.opacity-0{opacity:0}.transition-all{transition-property:all;transition-timing-function:var(--tw-ease,var(--default-transition-timing-function));transition-duration:var(--tw-duration,var(--default-transition-duration))}.transition-colors{transition-property:color,background-color,border-color,outline-color,text-decoration-color,fill,stroke,--tw-gradient-from,--tw-gradient-via,--tw-gradient-to;transition-timing-function:var(--tw-ease,var(--default-transition-timing-function));transition-duration:var(--tw-duration,var(--default-transition-duration))}.duration-150{--tw-duration:.15s;transition-duration:.15s}.duration-200{--tw-duration:.2s;transition-duration:.2s}::-moz-selection{background-color:var(--color-black);color:var(--color-white)}::selection{background-color:var(--color-black);color:var(--color-white)}.mx-2{margin-inline:calc(var(--spacing) * 2)}@media (hover:hover){.hover\:bg-black:hover{background-color:var(--color-black)}.hover\:bg-gray-900:hover{background-color:var(--color-gray-900)}.hover\:text-black:hover{color:var(--color-black)}.hover\:text-white:hover{color:var(--color-white)}.group:hover .group-hover\:text-gray-300{color:var(--color-gray-300)}.group:hover .group-hover\:text-white{color:var(--color-white)}.group:hover .group-hover\:opacity-100{opacity:1}.group:hover .group-hover\:translate-x-0{--tw-translate-x:0px;translate:var(--tw-translate-x) var(--tw-translate-y);}}}@property --tw-translate-x{syntax:"*";inherits:false;initial-value:0}@property --tw-translate-y{syntax:"*";inherits:false;initial-value:0}@property --tw-translate-z{syntax:"*";inherits:false;initial-value:0}@property --tw-border-style{syntax:"*";inherits:false;initial-value:solid}@property --tw-font-weight{syntax:"*";inherits:false}@property --tw-tracking{syntax:"*";inherits:false}@property --tw-duration{syntax:"*";inherits:false}
    </style>
`

const baseTemplate = `
{{define "layout"}}
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
	<link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
	<link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">
	<link rel="manifest" href="/site.webmanifest">
	<title>{{.Title}} - Go Reauth Proxy</title>
	<style>` + baseStyle + `</style>
</head>
<body class="{{.BodyClass}}">
	{{block "content" .}}{{end}}
	{{.ToolbarHTML}}
</body>
</html>
{{end}}
`

const footerTemplate = `
{{define "footer"}}
<p class="text-xs text-gray-400">
	© {{.Year}}
	<a href="https://github.com/kci-lnk/Go-Reauth-Proxy" 
	   target="_blank"
	   class="text-gray-500 hover:text-black transition-colors">
	   Go Reauth Proxy
	</a>
	<span class="mx-2">•</span>
	<span class="text-gray-400">v{{.Version}}</span>
</p>
{{end}}
`

const errorContent = `
{{define "content"}}
<div class="text-center px-5 max-w-md">
	<img src="/android-chrome-512x512.png" alt="Logo" style="width:64px;height:64px;margin:0 auto 1.25rem;display:block;border-radius:16px;">
	<h1 class="text-6xl font-semibold tracking-tight mb-4">{{.Title}}</h1>
	<p class="text-xl text-gray-600 mb-8">{{.Message}}</p>

	{{if .ShowBack}}
	<a href="/__select__"
	   class="inline-block px-5 py-2.5 text-sm font-medium 
	          text-white bg-black hover:bg-gray-900 
	          transition-colors duration-150 
	          border border-black">
		Go to Select
	</a>
	{{end}}

	<div class="mt-12">
		{{template "footer" .}}
	</div>
</div>
{{end}}
`

var errorTmpl = template.Must(
	template.New("base").
		Parse(baseTemplate + footerTemplate + errorContent),
)

func HTML(w http.ResponseWriter, code int, message string, rules []models.Rule) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	httpStatus := mapHTTPStatus(code)
	w.WriteHeader(httpStatus)

	var toolbarHTML template.HTML
	if len(rules) > 0 {
		toolbarHTML = template.HTML(GenerateToolbar(rules, ""))
	}

	data := pageData{
		Title:       strconv.Itoa(code),
		Message:     message,
		Year:        time.Now().Year(),
		ShowBack:    true,
		Version:     version.Version,
		BodyClass:   "flex items-center justify-center h-screen bg-white",
		ToolbarHTML: toolbarHTML,
	}

	_ = errorTmpl.ExecuteTemplate(w, "layout", data)
}

func Welcome(w http.ResponseWriter, rules []models.Rule) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	var toolbarHTML template.HTML
	if len(rules) > 0 {
		toolbarHTML = template.HTML(GenerateToolbar(rules, ""))
	}

	data := pageData{
		Title:       "It's working!",
		Message:     "Welcome to Go Reauth Proxy",
		Year:        time.Now().Year(),
		ShowBack:    false,
		Version:     version.Version,
		BodyClass:   "flex items-center justify-center h-screen bg-white",
		ToolbarHTML: toolbarHTML,
	}

	_ = errorTmpl.ExecuteTemplate(w, "layout", data)
}

func mapHTTPStatus(code int) int {
	if code >= 200 && code < 600 {
		return code
	}

	switch code {
	case errors.CodeProxyAuthFailed, errors.CodeProxyTargetInvalid:
		return http.StatusBadGateway
	case errors.CodeProxyTimeout:
		return http.StatusGatewayTimeout
	case errors.CodeUnauthorized:
		return http.StatusUnauthorized
	case errors.CodeNotFound:
		return http.StatusNotFound
	case errors.CodeBadRequest:
		return http.StatusBadRequest
	}

	return http.StatusInternalServerError
}
