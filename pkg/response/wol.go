package response

import (
	"go-reauth-proxy/pkg/i18n"
	"html/template"
	"net/http"
	"sync"
)

var (
	wolPageOnce sync.Once
	wolPageTmpl *template.Template
)

type wolPageData struct {
	Title       string
	Description string
	Loading     string
	Empty       string
	LoadFailed  string
	Wake        string
	Waking      string
	WakeSuccess string
	WakeFailed  string
	Online      string
	Offline     string
	Unknown     string
	LastChecked string
	Back        string
}

const wolPageHTML = `<!doctype html>
<html lang="{{.Locale}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{{.Data.Title}}</title>
<style>
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#18181b;background:#f4f4f5}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at top,#fff 0,#f4f4f5 52%,#e4e4e7 100%)}button,a{font:inherit}.shell{width:min(1120px,100%);margin:auto;padding:24px 16px 48px}.top{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:22px}.title-row{display:flex;align-items:center;gap:11px}.title-icon{width:30px;height:30px;flex:none}.title{margin:0;font-size:clamp(1.6rem,4vw,2.25rem);letter-spacing:-.035em}.desc{margin:8px 0 0;color:#71717a;line-height:1.6}.back{display:inline-flex;align-items:center;gap:7px;min-height:40px;padding:0 14px;border:1px solid #d4d4d8;border-radius:10px;background:#fff;color:#27272a;text-decoration:none;white-space:nowrap}.state{padding:56px 20px;border:1px dashed #d4d4d8;border-radius:18px;text-align:center;color:#71717a;background:rgba(255,255,255,.7)}.grid{display:grid;grid-template-columns:1fr;gap:14px}.card{display:flex;flex-direction:column;min-width:0;padding:18px;border:1px solid #e4e4e7;border-radius:18px;background:rgba(255,255,255,.92);box-shadow:0 8px 28px rgba(24,24,27,.06)}.card-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}.device-name{margin:0;font-size:1.1rem;overflow-wrap:anywhere}.status{display:inline-flex;align-items:center;gap:7px;flex:none;font-size:.82rem;color:#52525b}.dot{width:9px;height:9px;border-radius:999px;background:#f59e0b}.dot.online{background:#22c55e}.dot.offline{background:#a1a1aa}.meta{display:flex;flex-wrap:wrap;gap:7px 12px;margin-top:16px;padding-top:13px;border-top:1px solid #f0f0f1;color:#71717a;font-size:.78rem}.actions{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:auto;padding-top:18px}.result{min-height:20px;color:#71717a;font-size:.82rem}.result.ok{color:#15803d}.result.error{color:#b91c1c}.wake{display:inline-flex;align-items:center;justify-content:center;gap:8px;min-width:112px;min-height:42px;border:0;border-radius:11px;background:#18181b;color:#fff;font-weight:650;cursor:pointer}.wake svg{width:17px;height:17px}.wake:hover{background:#3f3f46}.wake:disabled{cursor:not-allowed;opacity:.58}.spinner{width:15px;height:15px;border:2px solid rgba(255,255,255,.4);border-top-color:#fff;border-radius:50%;animation:spin .75s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}@media(min-width:680px){.shell{padding:38px 24px 64px}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(min-width:1024px){.grid{grid-template-columns:repeat(3,minmax(0,1fr))}}@media(prefers-color-scheme:dark){:root{color:#f4f4f5;background:#09090b}body{background:radial-gradient(circle at top,#27272a 0,#09090b 60%)}.desc,.state,.meta,.result{color:#a1a1aa}.back,.card{border-color:#3f3f46;background:rgba(24,24,27,.92);color:#f4f4f5}.state{background:rgba(24,24,27,.65)}.status{color:#d4d4d8}.meta{border-top-color:#3f3f46}.wake{background:#fafafa;color:#18181b}.wake:hover{background:#e4e4e7}}
</style>
</head>
<body>
<main class="shell">
  <header class="top"><div><div class="title-row"><svg class="title-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m9 10 3-3 3 3"/><path d="M12 13V7"/><rect width="20" height="14" x="2" y="3" rx="2"/><path d="M12 17v4"/><path d="M8 21h8"/></svg><h1 class="title">{{.Data.Title}}</h1></div><p class="desc">{{.Data.Description}}</p></div><a class="back" href="/__select__" aria-label="{{.Data.Back}}">← {{.Data.Back}}</a></header>
  <section id="state" class="state" role="status">{{.Data.Loading}}</section>
  <section id="grid" class="grid" aria-live="polite" hidden></section>
</main>
<script>
(function(){
  'use strict';
  var labels={loading:{{.Data.Loading}},empty:{{.Data.Empty}},loadFailed:{{.Data.LoadFailed}},wake:{{.Data.Wake}},waking:{{.Data.Waking}},wakeSuccess:{{.Data.WakeSuccess}},wakeFailed:{{.Data.WakeFailed}},online:{{.Data.Online}},offline:{{.Data.Offline}},unknown:{{.Data.Unknown}},lastChecked:{{.Data.LastChecked}}};
  var state=document.getElementById('state');var grid=document.getElementById('grid');
  function text(tag,value,className){var node=document.createElement(tag);if(className)node.className=className;node.textContent=value||'';return node}
  function monitorIcon(){var icon=document.createElementNS('http://www.w3.org/2000/svg','svg');icon.setAttribute('viewBox','0 0 24 24');icon.setAttribute('fill','none');icon.setAttribute('stroke','currentColor');icon.setAttribute('stroke-width','2');icon.setAttribute('stroke-linecap','round');icon.setAttribute('stroke-linejoin','round');icon.setAttribute('aria-hidden','true');[['path','d','m9 10 3-3 3 3'],['path','d','M12 13V7'],['rect','width','20','height','14','x','2','y','3','rx','2'],['path','d','M12 17v4'],['path','d','M8 21h8']].forEach(function(spec){var node=document.createElementNS('http://www.w3.org/2000/svg',spec[0]);for(var index=1;index<spec.length;index+=2)node.setAttribute(spec[index],spec[index+1]);icon.appendChild(node)});return icon}
  function apiFetch(url,options){var headers=new Headers(options&&options.headers||{});headers.set('Cache-Control','no-cache');return fetch(url,Object.assign({cache:'no-store',credentials:'same-origin'},options||{},{headers:headers}))}
  function statusLabel(value){return value==='online'?labels.online:value==='offline'?labels.offline:labels.unknown}
  function render(items){grid.replaceChildren();if(!items.length){state.textContent=labels.empty;state.hidden=false;grid.hidden=true;return}state.hidden=true;grid.hidden=false;items.forEach(function(item){var card=text('article','', 'card');var head=text('div','', 'card-head');var names=text('div');names.appendChild(text('h2',item.name,'device-name'));var status=text('div','', 'status');var dot=text('span','', 'dot '+(item.status&&item.status.state||'unknown'));dot.setAttribute('aria-hidden','true');status.appendChild(dot);status.appendChild(text('span',statusLabel(item.status&&item.status.state)));head.appendChild(names);head.appendChild(status);card.appendChild(head);if(item.status&&item.status.checkedAt){var meta=text('div','', 'meta');meta.appendChild(text('span',labels.lastChecked.replace('{time}',new Date(item.status.checkedAt).toLocaleString())));card.appendChild(meta)}var actions=text('div','', 'actions');var result=text('span','', 'result');var button=text('button','','wake');button.type='button';button.replaceChildren(monitorIcon(),document.createTextNode(labels.wake));button.addEventListener('click',async function(){button.disabled=true;button.replaceChildren(text('span','', 'spinner'),document.createTextNode(labels.waking));result.className='result';result.textContent='';try{var response=await apiFetch('/__auth__/api/auth/wol/targets/'+encodeURIComponent(item.id)+'/wake',{method:'POST'});var payload=await response.json().catch(function(){return null});if(!response.ok)throw new Error(payload&&payload.message||labels.wakeFailed);result.textContent=labels.wakeSuccess;result.className='result ok'}catch(error){result.textContent=error&&error.message||labels.wakeFailed;result.className='result error'}finally{button.disabled=false;button.replaceChildren(monitorIcon(),document.createTextNode(labels.wake))}});actions.appendChild(result);actions.appendChild(button);card.appendChild(actions);grid.appendChild(card)})}
  async function load(){try{var response=await apiFetch('/__auth__/api/auth/wol/targets?_ts='+Date.now());var payload=await response.json().catch(function(){return null});if(!response.ok)throw new Error(payload&&payload.message||labels.loadFailed);render(payload&&payload.data&&payload.data.items||[])}catch(error){state.hidden=false;grid.hidden=true;state.textContent=error&&error.message||labels.loadFailed}}
  load();
})();
</script>
</body></html>`

type wolPageTemplateData struct {
	Locale string
	Data   wolPageData
}

func WOLPage(w http.ResponseWriter, r *http.Request) {
	locale := i18n.ResolveRequestLocale(r)
	data := wolPageData{
		Title:       i18n.T(locale, "gateway.wol.title"),
		Description: i18n.T(locale, "gateway.wol.description"),
		Loading:     i18n.T(locale, "gateway.wol.loading"),
		Empty:       i18n.T(locale, "gateway.wol.empty"),
		LoadFailed:  i18n.T(locale, "gateway.wol.loadFailed"),
		Wake:        i18n.T(locale, "gateway.wol.wake"),
		Waking:      i18n.T(locale, "gateway.wol.waking"),
		WakeSuccess: i18n.T(locale, "gateway.wol.wakeSuccess"),
		WakeFailed:  i18n.T(locale, "gateway.wol.wakeFailed"),
		Online:      i18n.T(locale, "gateway.wol.online"),
		Offline:     i18n.T(locale, "gateway.wol.offline"),
		Unknown:     i18n.T(locale, "gateway.wol.unknown"),
		LastChecked: i18n.T(locale, "gateway.wol.lastChecked"),
		Back:        i18n.T(locale, "gateway.wol.back"),
	}
	wolPageOnce.Do(func() { wolPageTmpl = template.Must(template.New("wol").Parse(wolPageHTML)) })
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Language", locale)
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if err := wolPageTmpl.Execute(w, wolPageTemplateData{Locale: locale, Data: data}); err != nil {
		http.Error(w, "Failed to render Wake-on-LAN page", http.StatusInternalServerError)
	}
}
