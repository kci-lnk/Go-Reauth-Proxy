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
	Title                    string
	Description              string
	Loading                  string
	Empty                    string
	LoadFailed               string
	Wake                     string
	Waking                   string
	WakeSuccess              string
	WakeFailed               string
	Shutdown                 string
	ShutdownTitle            string
	ShutdownDescription      string
	ShutdownWarning          string
	ShutdownConfirm          string
	ShutdownConfirmCountdown string
	ShuttingDown             string
	ShutdownAccepted         string
	ShutdownUnknown          string
	ShutdownFailed           string
	Cancel                   string
	Online                   string
	Offline                  string
	Unknown                  string
	LastChecked              string
	Back                     string
}

const wolPageHTML = `<!doctype html>
<html lang="{{.Locale}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{{.Data.Title}}</title>
<style>
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#18181b;background:#f4f4f5}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at top,#fff 0,#f4f4f5 52%,#e4e4e7 100%)}button,a{font:inherit}.shell{width:min(1120px,100%);margin:auto;padding:max(14px,env(safe-area-inset-top)) max(14px,env(safe-area-inset-right)) calc(40px + env(safe-area-inset-bottom)) max(14px,env(safe-area-inset-left))}.top{display:grid;grid-template-columns:40px minmax(0,1fr) 40px;align-items:start;gap:12px;margin-bottom:24px}.heading{min-width:0;padding-top:2px;text-align:center}.title{margin:0;font-size:clamp(1.3rem,5vw,1.7rem);font-weight:700;letter-spacing:-.025em;line-height:1.25}.desc{max-width:620px;margin:5px auto 0;color:#71717a;font-size:.88rem;line-height:1.45}.back{display:inline-flex;width:40px;height:40px;align-items:center;justify-content:center;border:0;border-radius:999px;background:transparent;color:#27272a;text-decoration:none;transition:background-color .16s ease,color .16s ease}.back:hover{background:rgba(24,24,27,.07)}.back:focus-visible{outline:2px solid currentColor;outline-offset:2px}.back svg{width:20px;height:20px}.top-balance{width:40px;height:40px}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}.state{padding:48px 18px;border:1px dashed #d4d4d8;border-radius:16px;text-align:center;color:#71717a;background:rgba(255,255,255,.7)}.grid{display:grid;grid-template-columns:1fr;gap:12px}.card{display:flex;flex-direction:column;min-width:0;padding:16px;border:1px solid #e4e4e7;border-radius:16px;background:rgba(255,255,255,.92);box-shadow:0 8px 28px rgba(24,24,27,.06)}.card-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}.device-name{margin:0;font-size:1.08rem;line-height:1.35;overflow-wrap:anywhere}.status{display:inline-flex;align-items:center;gap:7px;flex:none;font-size:.82rem;color:#52525b}.dot{width:9px;height:9px;border-radius:999px;background:#f59e0b}.dot.online{background:#22c55e}.dot.offline{background:#a1a1aa}.meta{display:flex;flex-wrap:wrap;gap:7px 12px;margin-top:14px;padding-top:12px;border-top:1px solid #f0f0f1;color:#71717a;font-size:.78rem}.actions{display:flex;flex-direction:column;align-items:stretch;gap:10px;margin-top:auto;padding-top:16px}.action-buttons{display:flex;width:100%;flex-wrap:wrap;gap:8px}.action-buttons>button{width:100%}.result{min-height:0;color:#71717a;font-size:.82rem}.result:not(:empty){min-height:20px}.result.ok{color:#15803d}.result.warning{color:#b45309}.result.error,.modal-error{color:#b91c1c}.wake,.shutdown,.modal-button{display:inline-flex;align-items:center;justify-content:center;gap:8px;min-height:44px;border:0;border-radius:11px;font-weight:650;cursor:pointer;touch-action:manipulation}.wake{min-width:112px;background:#18181b;color:#fff}.wake svg,.shutdown svg{width:18px;height:18px}.wake:hover{background:#3f3f46}.shutdown{min-width:104px;background:#dc2626;color:#fff}.shutdown:hover{background:#b91c1c}.wake:disabled,.shutdown:disabled,.modal-button:disabled{cursor:not-allowed;opacity:.58}.spinner{width:15px;height:15px;border:2px solid rgba(255,255,255,.4);border-top-color:#fff;border-radius:50%;animation:spin .75s linear infinite}.modal[hidden]{display:none}.modal{position:fixed;z-index:1000;inset:0;display:grid;place-items:center;padding:max(14px,env(safe-area-inset-top)) max(14px,env(safe-area-inset-right)) max(14px,env(safe-area-inset-bottom)) max(14px,env(safe-area-inset-left));background:rgba(9,9,11,.58)}.modal-panel{width:min(440px,100%);max-height:calc(100dvh - 28px);overflow:auto;padding:20px;border:1px solid #e4e4e7;border-radius:16px;background:#fff;box-shadow:0 24px 80px rgba(0,0,0,.28)}.modal-title{margin:0;color:#b91c1c;font-size:1.18rem}.modal-description{margin:10px 0 0;color:#52525b;line-height:1.55;overflow-wrap:anywhere}.modal-warning{margin:15px 0 0;padding:12px;border:1px solid rgba(220,38,38,.25);border-radius:10px;background:rgba(220,38,38,.06);font-size:.9rem;line-height:1.5}.modal-error{min-height:20px;margin:10px 0 0;font-size:.84rem}.modal-actions{display:flex;flex-direction:column-reverse;gap:9px;margin-top:16px}.modal-button{width:100%;padding:0 15px;background:#e4e4e7;color:#18181b}.modal-button.confirm{background:#dc2626;color:#fff}@keyframes spin{to{transform:rotate(360deg)}}@media(max-width:480px){.card-head{align-items:center}}@media(min-width:680px){.shell{padding:30px 24px 64px}.top{margin-bottom:30px}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.card{padding:18px}.actions{flex-direction:row;align-items:center;justify-content:space-between}.action-buttons{width:auto;justify-content:flex-end}.action-buttons>button{width:auto}.modal-panel{padding:22px;border-radius:18px}.modal-actions{flex-direction:row;justify-content:flex-end}.modal-button{width:auto}.modal-button.confirm{min-width:150px}}@media(min-width:1024px){.grid{grid-template-columns:repeat(3,minmax(0,1fr))}}@media(prefers-color-scheme:dark){:root{color:#f4f4f5;background:#09090b}body{background:radial-gradient(circle at top,#27272a 0,#09090b 60%)}.desc,.state,.meta,.result,.modal-description{color:#a1a1aa}.card,.modal-panel{border-color:#3f3f46;background:rgba(24,24,27,.98);color:#f4f4f5}.back{color:#f4f4f5}.back:hover{background:rgba(244,244,245,.1)}.state{background:rgba(24,24,27,.65)}.status{color:#d4d4d8}.meta{border-top-color:#3f3f46}.wake{background:#fafafa;color:#18181b}.wake:hover{background:#e4e4e7}.modal-button{background:#3f3f46;color:#f4f4f5}}
</style>
</head>
<body>
<main class="shell">
  <header class="top"><a class="back" href="/__select__" aria-label="{{.Data.Back}}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m15 18-6-6 6-6"/></svg><span class="sr-only">{{.Data.Back}}</span></a><div class="heading"><h1 class="title">{{.Data.Title}}</h1><p class="desc">{{.Data.Description}}</p></div><span class="top-balance" aria-hidden="true"></span></header>
  <section id="state" class="state" role="status">{{.Data.Loading}}</section>
  <section id="grid" class="grid" aria-live="polite" hidden></section>
</main>
<div id="shutdown-modal" class="modal" hidden>
  <section class="modal-panel" role="dialog" aria-modal="true" aria-labelledby="shutdown-title" aria-describedby="shutdown-description">
    <h2 id="shutdown-title" class="modal-title">{{.Data.ShutdownTitle}}</h2>
    <p id="shutdown-description" class="modal-description"></p>
    <p class="modal-warning">{{.Data.ShutdownWarning}}</p>
    <p id="shutdown-error" class="modal-error" role="alert"></p>
    <div class="modal-actions"><button id="shutdown-cancel" class="modal-button" type="button">{{.Data.Cancel}}</button><button id="shutdown-confirm" class="modal-button confirm" type="button" disabled></button></div>
  </section>
</div>
<script>
(function(){
  'use strict';
  var labels={loading:{{.Data.Loading}},empty:{{.Data.Empty}},loadFailed:{{.Data.LoadFailed}},wake:{{.Data.Wake}},waking:{{.Data.Waking}},wakeSuccess:{{.Data.WakeSuccess}},wakeFailed:{{.Data.WakeFailed}},shutdown:{{.Data.Shutdown}},shutdownDescription:{{.Data.ShutdownDescription}},shutdownConfirm:{{.Data.ShutdownConfirm}},shutdownConfirmCountdown:{{.Data.ShutdownConfirmCountdown}},shuttingDown:{{.Data.ShuttingDown}},shutdownAccepted:{{.Data.ShutdownAccepted}},shutdownUnknown:{{.Data.ShutdownUnknown}},shutdownFailed:{{.Data.ShutdownFailed}},online:{{.Data.Online}},offline:{{.Data.Offline}},unknown:{{.Data.Unknown}},lastChecked:{{.Data.LastChecked}}};
  var state=document.getElementById('state');var grid=document.getElementById('grid');var shutdownModal=document.getElementById('shutdown-modal');var shutdownDescription=document.getElementById('shutdown-description');var shutdownError=document.getElementById('shutdown-error');var shutdownCancel=document.getElementById('shutdown-cancel');var shutdownConfirm=document.getElementById('shutdown-confirm');var shutdownTarget=null;var shutdownDeadline=0;var shutdownTimer=null;var shutdownBusy=false;
  function text(tag,value,className){var node=document.createElement(tag);if(className)node.className=className;node.textContent=value||'';return node}
  function monitorIcon(){var icon=document.createElementNS('http://www.w3.org/2000/svg','svg');icon.setAttribute('viewBox','0 0 24 24');icon.setAttribute('fill','none');icon.setAttribute('stroke','currentColor');icon.setAttribute('stroke-width','2');icon.setAttribute('stroke-linecap','round');icon.setAttribute('stroke-linejoin','round');icon.setAttribute('aria-hidden','true');[['path','d','m9 10 3-3 3 3'],['path','d','M12 13V7'],['rect','width','20','height','14','x','2','y','3','rx','2'],['path','d','M12 17v4'],['path','d','M8 21h8']].forEach(function(spec){var node=document.createElementNS('http://www.w3.org/2000/svg',spec[0]);for(var index=1;index<spec.length;index+=2)node.setAttribute(spec[index],spec[index+1]);icon.appendChild(node)});return icon}
  function shutdownIcon(){var icon=document.createElementNS('http://www.w3.org/2000/svg','svg');icon.setAttribute('viewBox','0 0 24 24');icon.setAttribute('fill','none');icon.setAttribute('stroke','currentColor');icon.setAttribute('stroke-width','2');icon.setAttribute('stroke-linecap','round');icon.setAttribute('stroke-linejoin','round');icon.setAttribute('aria-hidden','true');[['path','d','M12 2v10'],['path','d','M18.4 6.6a9 9 0 1 1-12.77.04']].forEach(function(spec){var node=document.createElementNS('http://www.w3.org/2000/svg',spec[0]);for(var index=1;index<spec.length;index+=2)node.setAttribute(spec[index],spec[index+1]);icon.appendChild(node)});return icon}
  function apiFetch(url,options){var headers=new Headers(options&&options.headers||{});headers.set('Cache-Control','no-cache');return fetch(url,Object.assign({cache:'no-store',credentials:'same-origin'},options||{},{headers:headers}))}
  function statusLabel(value){return value==='online'?labels.online:value==='offline'?labels.offline:labels.unknown}
  function stopShutdownTimer(){if(shutdownTimer!==null)clearInterval(shutdownTimer);shutdownTimer=null}
  function resetShutdownDialog(){stopShutdownTimer();shutdownTarget=null;shutdownDeadline=0;shutdownBusy=false;shutdownError.textContent='';shutdownModal.hidden=true;shutdownCancel.disabled=false;shutdownConfirm.disabled=true}
  function updateShutdownCountdown(){var remaining=Math.max(0,Math.ceil((shutdownDeadline-Date.now())/1000));shutdownConfirm.textContent=remaining>0?labels.shutdownConfirmCountdown.replace('{seconds}',String(remaining)):labels.shutdownConfirm;shutdownConfirm.disabled=shutdownBusy||remaining>0;if(remaining===0)stopShutdownTimer()}
  function openShutdownDialog(item,controls){resetShutdownDialog();shutdownTarget={item:item,controls:controls};shutdownDeadline=Date.now()+3000;shutdownDescription.textContent=labels.shutdownDescription.replace('{target}',item.name||'').replace('{host}',item.sshHost||'');shutdownModal.hidden=false;updateShutdownCountdown();shutdownTimer=setInterval(updateShutdownCountdown,100);shutdownCancel.focus()}
  function scheduleRefreshes(){[5,20,35].forEach(function(seconds){setTimeout(load,seconds*1000)})}
  async function confirmShutdown(){if(!shutdownTarget||shutdownBusy||Date.now()<shutdownDeadline)return;var current=shutdownTarget;shutdownBusy=true;stopShutdownTimer();shutdownCancel.disabled=true;shutdownConfirm.disabled=true;shutdownConfirm.replaceChildren(text('span','', 'spinner'),document.createTextNode(labels.shuttingDown));shutdownError.textContent='';current.controls.setPending(true);try{var response=await apiFetch('/__auth__/api/auth/wol/targets/'+encodeURIComponent(current.item.id)+'/shutdown',{method:'POST'});var payload=await response.json().catch(function(){return null});if(response.status===504){current.controls.result.textContent=labels.shutdownUnknown;current.controls.result.className='result warning';resetShutdownDialog();scheduleRefreshes();return}if(!response.ok)throw new Error(payload&&payload.message||labels.shutdownFailed);current.controls.result.textContent=labels.shutdownAccepted;current.controls.result.className='result ok';resetShutdownDialog();scheduleRefreshes()}catch(error){shutdownBusy=false;shutdownCancel.disabled=false;shutdownConfirm.disabled=false;shutdownConfirm.textContent=labels.shutdownConfirm;shutdownError.textContent=error&&error.message||labels.shutdownFailed;current.controls.result.textContent=labels.shutdownFailed;current.controls.result.className='result error'}finally{current.controls.setPending(false)}}
  function render(items){grid.replaceChildren();if(!items.length){state.textContent=labels.empty;state.hidden=false;grid.hidden=true;return}state.hidden=true;grid.hidden=false;items.forEach(function(item){var card=text('article','', 'card');var head=text('div','', 'card-head');var names=text('div');names.appendChild(text('h2',item.name,'device-name'));var status=text('div','', 'status');var dot=text('span','', 'dot '+(item.status&&item.status.state||'unknown'));dot.setAttribute('aria-hidden','true');status.appendChild(dot);status.appendChild(text('span',statusLabel(item.status&&item.status.state)));head.appendChild(names);head.appendChild(status);card.appendChild(head);if(item.status&&item.status.checkedAt){var meta=text('div','', 'meta');meta.appendChild(text('span',labels.lastChecked.replace('{time}',new Date(item.status.checkedAt).toLocaleString())));card.appendChild(meta)}var actions=text('div','', 'actions');var result=text('span','', 'result');var actionButtons=text('div','', 'action-buttons');var wakeButton=text('button','','wake');wakeButton.type='button';wakeButton.replaceChildren(monitorIcon(),document.createTextNode(labels.wake));var shutdownButton=null;var pending=false;function setPending(value){pending=value;wakeButton.disabled=value;if(shutdownButton)shutdownButton.disabled=value}var controls={result:result,setPending:setPending};wakeButton.addEventListener('click',async function(){if(pending)return;setPending(true);wakeButton.replaceChildren(text('span','', 'spinner'),document.createTextNode(labels.waking));result.className='result';result.textContent='';try{var response=await apiFetch('/__auth__/api/auth/wol/targets/'+encodeURIComponent(item.id)+'/wake',{method:'POST'});var payload=await response.json().catch(function(){return null});if(!response.ok)throw new Error(payload&&payload.message||labels.wakeFailed);result.textContent=labels.wakeSuccess;result.className='result ok'}catch(error){result.textContent=error&&error.message||labels.wakeFailed;result.className='result error'}finally{setPending(false);wakeButton.replaceChildren(monitorIcon(),document.createTextNode(labels.wake))}});var online=item.status&&item.status.state==='online';if(online){if(item.shutdownAvailable){shutdownButton=text('button','','shutdown');shutdownButton.type='button';shutdownButton.replaceChildren(shutdownIcon(),document.createTextNode(labels.shutdown));shutdownButton.addEventListener('click',function(){if(!pending)openShutdownDialog(item,controls)});actionButtons.appendChild(shutdownButton)}}else{actionButtons.appendChild(wakeButton)}if(actionButtons.childNodes.length){actions.appendChild(result);actions.appendChild(actionButtons);card.appendChild(actions)}grid.appendChild(card)})}
  async function load(){try{var response=await apiFetch('/__auth__/api/auth/wol/targets?_ts='+Date.now());var payload=await response.json().catch(function(){return null});if(!response.ok)throw new Error(payload&&payload.message||labels.loadFailed);render(payload&&payload.data&&payload.data.items||[])}catch(error){state.hidden=false;grid.hidden=true;state.textContent=error&&error.message||labels.loadFailed}}
  shutdownCancel.addEventListener('click',function(){if(!shutdownBusy)resetShutdownDialog()});shutdownConfirm.addEventListener('click',confirmShutdown);shutdownModal.addEventListener('click',function(event){if(event.target===shutdownModal&&!shutdownBusy)resetShutdownDialog()});document.addEventListener('keydown',function(event){if(shutdownModal.hidden)return;if(event.key==='Escape'&&!shutdownBusy){event.preventDefault();resetShutdownDialog()}else if(event.key==='Enter'){event.preventDefault();confirmShutdown()}});
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
		Title:                    i18n.T(locale, "gateway.wol.title"),
		Description:              i18n.T(locale, "gateway.wol.description"),
		Loading:                  i18n.T(locale, "gateway.wol.loading"),
		Empty:                    i18n.T(locale, "gateway.wol.empty"),
		LoadFailed:               i18n.T(locale, "gateway.wol.loadFailed"),
		Wake:                     i18n.T(locale, "gateway.wol.wake"),
		Waking:                   i18n.T(locale, "gateway.wol.waking"),
		WakeSuccess:              i18n.T(locale, "gateway.wol.wakeSuccess"),
		WakeFailed:               i18n.T(locale, "gateway.wol.wakeFailed"),
		Shutdown:                 i18n.T(locale, "gateway.wol.shutdown"),
		ShutdownTitle:            i18n.T(locale, "gateway.wol.shutdownTitle"),
		ShutdownDescription:      i18n.T(locale, "gateway.wol.shutdownDescription"),
		ShutdownWarning:          i18n.T(locale, "gateway.wol.shutdownWarning"),
		ShutdownConfirm:          i18n.T(locale, "gateway.wol.shutdownConfirm"),
		ShutdownConfirmCountdown: i18n.T(locale, "gateway.wol.shutdownConfirmCountdown"),
		ShuttingDown:             i18n.T(locale, "gateway.wol.shuttingDown"),
		ShutdownAccepted:         i18n.T(locale, "gateway.wol.shutdownAccepted"),
		ShutdownUnknown:          i18n.T(locale, "gateway.wol.shutdownUnknown"),
		ShutdownFailed:           i18n.T(locale, "gateway.wol.shutdownFailed"),
		Cancel:                   i18n.T(locale, "gateway.cancel"),
		Online:                   i18n.T(locale, "gateway.wol.online"),
		Offline:                  i18n.T(locale, "gateway.wol.offline"),
		Unknown:                  i18n.T(locale, "gateway.wol.unknown"),
		LastChecked:              i18n.T(locale, "gateway.wol.lastChecked"),
		Back:                     i18n.T(locale, "gateway.wol.back"),
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
