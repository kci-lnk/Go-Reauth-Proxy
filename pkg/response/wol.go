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
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#18181b;background:#f4f4f5}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at top,#fff 0,#f4f4f5 52%,#e4e4e7 100%)}button,a{font:inherit}.shell{width:min(1120px,100%);margin:auto;padding:24px 16px 48px}.top{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:22px}.title-row{display:flex;align-items:center;gap:11px}.title-icon{width:30px;height:30px;flex:none}.title{margin:0;font-size:clamp(1.6rem,4vw,2.25rem);letter-spacing:-.035em}.desc{margin:8px 0 0;color:#71717a;line-height:1.6}.back{display:inline-flex;align-items:center;gap:7px;min-height:40px;padding:0 14px;border:1px solid #d4d4d8;border-radius:10px;background:#fff;color:#27272a;text-decoration:none;white-space:nowrap}.state{padding:56px 20px;border:1px dashed #d4d4d8;border-radius:18px;text-align:center;color:#71717a;background:rgba(255,255,255,.7)}.grid{display:grid;grid-template-columns:1fr;gap:14px}.card{display:flex;flex-direction:column;min-width:0;padding:18px;border:1px solid #e4e4e7;border-radius:18px;background:rgba(255,255,255,.92);box-shadow:0 8px 28px rgba(24,24,27,.06)}.card-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}.device-name{margin:0;font-size:1.1rem;overflow-wrap:anywhere}.note{margin:9px 0 0;color:#52525b;line-height:1.55;white-space:pre-wrap;overflow-wrap:anywhere}.status{display:inline-flex;align-items:center;gap:7px;flex:none;font-size:.82rem;color:#52525b}.dot{width:9px;height:9px;border-radius:999px;background:#f59e0b}.dot.online{background:#22c55e}.dot.offline{background:#a1a1aa}.meta{display:flex;flex-wrap:wrap;gap:7px 12px;margin-top:16px;padding-top:13px;border-top:1px solid #f0f0f1;color:#71717a;font-size:.78rem}.actions{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:auto;padding-top:18px}.result{min-height:20px;color:#71717a;font-size:.82rem}.result.ok{color:#15803d}.result.error{color:#b91c1c}.wake{display:inline-flex;align-items:center;justify-content:center;gap:8px;min-width:112px;min-height:42px;border:0;border-radius:11px;background:#18181b;color:#fff;font-weight:650;cursor:pointer}.wake svg{width:17px;height:17px}.wake:hover{background:#3f3f46}.wake:disabled{cursor:not-allowed;opacity:.58}.spinner{width:15px;height:15px;border:2px solid rgba(255,255,255,.4);border-top-color:#fff;border-radius:50%;animation:spin .75s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}@media(min-width:680px){.shell{padding:38px 24px 64px}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(min-width:1024px){.grid{grid-template-columns:repeat(3,minmax(0,1fr))}}@media(prefers-color-scheme:dark){:root{color:#f4f4f5;background:#09090b}body{background:radial-gradient(circle at top,#27272a 0,#09090b 60%)}.desc,.state,.meta,.result{color:#a1a1aa}.back,.card{border-color:#3f3f46;background:rgba(24,24,27,.92);color:#f4f4f5}.state{background:rgba(24,24,27,.65)}.note,.status{color:#d4d4d8}.meta{border-top-color:#3f3f46}.wake{background:#fafafa;color:#18181b}.wake:hover{background:#e4e4e7}}
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
  var secret='';var state=document.getElementById('state');var grid=document.getElementById('grid');
  function text(tag,value,className){var node=document.createElement(tag);if(className)node.className=className;node.textContent=value||'';return node}
  function monitorIcon(){var icon=document.createElementNS('http://www.w3.org/2000/svg','svg');icon.setAttribute('viewBox','0 0 24 24');icon.setAttribute('fill','none');icon.setAttribute('stroke','currentColor');icon.setAttribute('stroke-width','2');icon.setAttribute('stroke-linecap','round');icon.setAttribute('stroke-linejoin','round');icon.setAttribute('aria-hidden','true');[['path','d','m9 10 3-3 3 3'],['path','d','M12 13V7'],['rect','width','20','height','14','x','2','y','3','rx','2'],['path','d','M12 17v4'],['path','d','M8 21h8']].forEach(function(spec){var node=document.createElementNS('http://www.w3.org/2000/svg',spec[0]);for(var index=1;index<spec.length;index+=2)node.setAttribute(spec[index],spec[index+1]);icon.appendChild(node)});return icon}
  var sha256Constants=[1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298];
  function rotateRight(value,bits){return(value>>>bits)|(value<<(32-bits))}
  function concatBytes(left,right){var output=new Uint8Array(left.length+right.length);output.set(left);output.set(right,left.length);return output}
  function sha256(input){var size=Math.ceil((input.length+9)/64)*64;var data=new Uint8Array(size);data.set(input);data[input.length]=128;var view=new DataView(data.buffer);var bits=input.length*8;view.setUint32(size-8,Math.floor(bits/4294967296));view.setUint32(size-4,bits>>>0);var hash=[1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541459225];var words=new Uint32Array(64);for(var offset=0;offset<size;offset+=64){for(var index=0;index<16;index++)words[index]=view.getUint32(offset+index*4);for(index=16;index<64;index++){var word15=words[index-15],word2=words[index-2];var sigma0=rotateRight(word15,7)^rotateRight(word15,18)^(word15>>>3);var sigma1=rotateRight(word2,17)^rotateRight(word2,19)^(word2>>>10);words[index]=(words[index-16]+sigma0+words[index-7]+sigma1)>>>0}var a=hash[0],b=hash[1],c=hash[2],d=hash[3],e=hash[4],f=hash[5],g=hash[6],h=hash[7];for(index=0;index<64;index++){var big1=rotateRight(e,6)^rotateRight(e,11)^rotateRight(e,25);var choose=(e&f)^((~e)&g);var temp1=(h+big1+choose+sha256Constants[index]+words[index])>>>0;var big0=rotateRight(a,2)^rotateRight(a,13)^rotateRight(a,22);var majority=(a&b)^(a&c)^(b&c);var temp2=(big0+majority)>>>0;h=g;g=f;f=e;e=(d+temp1)>>>0;d=c;c=b;b=a;a=(temp1+temp2)>>>0}hash[0]=(hash[0]+a)>>>0;hash[1]=(hash[1]+b)>>>0;hash[2]=(hash[2]+c)>>>0;hash[3]=(hash[3]+d)>>>0;hash[4]=(hash[4]+e)>>>0;hash[5]=(hash[5]+f)>>>0;hash[6]=(hash[6]+g)>>>0;hash[7]=(hash[7]+h)>>>0}var output=new Uint8Array(32);var outputView=new DataView(output.buffer);hash.forEach(function(value,index){outputView.setUint32(index*4,value)});return output}
  function hmacSha256(key,message){if(key.length>64)key=sha256(key);var inner=new Uint8Array(64),outer=new Uint8Array(64);for(var index=0;index<64;index++){var value=key[index]||0;inner[index]=value^54;outer[index]=value^92}return sha256(concatBytes(outer,sha256(concatBytes(inner,message))))}
  function bytesToHex(bytes){return Array.from(bytes,function(value){return value.toString(16).padStart(2,'0')}).join('')}
  async function signHmac(key,message){var encoder=new TextEncoder();if(crypto.subtle){try{var cryptoKey=await crypto.subtle.importKey('raw',encoder.encode(key),{name:'HMAC',hash:'SHA-256'},false,['sign']);return bytesToHex(new Uint8Array(await crypto.subtle.sign('HMAC',cryptoKey,encoder.encode(message))))}catch(_){}}return bytesToHex(hmacSha256(encoder.encode(key),encoder.encode(message)))}
  function nonce(){var bytes=new Uint8Array(16);crypto.getRandomValues(bytes);return Array.from(bytes,function(value){return value.toString(16).padStart(2,'0')}).join('')}
  async function getSecret(){if(secret)return secret;var res=await fetch('/__auth__/__fn-knock/runtime-hmac-secret',{cache:'no-store'});if(!res.ok)throw new Error(labels.loadFailed);var body=await res.json();secret=body&&body.data&&body.data.hmacSecret||'';if(!secret)throw new Error(labels.loadFailed);return secret}
  async function signedFetch(url,options){var key=await getSecret();var timestamp=Date.now().toString();var requestNonce=nonce();var hex=await signHmac(key,timestamp+':'+requestNonce);var headers=new Headers(options&&options.headers||{});headers.set('x-timestamp',timestamp);headers.set('x-nonce',requestNonce);headers.set('x-signature',hex);headers.set('Cache-Control','no-cache');return fetch(url,Object.assign({cache:'no-store',credentials:'same-origin'},options||{},{headers:headers}))}
  function statusLabel(value){return value==='online'?labels.online:value==='offline'?labels.offline:labels.unknown}
  function render(items){grid.replaceChildren();if(!items.length){state.textContent=labels.empty;state.hidden=false;grid.hidden=true;return}state.hidden=true;grid.hidden=false;items.forEach(function(item){var card=text('article','', 'card');var head=text('div','', 'card-head');var names=text('div');names.appendChild(text('h2',item.name,'device-name'));if(item.note)names.appendChild(text('p',item.note,'note'));var status=text('div','', 'status');var dot=text('span','', 'dot '+(item.status&&item.status.state||'unknown'));dot.setAttribute('aria-hidden','true');status.appendChild(dot);status.appendChild(text('span',statusLabel(item.status&&item.status.state)));head.appendChild(names);head.appendChild(status);card.appendChild(head);if(item.status&&item.status.checkedAt){var meta=text('div','', 'meta');meta.appendChild(text('span',labels.lastChecked.replace('{time}',new Date(item.status.checkedAt).toLocaleString())));card.appendChild(meta)}var actions=text('div','', 'actions');var result=text('span','', 'result');var button=text('button','','wake');button.type='button';button.replaceChildren(monitorIcon(),document.createTextNode(labels.wake));button.addEventListener('click',async function(){button.disabled=true;button.replaceChildren(text('span','', 'spinner'),document.createTextNode(labels.waking));result.className='result';result.textContent='';try{var response=await signedFetch('/__auth__/api/auth/wol/targets/'+encodeURIComponent(item.id)+'/wake',{method:'POST'});var payload=await response.json().catch(function(){return null});if(!response.ok)throw new Error(payload&&payload.message||labels.wakeFailed);result.textContent=labels.wakeSuccess;result.className='result ok'}catch(error){result.textContent=error&&error.message||labels.wakeFailed;result.className='result error'}finally{button.disabled=false;button.replaceChildren(monitorIcon(),document.createTextNode(labels.wake))}});actions.appendChild(result);actions.appendChild(button);card.appendChild(actions);grid.appendChild(card)})}
  async function load(){try{var response=await signedFetch('/__auth__/api/auth/wol/targets?_ts='+Date.now());var payload=await response.json().catch(function(){return null});if(!response.ok)throw new Error(payload&&payload.message||labels.loadFailed);render(payload&&payload.data&&payload.data.items||[])}catch(error){state.hidden=false;grid.hidden=true;state.textContent=error&&error.message||labels.loadFailed}}
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
	if err := wolPageTmpl.Execute(w, wolPageTemplateData{Locale: locale, Data: data}); err != nil {
		http.Error(w, "Failed to render Wake-on-LAN page", http.StatusInternalServerError)
	}
}
