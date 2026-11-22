// Shared browser-side primitives: DOM helpers, safe fetching with cancellation,
// local storage state and view plumbing. No view-specific code lives here.
export const API = location.protocol.startsWith("http") ? "" : "http://127.0.0.1:8099";
export const $ = s => document.querySelector(s);
export const term = $("#term"), cmdIn = $("#cmd");

export const store = {
  get:(k,d)=>{try{return JSON.parse(localStorage.getItem(k))??d}catch{return d}},
  set:(k,v)=>localStorage.setItem(k,JSON.stringify(v)),
};

export const TYPES = ["username","email","domain","ip","phone","person","company"];
export const state = {
  TYPE: "username",
  busy: false,
  LAST_SEARCH: null,
  stats: store.get("kyther_stats",{scanned:0,found:0,hits:0,threat:"LOW"}),
  log: store.get("kyther_log",[]),
  NEWS: [],
  THREATS: null,
  selectedLogId: null,
};

// Backfill ids for entries logged before detail-capture existed.
let _mig = false;
state.log.forEach((e,i)=>{ if(!e.id){ e.id="s"+(e.ts||0).toString(36)+"i"+i+Math.random().toString(36).slice(2,5); _mig=true; } });
if(_mig) store.set("kyther_log",state.log);

// ---- Cancellation + busy affordances --------------------------------------
const _controllers = new Map();
export function beginRequest(key){
  _controllers.get(key)?.abort();               // supersede the previous request
  const controller = new AbortController();
  _controllers.set(key, controller);
  return controller;
}
export function endRequest(key, controller){
  if(_controllers.get(key) === controller) _controllers.delete(key);
}
export function isAbort(e){ return !!e && e.name === "AbortError"; }

// Fetch + status check in one place: a 500 returning JSON must not be rendered
// as if the lookup succeeded.
async function check(r){
  if(r.ok) return r;
  let detail = "";
  try { detail = (await r.json()).detail || ""; } catch(_) {}
  throw new Error(detail ? JSON.stringify(detail) : "HTTP " + r.status);
}
export async function apiJson(url, opts){
  return (await check(await fetch(url, opts))).json();
}
export async function apiBlob(url, opts){
  return (await check(await fetch(url, opts))).blob();
}
// One caller per key: a second click cancels the first instead of racing it.
export async function requestJson(key, url, opts={}){
  const controller = beginRequest(key);
  try { return await apiJson(url, {...opts, signal: controller.signal}); }
  finally { endRequest(key, controller); }
}
export async function requestBlob(key, url, opts={}){
  const controller = beginRequest(key);
  try { return await apiBlob(url, {...opts, signal: controller.signal}); }
  finally { endRequest(key, controller); }
}
export function setButtonBusy(btn, text){
  if(!btn) return ()=>{};
  const idle = btn.dataset.idleLabel ?? btn.textContent;
  btn.dataset.idleLabel = idle;
  btn.disabled = true;
  btn.classList.add("busy");
  if(text) btn.textContent = text;
  return ()=>{
    btn.disabled = false;
    btn.classList.remove("busy");
    btn.textContent = idle;
  };
}

// Views register lazily-loaded hooks here so switching tabs never duplicates
// listeners, and the core module stays free of view imports.
const _viewHooks = {};
let _refreshLogs = ()=>{};
export function registerViewHooks(hooks){ Object.assign(_viewHooks, hooks); }
export function setRefreshLogs(fn){ _refreshLogs = fn; }
export function showView(v){
  document.querySelectorAll(".view").forEach(s=>{ s.hidden = s.id!=="view-"+v; });
  document.querySelectorAll(".nav-item").forEach(b=>b.classList.toggle("on",b.dataset.view===v));
  if(v==="reddit") $("#rdInput").focus();
  if(_viewHooks[v]) _viewHooks[v]();
  window.scrollTo(0,0);
}

// Toggle the collapsed "unverified accounts" list when its expander is clicked.
term.addEventListener("click",e=>{
  const ex=e.target.closest(".expander"); if(!ex) return;
  const el=document.getElementById(ex.dataset.t); if(!el) return;
  const showing=el.style.display!=="none";
  el.style.display=showing?"none":"inline";
  ex.textContent=(showing?"show ":"hide ")+ex.dataset.n+(showing?" ▸":" ▾");
});
export const esc=s=>String(s).replace(/[&<>"'`]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;","`":"&#96;"}[c]));
// Only http(s) URLs (or in-page anchors) may become clickable links. Third-party
// data must never put javascript:/data: into an href, even when HTML-escaped.
export function safeHref(u){
  const s=String(u==null?'':u).trim();
  if(s.startsWith('#')) return esc(s);
  try{
    const parsed=new URL(s, location.href);
    return (parsed.protocol==='http:'||parsed.protocol==='https:')?esc(parsed.href):'#';
  }catch(e){ return '#'; }
}
export function put(html,cls){ const d=document.createElement("div"); d.className="line "+(cls||""); d.innerHTML=html; term.appendChild(d); term.scrollTop=term.scrollHeight; return d; }
export function banner(){
  put('<span class="ok">Kyther</span> <span class="info">v0.2 — 20 analyzers online</span>');
  put('<span class="info">type a command, or use Quick Search below. `help` for options.</span>');
  put('&nbsp;');
}
export function renderStats(){
  $("#stScanned").textContent=state.stats.scanned;
  $("#stFound").textContent=state.stats.found.toLocaleString();
  $("#stRate").textContent=state.stats.scanned?Math.round(state.stats.hits/state.stats.scanned*100*10)/10+"%":"—";
  renderRisk();
}
function renderRisk(){
  const r=state.stats.risk, main=$("#riskMain"), fac=$("#riskFactors");
  if(!r){ main.textContent="—"; main.style.color="var(--dim)"; fac.innerHTML='<span class="foot">no scan yet</span>'; return; }
  // RED for Critical/High, YELLOW for Medium, GREEN for Low
  const col = (r.tier==="Critical"||r.tier==="High") ? "var(--dot-r)"
            : r.tier==="Medium" ? "var(--dot-y)" : "var(--green)";
  main.style.color=col;
  main.textContent=`${r.tier} (${r.score}/100)`;
  fac.innerHTML='<div class="rf-label">Top factors</div>' +
    (r.factors||[]).map(f=>`<div class="rf"><span class="lbl">• ${esc(f.label)}</span><span class="pts">${f.points}</span></div>`).join("");
}
export function renderLog(){
  const el=$("#logList");
  if(!state.log.length){ el.innerHTML='<div class="log-empty">no searches yet — run a command above.</div>'; return; }
  el.innerHTML=state.log.slice(0,25).map(e=>
    `<div class="log-item" data-id="${esc(e.id||"")}"><span class="log-time">${esc(e.time)}</span><span class="log-cmd"><span class="t">--${esc(e.type)}</span> ${esc(e.value)}</span><span class="log-res">${esc(e.result)}</span></div>`
  ).join("");
}
export function addLog(type,value,result,detail){
  const id="s"+Date.now().toString(36)+Math.random().toString(36).slice(2,5);
  state.log.unshift({id, ts:Date.now(), time:new Date().toLocaleTimeString([], {hour:"2-digit",minute:"2-digit",second:"2-digit"}),type,value,result});
  state.log=state.log.slice(0,60); store.set("kyther_log",state.log);
  if(detail) saveDetail(id,detail);
  renderLog();
  if(!$("#view-logs").hidden) _refreshLogs();
}
// Persist the full scan result for a state.log entry so Logs can show every detail
// later. localStorage is small, so keep only the 15 most-recent searches'
// details and evict oldest on quota overflow.
function saveDetail(id,d){
  let det=store.get("kyther_details",{});
  det[id]=d;
  const keep=new Set(state.log.slice(0,15).map(e=>e.id));
  for(const k of Object.keys(det)) if(!keep.has(k)) delete det[k];
  try{ store.set("kyther_details",det); }
  catch(_){
    const ids=state.log.slice(0,15).map(e=>e.id).filter(k=>det[k]);
    while(ids.length){ delete det[ids.pop()]; try{ store.set("kyther_details",det); break; }catch(__){} }
  }
}
export function getDetail(id){ return store.get("kyther_details",{})[id]||null; }
export function ago(ts){ if(!ts)return""; const s=Date.now()/1000-ts; if(s<3600)return Math.round(s/60)+"m"; if(s<86400)return Math.round(s/3600)+"h"; return Math.round(s/86400)+"d"; }
