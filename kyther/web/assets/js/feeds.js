// Live feeds: cyber news, threat actors and World Pulse coverage.
import { API, $, state, esc, safeHref, ago, requestJson, setButtonBusy, isAbort } from './core.js';
export async function loadNews(btn=$("#attacksRefresh")){
  const done=setButtonBusy(btn);
  try{
    state.NEWS=await requestJson("news",API+"/api/news");
    const el=$("#newsList");
    if(!state.NEWS.length){ el.innerHTML='<div class="news-loading">feed unavailable.</div>'; }
    else el.innerHTML=state.NEWS.map(n=>`<a class="news-item" href="${safeHref(n.url)}" target="_blank" rel="noopener noreferrer"><div class="t">${esc(n.title)}</div><div class="m">${esc(n.source)} · ${esc(ago(n.ts))}</div></a>`).join("");
  }catch(e){
    if(isAbort(e)) return;
    $("#newsList").innerHTML='<div class="news-loading">feed unavailable.</div>';
  }finally{ done(); renderAttacks(); }
}
export function renderAttacks(){
  const el=$("#attacksList"); if(!el) return;
  if(!state.NEWS.length){ el.innerHTML='<div class="news-loading">feed unavailable.</div>'; return; }
  el.innerHTML=state.NEWS.map((n,i)=>`<a class="attack-item" href="${safeHref(n.url)}" target="_blank" rel="noopener noreferrer"><div class="ai-idx">${String(i+1).padStart(2,"0")}</div><div class="ai-body"><div class="ai-title">${esc(n.title)}</div><div class="ai-meta">${esc(n.source)} · ${esc(ago(n.ts))} ago</div></div><div class="ai-arrow">↗</div></a>`).join("");
}
// ---------- Threat Actors view (classified-dossier card gallery) ----------
let threatsBusy=false, thMotive="all";
const _norm=s=>String(s||"").toLowerCase().replace(/[^a-z0-9]/g,"");
let _activeGroups=new Set();

function motiveCat(m){
  const s=String(m||"").toLowerCase();
  if(s.includes("espionage")) return "espionage";
  if(s.includes("financial")||s.includes("theft")) return "financial";
  if(s.includes("hacktivism")||s.includes("ideolog")) return "hacktivism";
  if(s.includes("sabotage")||s.includes("destruction")||s.includes("denial")) return "sabotage";
  return "";
}
// Heuristic 1–5 threat rating — NOT an official score; labelled as such in the UI.
function threatRating(a){
  let s=1;
  if(a._cat==="espionage"||a._cat==="sabotage") s+=2;
  else if(a._cat==="financial") s+=1;
  if(a.sponsor) s+=1;
  if(a._active) s+=1;
  if((a.aliases||[]).length>=6) s+=1;
  return Math.max(1,Math.min(5,s));
}
function caseId(name){ let h=0; for(const c of (name||"")) h=(h*31+c.charCodeAt(0))>>>0; return "CF-"+String(h%9000+1000); }
function meter(n){ let s=""; for(let i=0;i<5;i++) s+=`<i class="${i<n?'on':''}"></i>`; return `<span class="d-meter">${s}</span>`; }
function flag(cc){ cc=String(cc||"").trim().toUpperCase(); if(!/^[A-Z]{2}$/.test(cc)) return ""; return String.fromCodePoint(0x1F1E6+cc.charCodeAt(0)-65, 0x1F1E6+cc.charCodeAt(1)-65); }
function actorForGroup(group){ const g=_norm(group); if(!g) return null; return ((state.THREATS&&state.THREATS.actors)||[]).find(a=>_norm(a.name)===g || (a.aliases||[]).some(x=>_norm(x)===g)) || null; }

function openIncident(i){
  const a=((state.THREATS&&state.THREATS.attacks)||[])[i]; if(!a) return;
  const actor=actorForGroup(a.group);
  const gang = actor ? `<a class="th-gang-link" data-actor="${esc(actor.name)}">${esc(a.group||"?")}</a>` : `<span style="color:#e0857f">${esc(a.group||"?")}</span>`;
  const where=[a.country,a.sector].filter(Boolean).map(esc).join(" · ");
  const links=[];
  if(a.ref) links.push(`<a class="th-d-ref" href="${safeHref(a.ref)}" target="_blank" rel="noopener noreferrer">view on ransomware.live ↗</a>`);
  if(a.press && a.press.url) links.push(`<a class="th-d-ref" href="${safeHref(a.press.url)}" target="_blank" rel="noopener noreferrer">read news coverage ↗</a>`);
  $("#thModalBody").innerHTML=`
    <div class="d-head" style="padding:0 0 6px"><span>Incident brief</span><span class="d-case">${esc(a.date||"")}</span></div>
    <div class="th-d-name">${esc(a.victim||"Unknown victim")}</div>
    <div class="th-d-represent" style="margin-top:6px">claimed by ${gang}${where?` · ${flag(a.country)} ${where}`:""}</div>
    ${a.domain?`<div class="th-d-represent"><span class="info">victim site:</span> <a class="th-d-ref" href="${safeHref('https://'+a.domain)}" target="_blank" rel="noopener noreferrer">${esc(a.domain)} ↗</a></div>`:""}
    ${a.description?`<div class="th-d-sec"><div class="plabel">About the victim</div><div class="th-d-desc">${esc(a.description)}</div></div>`:""}
    ${a.press&&a.press.summary?`<div class="th-d-sec"><div class="plabel">What happened</div><div class="th-d-desc">${esc(a.press.summary)}</div></div>`:""}
    ${links.length?`<div class="th-d-sec"><div class="plabel">View more</div>${links.map(l=>`<div style="padding:2px 0">${l}</div>`).join("")}</div>`:""}
    ${actor
      ? `<div class="th-d-sec"><a class="th-d-ref th-gang-link" data-actor="${esc(actor.name)}">open ${esc(actor.name)} dossier →</a></div>`
      : `<div class="th-d-sec"><span class="info" style="font-size:11.5px">No threat-actor profile on file for this gang yet.</span></div>`}`;
  const m=$("#thModal"); m.hidden=false; m.scrollTop=0;
}
function motiveTags(a){
  const tags=[];
  if(a.motive) tags.push(`<span class="mtag ${a._cat||''}">${esc(a.motive)}</span>`);
  if(a.origin) tags.push(`<span class="mtag origin">${esc(a.origin)}</span>`);
  return tags.join("");
}

export async function loadThreats(force,btn=$("#threatsRefresh")){
  if(threatsBusy) return;
  if(state.THREATS && !force){ renderThreats(); return; }
  threatsBusy=true;
  const done=setButtonBusy(btn);
  $("#thTimeline").innerHTML='<div class="rd-empty">loading live attack feed…</div>';
  $("#thGallery").innerHTML='<div class="rd-empty">loading threat actors…</div>';
  try{
    state.THREATS=await requestJson("threats",API+"/api/threats");
    _activeGroups=new Set((state.THREATS.attacks||[]).map(x=>_norm(x.group)));
    (state.THREATS.actors||[]).forEach(a=>{
      a._cat=motiveCat(a.motive);
      a._active=[_norm(a.name),...(a.aliases||[]).map(_norm)].some(k=>k && _activeGroups.has(k));
      a._rating=threatRating(a);
    });
    renderThreats();
  }catch(e){
    if(isAbort(e)) return;
    $("#thTimeline").innerHTML='<div class="rd-empty err">feed unavailable: '+esc(e.message)+'</div>';
    $("#thGallery").innerHTML='';
  }finally{ threatsBusy=false; done(); }
}

export function renderThreats(){
  const t=state.THREATS||{}, attacks=t.attacks||[], actors=t.actors||[];
  $("#thAttackMeta").textContent = attacks.length?`· ${attacks.length} latest, newest first`:"";
  const activeN=actors.filter(a=>a._active).length;
  $("#thActorMeta").textContent = actors.length?`· ${actors.length} tracked${activeN?` · ${activeN} active now`:""}`:"";
  $("#thTimeline").innerHTML = attacks.length ? attacks.map((a,i)=>{
    return `<div class="th-atk" data-idx="${i}"><span class="ta-date">${esc(a.date||"")}</span><span class="ta-flag">${flag(a.country)}</span><span class="ta-group">${esc(a.group||"?")}</span><span class="ta-victim">${esc(a.victim||"—")}</span><span class="ta-meta">${esc(a.sector||"")}</span></div>`;
  }).join("") : '<div class="rd-empty">feed unavailable.</div>';
  renderFilters(); renderSpotlight(); renderGallery();
}

function renderFilters(){
  const cats=[["all","All"],["active","Active now"],["espionage","Espionage"],["financial","Financial"],["hacktivism","Hacktivism"],["sabotage","Sabotage"]];
  $("#thFilters").innerHTML=cats.map(([k,l])=>`<span class="th-chip${thMotive===k?" on":""}" data-k="${k}">${l}</span>`).join("");
}

function currentActors(){
  const actors=(state.THREATS&&state.THREATS.actors)||[];
  const nq=_norm($("#thSearch")?$("#thSearch").value:"");
  return actors.filter(a=>{
    if(thMotive==="active" && !a._active) return false;
    if(thMotive!=="all" && thMotive!=="active" && a._cat!==thMotive) return false;
    if(nq){
      const hay=_norm(a.name)+_norm(a.motive)+_norm(a.origin)+_norm(a.sponsor)+(a.aliases||[]).map(_norm).join("");
      if(!hay.includes(nq)) return false;
    }
    return true;
  });
}

function dossierCard(a){
  return `<div class="dossier m-${a._cat||'none'}" data-name="${esc(a.name)}">
    <div class="d-stripe"></div>
    <div class="d-head"><span>Case File</span><span class="d-case">${caseId(a.name)}</span></div>
    <div class="d-body">
      <div class="d-name">${esc(a.name)}</div>
      <div class="d-tags">${motiveTags(a)||'<span class="mtag">unclassified</span>'}</div>
      <div class="d-rating">Threat ${meter(a._rating)}</div>
      <div class="d-foot"><span>${a.sponsor?esc(a.sponsor):(a.origin?'origin '+esc(a.origin):'')}</span>${a._active?'<span class="d-active">Active</span>':''}</div>
    </div>
  </div>`;
}

function renderGallery(){
  const list=currentActors().slice();
  list.sort((x,y)=> (y._active-x._active) || (y._rating-x._rating) || ((x.motive?0:1)-(y.motive?0:1)) || String(x.name).localeCompare(String(y.name)));
  const CAP=150, shown=list.slice(0,CAP), el=$("#thGallery");
  if(!shown.length){ el.innerHTML='<div class="rd-empty">no actors match this filter.</div>'; return; }
  el.innerHTML=shown.map(dossierCard).join("") + (list.length>CAP?`<div class="th-more">showing top ${CAP} of ${list.length} — refine with search or a filter</div>`:"");
}

function renderSpotlight(){
  const actors=(state.THREATS&&state.THREATS.actors)||[];
  const pool=actors.filter(a=>a.motive && a.description && (a.aliases||[]).length>=3);
  const src=pool.length?pool:actors.filter(a=>a.description);
  if(!src.length){ $("#thSpotlight").innerHTML=""; return; }
  const a=src[Math.floor(Date.now()/86400000)%src.length];   // deterministic per day
  $("#thSpotlight").innerHTML=`<div class="panel spotlight m-${a._cat||'none'}" data-name="${esc(a.name)}">
    <div class="d-stripe"></div>
    <div class="sp-inner">
      <div class="sp-l">
        <div class="sp-label">Featured dossier · actor of the day</div>
        <div class="sp-name">${esc(a.name)}</div>
        <div class="th-d-tags">${motiveTags(a)}${a._active?' <span class="d-active">Active now</span>':''}</div>
        <div class="d-rating" style="margin-top:10px">Threat ${meter(a._rating)}</div>
      </div>
      <div class="sp-r">
        <div class="sp-desc">${esc((a.description||"").slice(0,340))}${(a.description||"").length>340?'…':''}</div>
        <div class="sp-open">open full case file ↗</div>
      </div>
    </div>
  </div>`;
}

function actorDetailHTML(a){
  const rep=[];
  if(a.sponsor) rep.push(`state-sponsored by <b>${esc(a.sponsor)}</b>`);
  else if(a.origin) rep.push(`origin <b>${esc(a.origin)}</b>`);
  if(a.motive) rep.push(`primary motive <b>${esc(a.motive)}</b>`);
  const represent = rep.length?`<div class="th-d-represent">${rep.join(" · ")}</div>`:"";
  const keys=new Set([_norm(a.name), ...(a.aliases||[]).map(_norm)]);
  const atks=((state.THREATS&&state.THREATS.attacks)||[]).filter(x=>keys.has(_norm(x.group))).slice(0,12);
  const atkHtml=atks.length?`<div class="th-d-sec"><div class="plabel">Recent attacks by this group</div>${atks.map(x=>`<div class="th-d-atk"><span class="d">${esc(x.date||"")}</span><span class="v">${esc(x.victim||"—")}</span> <span class="info">${[x.country,x.sector].filter(Boolean).map(esc).join(" · ")}</span></div>`).join("")}</div>`:"";
  return `
    <div class="d-head" style="padding:0 0 6px"><span>Case File ${caseId(a.name)}</span>${a._active?'<span class="d-active">Active now</span>':''}</div>
    <div class="th-d-name">${esc(a.name)}</div>
    <div class="th-d-tags">${motiveTags(a)||'<span class="info" style="font-size:11px">unclassified</span>'}</div>
    <div class="d-rating" style="margin:9px 0">Threat rating ${meter(a._rating)} <span class="info" style="margin-left:6px;text-transform:none;letter-spacing:0">(heuristic)</span></div>
    ${represent}
    ${(a.targets||[]).length?`<div class="th-d-represent"><span class="info">targets:</span> ${a.targets.map(esc).join(", ")}</div>`:""}
    ${a.description?`<div class="th-d-sec"><div class="plabel">Profile</div><div class="th-d-desc">${esc(a.description)}</div></div>`:""}
    ${(a.aliases||[]).length?`<div class="th-d-sec"><div class="plabel">Also known as</div><div class="th-d-aliases">${a.aliases.map(x=>`<span>${esc(x)}</span>`).join(" · ")}</div></div>`:""}
    ${atkHtml}
    ${a.ref?`<div class="th-d-sec"><a class="th-d-ref" href="${safeHref(a.ref)}" target="_blank" rel="noopener noreferrer">reference ↗</a></div>`:""}`;
}

function openActor(name){
  const a=((state.THREATS&&state.THREATS.actors)||[]).find(x=>x.name===name);
  if(!a) return;
  $("#thModalBody").innerHTML=actorDetailHTML(a);
  const m=$("#thModal"); m.hidden=false; m.scrollTop=0;
}
function closeActor(){ $("#thModal").hidden=true; }

$("#thTimeline").addEventListener("click",e=>{ const r=e.target.closest(".th-atk"); if(r) openIncident(+r.dataset.idx); });
$("#thModalBody").addEventListener("click",e=>{ const g=e.target.closest(".th-gang-link"); if(g){ e.preventDefault(); openActor(g.dataset.actor); } });
$("#thGallery").addEventListener("click",e=>{ const c=e.target.closest(".dossier"); if(c) openActor(c.dataset.name); });
$("#thSpotlight").addEventListener("click",e=>{ const c=e.target.closest(".spotlight"); if(c) openActor(c.dataset.name); });
$("#thFilters").addEventListener("click",e=>{ const c=e.target.closest(".th-chip"); if(c){ thMotive=c.dataset.k; renderFilters(); renderGallery(); } });
$("#thSearch").addEventListener("input",renderGallery);
$("#thModalX").addEventListener("click",closeActor);
$("#thModal").addEventListener("click",e=>{ if(e.target.id==="thModal") closeActor(); });
document.addEventListener("keydown",e=>{ if(e.key==="Escape" && !$("#thModal").hidden) closeActor(); });
$("#threatsRefresh").addEventListener("click",e=>loadThreats(true,e.currentTarget));
// ---------- World Pulse view ----------
let pulseInited=false, pulseTopic=null, pulseData=null;
// Mirrors PULSE_REGIONS in api.py so the dropdown still populates on failure.
const PULSE_REGIONS_FALLBACK={en:"Global (English)",es:"Spanish",hi:"Hindi / India",ar:"Arabic",fr:"French",de:"German",pt:"Portuguese",ja:"Japanese",ru:"Russian",zh:"Chinese"};
function setPulseRegions(regions, selected){
  const sel=$("#pulseRegion");
  if(sel.options.length) return;
  const src=(regions&&Object.keys(regions).length)?regions:PULSE_REGIONS_FALLBACK;
  sel.innerHTML=Object.entries(src).map(([k,v])=>`<option value="${esc(k)}"${k===selected?" selected":""}>${esc(v)}</option>`).join("");
}
export function initPulse(){
  if(pulseInited){ $("#pulseInput").focus(); return; }
  pulseInited=true;
  loadPulseTrending("en");
  $("#pulseInput").focus();
}
function trendRetryButton(id){
  return `<div style="margin-top:10px"><button id="${id}" class="vh-btn">retry</button></div>`;
}
export async function loadPulseTrending(region,btn=$("#pulseRefresh")){
  const el=$("#pulseTrend"), done=setButtonBusy(btn);
  el.innerHTML='<div class="rd-empty">loading trending topics…</div>';
  try{
    const d=await requestJson("pulse-trend",API+"/api/pulse/trending?region="+encodeURIComponent(region));
    setPulseRegions(d.regions, region);
    if(!d.topics || !d.topics.length){
      el.innerHTML=`<div class="pulse-empty${d.ok?"":" err"}">${esc(d.message||"trending unavailable for this region right now.")}</div>`+
        (d.ok?"":trendRetryButton("pulseTrendRetry"));
      const rb=$("#pulseTrendRetry"); if(rb) rb.addEventListener("click",e=>loadPulseTrending($("#pulseRegion").value||region,e.currentTarget));
      return;
    }
    el.innerHTML=d.topics.map(t=>`<span class="pulse-chip" data-topic="${esc(t.topic)}">${esc(t.topic)}${t.views?`<span class="pc-v">${Number(t.views).toLocaleString()}</span>`:""}</span>`).join("");
  }catch(e){
    if(isAbort(e)) return;
    setPulseRegions(null, region);
    el.innerHTML='<div class="pulse-empty err">couldn\'t load trending: '+esc(e.message)+'</div>'+trendRetryButton("pulseTrendRetry");
    const rb=$("#pulseTrendRetry"); if(rb) rb.addEventListener("click",e=>loadPulseTrending($("#pulseRegion").value||region,e.currentTarget));
  }finally{ done(); }
}
let pulseBusy=false;
export async function runPulseTopic(q,btn=$("#pulseGo")){
  q=(q||"").trim(); if(!q||pulseBusy) return;
  pulseBusy=true; pulseTopic=q;
  const done=setButtonBusy(btn);
  $("#pulseInput").value=q;
  $("#pulseResult").innerHTML='<div class="rd-empty">gathering coverage across regions<span class="blink">_</span></div>';
  try{
    pulseData=await requestJson("pulse-topic",API+"/api/pulse/topic?q="+encodeURIComponent(q));
    renderPulseTopic();
  }catch(e){
    if(isAbort(e)) return;
    pulseData=null;
    $("#pulseResult").innerHTML='<div class="pulse-empty err">lookup failed: '+esc(e.message)+'</div>'+
      '<div style="margin-top:10px"><button id="pulseRetry" class="vh-btn">retry</button></div>';
    const rb=$("#pulseRetry"); if(rb) rb.addEventListener("click",e=>runPulseTopic(pulseTopic,e.currentTarget));
  }finally{ pulseBusy=false; done(); }
}
function pulseArt(a){
  const meta=[a.source,a.date].filter(Boolean).map(esc).join(" · ");
  return `<a class="pulse-art" href="${safeHref(a.url)}" target="_blank" rel="noopener noreferrer"><div class="pa-title">${esc(a.title||"(untitled)")}</div><div class="pa-meta">${meta}</div></a>`;
}
function renderPulseTopic(){
  const d=pulseData, box=$("#pulseResult");
  if(!d || !d.ok){
    box.innerHTML=`<div class="pulse-empty err">${esc((d&&d.message)||"No coverage found.")}</div>`+
      (d&&d.error==="source_busy"?`<div style="margin-top:10px"><button id="pulseRetry" class="vh-btn">retry</button></div>`:"");
    const rb=$("#pulseRetry"); if(rb) rb.addEventListener("click",e=>runPulseTopic(pulseTopic,e.currentTarget));
    return;
  }
  const avail=(d.available==null?d.sides.length:d.available);
  const meta=[`${d.total} recent article${d.total===1?"":"s"}`,
              `across ${avail} of ${d.sides.length} country editions`];
  if(d.partial) meta.push(`${(d.failed||[]).length} edition${(d.failed||[]).length===1?"":"s"} unavailable`);
  const head=`<div class="pulse-topic-head"><span class="pt-name">${esc(d.q)}</span><span class="pt-meta">${esc(meta.join(" · "))} — compare coverage, not tone</span></div>`;
  const read=(d.read&&d.read.length)?`<div class="pulse-read"><div class="pr-h">Coverage read</div><ul>${d.read.map(x=>`<li>${esc(x)}</li>`).join("")}</ul></div>`:"";
  const cols=(d.sides||[]).map(s=>{
    if(s.error) return `<div class="pulse-group failed"><div class="pg-head"><span class="pg-country">${esc(s.label)}</span><span class="pg-count">unavailable</span></div><div class="pulse-empty err">edition failed: ${esc(s.error)}</div></div>`;
    const n=(s.articles||[]).length;
    return `<div class="pulse-group"><div class="pg-head"><span class="pg-country">${esc(s.label)}</span><span class="pg-count">${n} article${n===1?"":"s"}</span></div>${(s.articles||[]).map(pulseArt).join("")||'<div class="pulse-empty">no recent articles in this edition (valid zero result).</div>'}</div>`;
  }).join("");
  box.innerHTML=head+read+`<div class="pulse-region-grid">${cols}</div>`;
}
$("#pulseRefresh").addEventListener("click",e=>loadPulseTrending($("#pulseRegion").value||"en",e.currentTarget));
$("#pulseRegion").addEventListener("change",e=>loadPulseTrending(e.target.value,e.currentTarget));
$("#pulseTrend").addEventListener("click",e=>{ const c=e.target.closest(".pulse-chip"); if(c) runPulseTopic(c.dataset.topic,e.currentTarget); });
$("#pulseGo").addEventListener("click",e=>runPulseTopic($("#pulseInput").value,e.currentTarget));
$("#pulseInput").addEventListener("keydown",e=>{ if(e.key==="Enter") runPulseTopic($("#pulseInput").value,e.currentTarget); });
