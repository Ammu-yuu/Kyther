// Detail views: logs, Reddit, Company Footprint and Image Intelligence.
import { API, $, state, store, esc, safeHref, requestJson,
         setButtonBusy, isAbort, showView, getDetail } from './core.js';
import { runSearch, runAudit, setType, dedupe } from './scan.js';

function panelSec(label,html){ return html?`<div class="th-sec"><div class="plabel">${label}</div>${html}</div>`:""; }
function riskColor(tier){ return (tier==="Critical"||tier==="High")?"var(--dot-r)":tier==="Medium"?"var(--dot-y)":"var(--green)"; }

// ---------- Logs view ----------
export function renderLogsFull(){
  const el=$("#logsFull"); if(!el) return;
  if(!state.log.length){ el.innerHTML='<div class="ld-empty">no searches yet.</div>'; $("#logsDetail").innerHTML='<div class="ld-empty">run a search from Home to see it here.</div>'; return; }
  el.innerHTML=state.log.map(e=>`<div class="log-row${e.id===state.selectedLogId?" on":""}" data-id="${esc(e.id)}"><div class="lr-top"><span class="lr-val">${esc(e.value)}</span><span class="lr-type">--${esc(e.type)}</span></div><div class="lr-meta"><span>${esc(e.time)}</span><span>·</span><span>${esc(e.result)}</span></div></div>`).join("");
}
export function selectLog(id){
  state.selectedLogId=id; renderLogsFull();
  const entry=state.log.find(e=>e.id===id), box=$("#logsDetail");
  box.innerHTML = entry ? detailHTML(entry) : '<div class="ld-empty">not found.</div>';
  box.scrollTop=0;
}
function auditDetailHTML(entry,d){
  const sec=(label,html)=>html?`<div class="ld-sec"><div class="plabel">${label}</div><div class="ld-body">${html}</div></div>`:"";
  const head=`<div class="ld-h"><div><div class="ld-h-val">Security audit · kyther</div><div class="ld-h-meta"><span class="lr-type">--audit</span> · ${esc(entry.time)} · ${esc(entry.result)}</div></div><div class="ld-actions"><button class="ld-btn audit">⛊ Run audit again</button></div></div>`;
  if(!d) return head+`<div class="ld-sec"><div class="ld-empty">Full audit detail wasn't saved for this run. Hit “Run audit again” to re-scan and capture everything.</div></div>`;
  const b=d.bandit||{}, dp=d.deps||{};
  const sevChip=s=>`<span class="aud-sev ${String(s||"").toLowerCase()}">${esc(s)}</span>`;
  // code (bandit)
  let code;
  if(b.available===false) code='<div class="ld-empty">bandit not installed — <code>pip install bandit</code>.</div>';
  else if(b.error) code=`<div class="ld-empty">bandit: ${esc(b.error)}</div>`;
  else{
    code=`<div class="aud-sum"><span class="${b.high?'aud-hi':'ok'}">${b.high||0} high</span> · <span class="aud-med">${b.medium||0} medium</span> · <span class="info">${b.low||0} low</span> <span class="info">· ${b.loc||0} LOC</span></div>`;
    const rows=(b.findings||[]).map(f=>`<div class="ld-kv aud-row">${sevChip(f.sev)}<span class="kv">${esc(f.id)}</span><span class="val">${esc(f.file)}:${esc(f.line)}</span><span class="info">${esc(f.text)}</span></div>`).join("");
    code+=rows||'<div class="ok">✓ no code issues.</div>';
  }
  // dependencies (pip-audit)
  let deps;
  if(dp.available===false) deps='<div class="ld-empty">pip-audit not installed — <code>pip install pip-audit</code>.</div>';
  else if(dp.error) deps=`<div class="ld-empty">pip-audit: ${esc(dp.error)}</div>`;
  else{
    deps=`<div class="aud-sum"><span class="${dp.vuln_count?'aud-hi':'ok'}">${dp.vuln_count||0} CVEs</span> <span class="info">across ${dp.pkg_count||0} packages</span></div>`;
    const rows=(dp.packages||[]).map(p=>`<div class="ld-kv aud-row"><span class="val">${esc(p.name)}</span><span class="kv">${esc(p.version)}</span><span class="info">${p.count} ${p.count===1?'advisory':'advisories'}${p.fix?' → '+esc(p.fix):''}</span></div>`).join("");
    deps+=rows||'<div class="ok">✓ no known CVEs.</div>';
  }
  const raw=`<details class="ld-raw"><summary>raw capture (full JSON)</summary><pre class="ld-pre">${esc(JSON.stringify(d,null,2))}</pre></details>`;
  return head+sec("Code — Bandit (SAST)",code)+sec("Dependencies — pip-audit",deps)+sec("Full capture",raw);
}
function detailHTML(entry){
  const d=getDetail(entry.id);
  if(entry.type==="audit"||(d&&d.__audit)) return auditDetailHTML(entry,d);
  const head=`<div class="ld-h"><div><div class="ld-h-val">${esc(entry.value)}</div><div class="ld-h-meta"><span class="lr-type">--${esc(entry.type)}</span> · ${esc(entry.time)} · ${esc(entry.result)}</div></div><div class="ld-actions"><button class="ld-btn run" data-type="${esc(entry.type)}" data-value="${esc(entry.value)}">▷ Run command again</button><button class="ld-btn again" data-type="${esc(entry.type)}" data-value="${esc(entry.value)}">⌕ Search again</button></div></div>`;
  if(!d) return head + `<div class="ld-sec"><div class="ld-empty">Full details weren't saved for this search (it predates detail capture, or the scan errored). Hit “Run command again” to re-scan and capture everything.</div></div>`;
  const findings=d.findings||[], catf=c=>findings.filter(f=>f.category===c);
  const accounts=dedupe(catf("accounts").flatMap(f=>f.data.profiles||[]));
  const dos=d.dossier||{}, risk=dos.risk;
  const infra=catf("infrastructure"), timeline=d.timeline||[];
  const breachesArr=catf("breaches").flatMap(f=>f.data.breaches||[]);
  const sec=(label,html)=>html?`<div class="ld-sec"><div class="plabel">${label}</div><div class="ld-body">${html}</div></div>`:"";

  let riskHtml="";
  if(risk){ riskHtml=`<div class="ld-risk" style="color:${riskColor(risk.tier)}">${esc(risk.tier)} · ${risk.score}/100</div>`+(risk.factors||[]).map(f=>`<div class="rf"><span class="lbl">${esc(f.label)}</span><span class="pts">+${f.points}</span></div>`).join(""); }

  const idb=[];
  if(dos.primary_name) idb.push(`<div class="ld-kv"><span class="kv">name</span><span class="val">${esc(dos.primary_name)}</span></div>`);
  if((dos.locations||[]).length) idb.push(`<div class="ld-kv"><span class="kv">location</span><span class="val">${esc(dos.locations.join(", "))}</span></div>`);
  if((dos.companies||[]).length) idb.push(`<div class="ld-kv"><span class="kv">org</span><span class="val">${esc(dos.companies.join(", "))}</span></div>`);

  const emails=(dos.emails||[]).map(e=>`<div class="ld-kv"><span class="val">${esc(e.email)}</span>${e.noreply?' <span class="info">(noreply)</span>':""}</div>`).join("");

  let acc="";
  if(accounts.length){
    const conf=accounts.filter(p=>(p.confidence||"possible")==="confirmed");
    const unv=accounts.filter(p=>(p.confidence||"possible")!=="confirmed");
    acc+=`<div class="ld-accsum"><span class="ok">${conf.length} verified</span> <span class="kv">·</span> <span class="info">${unv.length} unverified</span> <span class="kv">·</span> ${accounts.length} total</div>`;
    if(conf.length){
      const g={}; conf.forEach(p=>{const k=(p.category||"other").replace(/xx/gi,"").trim()||"other";(g[k]=g[k]||[]).push(p);});
      acc+=Object.entries(g).sort((a,b)=>b[1].length-a[1].length).map(([c,ps])=>`<div class="ld-accrow"><span class="kv">${esc(c)}:</span> ${ps.map(p=>`<a class="match" href="${safeHref(p.url)}" target="_blank" rel="noopener noreferrer">${esc(p.platform)}</a>`).join(" ")}</div>`).join("");
    }
    if(unv.length){
      acc+=`<details class="ld-unv"><summary>show ${unv.length} unverified (status-code guesses — some don't exist)</summary><div class="ld-unv-links">${unv.map(p=>`<a class="unv-link" href="${safeHref(p.url)}" target="_blank" rel="noopener noreferrer">${esc(p.platform)}</a>`).join(" ")}</div></details>`;
    }
  }

  const infraHtml=infra.map(f=>`<div class="ld-kv"><span class="kv">${esc(f.analyzer)}</span><span class="val">${esc(f.title)}</span></div>`).join("");
  const tlHtml=timeline.map(t=>`<div class="ld-kv"><span class="kv">${esc(t.date||t.time||t.year||"—")}</span><span class="val">${esc(t.label||t.title||t.event||t.description||JSON.stringify(t))}</span>${t.source?` <span class="info">(${esc(t.source)})</span>`:""}</div>`).join("");
  const brHtml=breachesArr.length?breachesArr.map(b=>`<div class="ld-kv"><span class="val">${esc(b.name||b.Name||b.title||"breach")}</span> <span class="info">${esc(b.date||b.BreachDate||"")}</span></div>`).join(""):"";

  // Render the profile-enrichment fields the API returns but the log viewer
  // previously ignored (they were only visible inside the raw JSON dump).
  const enrich=[];
  if((dos.names||[]).length>1) enrich.push(`<div class="ld-kv"><span class="kv">other names</span><span class="val">${esc(dos.names.join(" · "))}</span></div>`);
  if((dos.enriched_platforms||[]).length) enrich.push(`<div class="ld-kv"><span class="kv">profiles checked</span><span class="val">${esc(dos.enriched_platforms.join(", "))}</span></div>`);
  (dos.bios||[]).forEach(b=>enrich.push(`<div class="ld-kv"><span class="kv">bio · ${esc(b.platform)}</span><span class="val">${esc(b.text)}</span></div>`));
  (dos.avatars||[]).forEach(a=>{ const href=safeHref(a.url); if(href!=="#") enrich.push(`<div class="ld-kv"><span class="kv">avatar · ${esc(a.platform)}</span><a href="${href}" target="_blank" rel="noopener noreferrer"><img src="${href}" alt="" style="width:24px;height:24px;border-radius:50%;object-fit:cover;border:1px solid var(--border);vertical-align:middle"></a></div>`); });
  (dos.links||[]).forEach(l=>enrich.push(`<div class="ld-kv"><a class="match" href="${safeHref(l)}" target="_blank" rel="noopener noreferrer">${esc(l)}</a></div>`));
  (dos.linked_accounts||[]).forEach(a=>enrich.push(`<div class="ld-kv"><span class="kv">linked · ${esc(a.service||a.platform||"proof")}</span>${a.url?`<a class="match" href="${safeHref(a.url)}" target="_blank" rel="noopener noreferrer">${esc(a.handle||a.url)}</a>`:`<span class="val">${esc(a.handle||"")}</span>`}</div>`));

  const raw=`<details class="ld-raw"><summary>raw capture (full JSON)</summary><pre class="ld-pre">${esc(JSON.stringify(d,null,2))}</pre></details>`;

  const body=sec("Risk",riskHtml)+sec("Identity",idb.join(""))+sec("Emails",emails)+sec("Accounts",acc)+sec("Enrichment",enrich.join(""))+sec("Infrastructure",infraHtml)+sec("Timeline",tlHtml)+sec("Breaches",brHtml)+sec("Full capture",raw);
  return head + (body || `<div class="ld-sec"><div class="ld-empty">no findings were captured for this search.</div></div>`);
}
$("#logsFull").addEventListener("click",e=>{ const r=e.target.closest(".log-row"); if(r) selectLog(r.dataset.id); });
$("#logsDetail").addEventListener("click",e=>{
  const run=e.target.closest(".ld-btn.run"), again=e.target.closest(".ld-btn.again"), aud=e.target.closest(".ld-btn.audit");
  if(aud){ showView("home"); runAudit(); }
  else if(run){ showView("home"); setType(run.dataset.type); runSearch(run.dataset.type,run.dataset.value); }
  else if(again){ showView("home"); setType(again.dataset.type); $("#qval").value=again.dataset.value; $("#qval").focus(); }
});
$("#logsClearAll").addEventListener("click",()=>{ state.log=[]; store.set("kyther_log",state.log); store.set("kyther_details",{}); state.selectedLogId=null; renderLog(); renderLogsFull(); });
$("#logList").addEventListener("click",e=>{ const it=e.target.closest(".log-item"); if(it&&it.dataset.id){ showView("logs"); selectLog(it.dataset.id); } });
$("#attacksRefresh").addEventListener("click",e=>loadNews(e.currentTarget));
// ---------- Reddit view ----------
let rdBusy=false;
export async function runReddit(raw,btn=$("#rdGo")){
  if(rdBusy) return;
  const u=(raw||"").trim(); if(!u) return;
  rdBusy=true; const done=setButtonBusy(btn);
  $("#rdResult").innerHTML='<div class="rd-empty">searching Reddit archives<span class="blink">_</span></div>';
  try{
    renderReddit(await requestJson("reddit",API+"/api/reddit?u="+encodeURIComponent(u)));
  }catch(e){
    if(isAbort(e)) return;
    $("#rdResult").innerHTML='<div class="rd-empty err">lookup failed: '+esc(e.message)+'</div>';
  }finally{ rdBusy=false; done(); }
}
function renderReddit(d){
  const box=$("#rdResult");
  if(!d || !d.found){
    box.innerHTML=`<div class="rd-empty ${d&&d.error==='fetch_failed'?'err':''}">${esc((d&&d.message)||"No archived Reddit activity found.")}</div>`;
    return;
  }

  const k=d.karma||{}, fl=d.flags||{};
  const num=n=>(n==null?"—":Number(n).toLocaleString());
  const badge=(on,label,cls)=>on?`<span class="rd-badge ${cls||""}">${label}</span>`:"";
  const badges=[badge(fl.gold,"gold"),badge(fl.mod,"mod"),badge(fl.employee,"admin"),
                badge(fl.verified_email,"verified email"),badge(fl.nsfw,"NSFW","nsfw")].join("");
  const stat=(lbl,val,foot)=>`<div class="panel rd-stat"><div class="plabel">${lbl}</div><div class="n">${val}</div>${foot?`<div class="foot">${esc(foot)}</div>`:""}</div>`;

  const acts=(d.counts&&(d.counts.posts_fetched||0)+(d.counts.comments_fetched||0))||0;
  const maxSub=Math.max(1,...(d.top_subreddits||[]).map(s=>s.count));
  const subs=(d.top_subreddits||[]).map(s=>`<a class="rd-bar" href="https://www.reddit.com/r/${encodeURIComponent(s.subreddit)}" target="_blank" rel="noopener noreferrer"><span class="rb-name">r/${esc(s.subreddit)}</span><span class="rb-track"><span class="rb-fill" style="width:${Math.round(s.count/maxSub*100)}%"></span></span><span class="rb-n">${s.count}</span></a>`).join("");
  const maxH=Math.max(1,...(d.activity_by_hour||[0]));
  const hours=(d.activity_by_hour||[]).map((n,i)=>`<span class="rd-hbar" title="${i}:00 UTC — ${n} actions"><span style="height:${Math.round(n/maxH*100)}%"></span></span>`).join("");
  const trophies=(d.trophies||[]).length?`<div class="rd-sec"><div class="plabel">Trophies</div><div class="rd-chips">${d.trophies.map(t=>`<span class="rd-chip">${esc(t)}</span>`).join("")}</div></div>`:"";
  const posts=(d.recent_posts||[]).map(p=>`<a class="rd-item" href="${safeHref(p.url)}" target="_blank" rel="noopener noreferrer"><div class="ri-title">${esc(p.title||"(untitled)")}</div><div class="ri-meta">r/${esc(p.subreddit)} · ↑${num(p.score)} · ${num(p.num_comments)} comments · ${esc((p.created||"").slice(0,10))}${p.nsfw?' · <span class="rd-nsfw">NSFW</span>':""}</div></a>`).join("")||'<div class="rd-empty">no public posts.</div>';
  const cmts=(d.recent_comments||[]).map(c=>`<a class="rd-item" href="${safeHref(c.url)}" target="_blank" rel="noopener noreferrer"><div class="ri-body">${esc(c.body||"")}</div><div class="ri-meta">r/${esc(c.subreddit)} · ↑${num(c.score)} · ${esc((c.created||"").slice(0,10))}</div></a>`).join("")||'<div class="rd-empty">no public comments.</div>';

  const c=d.counts||{};
  const totals = c.posts_total!=null
    ? `${num(c.posts_total)} posts · ${num(c.comments_total)} comments archived`
    : `${num(c.posts_fetched)} posts · ${num(c.comments_fetched)} comments sampled`;
  const meta = [totals, d.last_active?`last active ${esc(d.last_active)}`:"", `via ${esc(d.source||"archives")}`].filter(Boolean).join(" · ");
  box.innerHTML=`
    <div class="panel rd-card">
      <div class="rd-head">
        <div class="rd-avatar rd-avatar-ph">r/</div>
        <div class="rd-id">
          <div class="rd-name">u/${esc(d.username)}</div>
          <div class="rd-sub2">${meta}</div>
          ${badges?`<div class="rd-badges">${badges}</div>`:""}
          ${d.bio?`<div class="rd-bio">${esc(d.bio)}</div>`:""}
          <a class="rd-link" href="${safeHref(d.url)}" target="_blank" rel="noopener noreferrer">${esc(d.url)} ↗</a>
        </div>
      </div>
    </div>
    <div class="rd-stats">
      ${stat("Total Karma",num(k.total))}
      ${stat("Post Karma",num(k.post))}
      ${stat("Comment Karma",num(k.comment))}
      ${stat("Cake Day",esc(d.created||"—"),d.age_days!=null?(d.age_days/365).toFixed(1)+" yrs on Reddit":"")}
    </div>
    ${d.karma_known?"":`<div class="rd-note">karma isn't in the archive for this account — figures shown are from indexed posts/comments only.</div>`}
    ${trophies}
    ${subs?`<div class="rd-sec"><div class="plabel">Top subreddits <span class="info">(from ${acts} sampled actions)</span></div><div class="rd-bars">${subs}</div></div>`:""}
    ${(d.activity_by_hour||[]).some(n=>n)?`<div class="rd-sec"><div class="plabel">Activity by hour <span class="info">(UTC)</span></div><div class="rd-hist">${hours}</div><div class="rd-hist-x"><span>00</span><span>06</span><span>12</span><span>18</span><span>23</span></div></div>`:""}
    <div class="rd-cols">
      <div class="rd-sec" style="margin-top:0"><div class="plabel">Recent posts</div><div class="rd-list">${posts}</div></div>
      <div class="rd-sec" style="margin-top:0"><div class="plabel">Recent comments</div><div class="rd-list">${cmts}</div></div>
    </div>`;
}
$("#rdGo").addEventListener("click",e=>runReddit($("#rdInput").value,e.currentTarget));
$("#rdInput").addEventListener("keydown",e=>{ if(e.key==="Enter") runReddit($("#rdInput").value,e.currentTarget); });
// ---------- Company Footprint ----------
export async function runFootprint(q,btn=$("#fpGo")){
  q=(q||"").trim(); if(!q) return;
  const el=$("#fpResult"), done=setButtonBusy(btn);
  el.innerHTML='<div class="rd-empty">mapping footprint — subdomains, services, job posts… (can take ~20s)</div>';
  try{
    renderFootprint(await requestJson("footprint",API+"/api/footprint?target="+encodeURIComponent(q)));
  }catch(e){
    if(isAbort(e)) return;
    el.innerHTML='<div class="rd-empty">footprint failed: '+esc(e.message)+'</div>';
  }finally{ done(); }
}
function renderFootprint(d){
  const el=$("#fpResult"), parts=[];
  if(d.ok===false){
    const notes=(d.errors||[]).map(e=>`<li>${esc(e)}</li>`).join("");
    el.innerHTML='<div class="pulse-empty err">Footprint incomplete — no usable source data.</div>'+
      (notes?`<ul class="sig-list">${notes}</ul>`:"")+
      '<div style="margin-top:10px"><button id="fpRetry" class="vh-btn">retry</button></div>';
    const rb=$("#fpRetry"); if(rb) rb.addEventListener("click",e=>runFootprint(d.target||$("#fpInput").value,e.currentTarget));
    return;
  }
  const sub=(d.subdomains||[]).length, svc=(d.services||[]).length, jc=d.jobs?d.jobs.count:0;
  parts.push(`<div class="fp-summary"><span class="fp-stat"><b>${esc(d.domain||d.target)}</b></span><span class="fp-stat">${sub} subdomains</span><span class="fp-stat">${svc} hosts mapped</span><span class="fp-stat">${jc} job posts</span></div>`);
  if((d.errors||[]).length){
    parts.push(`<div class="pulse-empty err" style="margin-bottom:10px">Source / coverage notes — results may be partial:</div><ul class="sig-list">${d.errors.map(e=>`<li>${esc(e)}</li>`).join("")}</ul>`);
  }
  if(d.risk){
    const r=d.risk, c=r.counts||{};
    const chips=`<span class="risk-chip rk-high">${c.high||0} high</span><span class="risk-chip rk-med">${c.medium||0} med</span><span class="risk-chip rk-low">${c.low||0} low</span>`;
    const rows=(r.findings||[]).map(f=>`<div class="risk-row rk-${esc(f.level)}"><span class="rk-dot"></span><span class="rk-svc">${esc(f.service)}${f.port?':'+f.port:''}</span><span class="rk-host">${esc(f.host||f.ip||'')}</span><span class="rk-why">${esc(f.why)}</span></div>`).join("");
    parts.push(`<div class="verdict verdict-${esc(r.posture)}"><div class="vd-head"><span class="vd-tag">ATTACK SURFACE</span><span class="vd-text">${esc(r.headline)}</span></div><div class="risk-chips">${chips}</div>${rows?`<div class="risk-list">${rows}</div>`:`<div class="info" style="margin-top:6px">${r.posture==="incomplete"?"Checks incomplete — exposure can't be judged from what was collected (see notes above).":"No notable ports or CVEs on the hosts that were actually scanned."}</div>`}</div>`);
  }
  if(d.dns&&Object.keys(d.dns).length){
    const rows=Object.entries(d.dns).map(([k,v])=>`<div class="ld-kv"><span class="kv">${esc(k)}</span><span class="val">${esc(Array.isArray(v)?v.join(", "):String(v))}</span></div>`).join("");
    parts.push(panelSec("DNS",rows));
  }
  if(d.tech&&d.tech.title) parts.push(panelSec("Tech / server",`<div class="val">${esc(d.tech.title)}</div>`));
  if(svc){
    const rows=d.services.map(s=>{
      const g=s.geo||{}, loc=[g.city,g.country].filter(Boolean).join(", ");
      const ports=(s.ports||[]).join(", ")||"—";
      const cve=(s.vulns||[]).length?`<span class="fp-cve">${s.vulns.length} CVE</span>`:"";
      return `<div class="fp-svc"><div class="fp-svc-ip">${esc(s.ip)}${cve}</div><div class="info">${esc((s.hosts||[]).slice(0,2).join(", "))}</div><div class="info">ports: ${esc(ports)}</div><div class="info">${esc(loc)} ${esc(g.org||"")}</div></div>`;
    }).join("");
    parts.push(panelSec("Exposed services",`<div class="fp-svc-grid">${rows}</div>`));
  }
  if(sub) parts.push(panelSec(`Subdomains (${sub})`,`<div class="fp-subs">${d.subdomains.slice(0,120).map(s=>`<span>${esc(s)}</span>`).join("")}</div>`));
  if(d.jobs){
    const j=d.jobs;
    const offices=(j.locations||[]).slice(0,24).map(l=>`<span class="fp-chip">${esc(l)}</span>`).join("")||'<span class="info">—</span>';
    const posts=(j.postings||[]).slice(0,25).map(p=>`<div class="ld-kv"><a class="match" href="${safeHref(p.url||'#')}" target="_blank" rel="noopener noreferrer">${esc(p.title||'?')}</a><span class="info">${esc(p.location||'')}</span></div>`).join("");
    parts.push(panelSec(`Public job posts — ${j.count} via ${esc(j.source)}`,`<div class="plabel" style="margin:0 0 6px">Office locations</div><div class="fp-chips">${offices}</div><div class="plabel" style="margin:13px 0 6px">Recent openings</div>${posts}`));
  }
  if(d.note) parts.push(`<div class="rd-empty">${esc(d.note)}</div>`);
  el.innerHTML=parts.join("")||'<div class="rd-empty">no footprint data.</div>';
}
$("#fpGo").addEventListener("click",e=>runFootprint($("#fpInput").value,e.currentTarget));
$("#fpInput").addEventListener("keydown",e=>{ if(e.key==="Enter") runFootprint($("#fpInput").value,e.currentTarget); });
// ---------- Image Intelligence ----------
export function initImage(){ $("#imgUrl").focus(); }
export async function runImage(btn=$("#imgGo")){
  const url=$("#imgUrl").value.trim(), el=$("#imgResult"), done=setButtonBusy(btn);
  if(!url && !window.__imgData){ el.innerHTML='<div class="rd-empty">paste an image URL or upload a file.</div>'; return; }
  el.innerHTML='<div class="rd-empty">reading image…</div>';
  try{
    const body = window.__imgData ? {data:window.__imgData} : {url};
    const r=await requestJson("image",API+"/api/image",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
    renderImage(r, url);
  }catch(e){
    if(isAbort(e)) return;
    el.innerHTML='<div class="rd-empty">failed: '+esc(e.message)+'</div>';
  }finally{ done(); }
}
function renderImage(d,url){
  const el=$("#imgResult");
  if(!d.ok){ el.innerHTML='<div class="rd-empty">'+esc(d.error||'could not read image')+'</div>'; return; }
  const parts=[`<div class="fp-summary"><span class="fp-stat"><b>${esc(d.format||'?')}</b></span><span class="fp-stat">${d.width}×${d.height}</span><span class="fp-stat">${((d.bytes||0)/1024|0)} KB</span></div>`];
  if(d.resolved_image) parts.push(`<div class="info" style="margin:2px 0 4px">↳ analysed the page's main image: <a class="match" href="${safeHref(d.resolved_image)}" target="_blank" rel="noopener noreferrer">${esc(d.resolved_image).slice(0,90)}…</a></div>`);
  if(d.assessment){
    const a=d.assessment;
    const sigs=(a.signals||[]).map(s=>`<li class="sig-${esc(s.level)}">${esc(s.text)}</li>`).join("");
    const steps=(a.next_steps||[]).map(s=>`<li>${esc(s)}</li>`).join("");
    parts.push(`<div class="verdict verdict-${esc(a.confidence)}"><div class="vd-head"><span class="vd-tag">VERDICT</span><span class="vd-text">${esc(a.verdict)}</span><span class="vd-conf">${esc(a.confidence)}</span></div>${sigs?`<ul class="sig-list">${sigs}</ul>`:""}${steps?`<div class="vd-steps-h">Next steps</div><ol class="vd-steps">${steps}</ol>`:""}</div>`);
  }
  const ex=d.exif||{};
  parts.push(panelSec("Metadata (EXIF)", Object.keys(ex).length
    ? Object.entries(ex).map(([k,v])=>`<div class="ld-kv"><span class="kv">${esc(k)}</span><span class="val">${esc(v)}</span></div>`).join("")
    : '<div class="info">No EXIF present — it may have been stripped on upload, or never embedded. Absence alone proves nothing.</div>'));
  if(d.gps){
    const g=d.gps;
    if(g.exact===false){
      // Unsigned EXIF magnitudes are not a location. Never generate map links
      // from them — guessing N/E would silently put the pin in the wrong place.
      const mags=[g.lat_magnitude,g.lon_magnitude].filter(v=>v!=null).join(", ")||"—";
      const refs=[g.lat_ref?`latitude ${g.lat_ref}`:"latitude ref missing",
                  g.lon_ref?`longitude ${g.lon_ref}`:"longitude ref missing"].join(" · ");
      parts.push(panelSec("⚠ Incomplete GPS in image",`<div class="val">unsigned magnitudes: ${esc(mags)}</div><div class="info" style="margin-top:5px">${esc(refs)}</div><div class="info" style="margin-top:6px">${esc(g.note||"Hemisphere references are missing; no map or place lookup was attempted.")}</div>`));
    }else{
      const maps=g.maps||{};
      const btns=Object.entries(maps).map(([k,v])=>`<a class="launch-btn" href="${safeHref(v)}" target="_blank" rel="noopener noreferrer">${esc(k)} ↗</a>`).join("")
        ||`<a class="launch-btn" href="${safeHref(`https://www.google.com/maps?q=${g.lat},${g.lon}`)}" target="_blank" rel="noopener noreferrer">Google Maps ↗</a>`;
      const place=g.place?`<div class="val" style="margin-top:5px;color:var(--primary)">${esc(g.place)}</div>`:"";
      parts.push(panelSec("📍 GPS embedded in image",`<div class="val">${esc(g.lat)}, ${esc(g.lon)}</div>${place}<div class="img-launchers" style="margin-top:7px">${btns}</div><div class="info" style="margin-top:6px">Open Street View and confirm the place actually matches the photo.</div>`));
    }
  }
  const rs=d.reverse_search||{};
  parts.push(panelSec("Reverse image search", Object.keys(rs).length
    ? `<div class="img-launchers">`+Object.entries(rs).map(([k,v])=>`<a class="launch-btn" href="${safeHref(v)}" target="_blank" rel="noopener noreferrer">${esc(k)} ↗</a>`).join("")+`</div><div class="info" style="margin-top:6px">TinEye sorts oldest-first → the earliest known upload of a viral image.</div>`
    : '<div class="info">Paste a public image <b>URL</b> (not an upload) to get one-click reverse-search launchers.</div>'));
  el.innerHTML=parts.join("");
}
$("#imgGo").addEventListener("click",e=>{ window.__imgData=null; runImage(e.currentTarget); });
$("#imgUrl").addEventListener("keydown",e=>{ if(e.key==="Enter"){ window.__imgData=null; runImage(); } });
$("#imgFile").addEventListener("change",function(){
  const f=this.files&&this.files[0]; if(!f) return;
  const rd=new FileReader();
  rd.onload=()=>{ window.__imgData=rd.result; $("#imgUrl").value=""; runImage(); };
  rd.readAsDataURL(f);
});
