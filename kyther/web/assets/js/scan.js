// Home view: scanning, self-audit, result rendering and PDF reports.
(function(K){
"use strict";
const {API, $, cmdIn, state, store, TYPES, esc, safeHref, put, addLog,
       renderStats, requestJson, requestBlob, setButtonBusy, isAbort} = K;

// Home view: scanning, self-audit, result rendering and PDF reports.
async function runSearch(type,value){
  if(state.busy) return; value=(value||"").trim(); if(!value) return;
  state.busy=true; $("#qgo").disabled=true; cmdIn.disabled=true;
  put(`<span class="cmd"><span class="match">&gt;</span> search --${esc(type)} ${esc(value)}</span>`);
  const hint=(type==="email"||type==="username")?" — account sweeps can take ~1 min":"";
  const running=put(`<span class="info">running scan${hint}<span class="blink">_</span></span>`);
  const t0=performance.now();
  try{
    const d=await requestJson("scan",API+"/api/scan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target:value,type,depth:1})});
    const secs=((performance.now()-t0)/1000).toFixed(1);
    running.remove();
    renderResult(d,secs);
    updateFromResult(d,type,value);
    state.LAST_SEARCH={type,value};                 // remember what to report on
    $("#reportBtn").disabled=false;
    $("#reportStatus").className="report-status"; $("#reportStatus").textContent="";
  }catch(e){
    running.remove();
    if(isAbort(e)) return;                         // superseded by a newer scan
    put(`<span class="err">[x] scan failed: ${esc(e.message)}</span>`);
    addLog(type,value,"error");
    state.stats.scanned++; store.set("kyther_stats",state.stats); renderStats();
  }finally{
    state.busy=false; $("#qgo").disabled=false; cmdIn.disabled=false; cmdIn.focus();
    put("&nbsp;");
  }
}

async function runAudit(){
  if(state.busy) return;
  state.busy=true; $("#qgo").disabled=true; $("#auditGo").disabled=true; cmdIn.disabled=true;
  put(`<span class="cmd"><span class="match">&gt;</span> audit --self</span>`);
  const running=put(`<span class="info">scanning source + dependencies<span class="blink">_</span></span>`);
  const t0=performance.now();
  try{
    const d=await requestJson("audit",API+"/api/audit",{method:"POST"});
    const secs=((performance.now()-t0)/1000).toFixed(1);
    running.remove();
    renderAudit(d,secs);
    const b=d.bandit||{}, dp=d.deps||{};
    const res=`${b.high||0}H ${b.medium||0}M ${b.low||0}L · ${dp.vuln_count||0} CVEs`;
    addLog("audit","self · kyther",res,{__audit:true,...d});
  }catch(e){
    running.remove();
    if(isAbort(e)) return;
    put(`<span class="err">[x] audit failed: ${esc(e.message)}</span>`);
  }finally{
    state.busy=false; $("#qgo").disabled=false; $("#auditGo").disabled=false; cmdIn.disabled=false; cmdIn.focus();
    put("&nbsp;");
  }
}
function renderAudit(d,secs){
  const b=d.bandit||{}, dp=d.deps||{}, YEL="#c2a24f";
  put(`<span class="ok">[ok]</span> <span class="info">security audit complete [${secs}s]</span>`);
  // --- source (bandit) ---
  if(b.available===false){ put(`<span class="info">    code: bandit not installed — pip install bandit</span>`); }
  else if(b.error){ put(`<span class="err">    code (bandit): ${esc(b.error)}</span>`); }
  else{
    const H=b.high||0,M=b.medium||0,L=b.low||0;
    put(`<span class="plus">[+]</span> <span class="kv">code (bandit):</span> <span class="${H?'err':'ok'}">${H} high</span> <span class="kv">·</span> <span style="color:${YEL}">${M} medium</span> <span class="kv">·</span> <span class="info">${L} low</span> <span class="info">(${b.loc} LOC)</span>`);
    (b.findings||[]).filter(f=>f.sev!=="LOW").slice(0,6).forEach(f=>{
      const hi=f.sev==="HIGH"; const cs=hi?'class="err"':`style="color:${YEL}"`;
      put(`    <span ${cs}>${esc(f.id)} ${esc(f.sev)}</span> <span class="val">${esc(f.file)}:${esc(f.line)}</span> <span class="info">${esc(f.text)}</span>`);
    });
  }
  // --- dependencies (pip-audit) ---
  if(dp.available===false){ put(`<span class="info">    deps: pip-audit not installed — pip install pip-audit</span>`); }
  else if(dp.error){ put(`<span class="err">    deps (pip-audit): ${esc(dp.error)}</span>`); }
  else{
    const V=dp.vuln_count||0;
    put(`<span class="plus">[+]</span> <span class="kv">dependencies (pip-audit):</span> <span class="${V?'err':'ok'}">${V} CVEs</span> <span class="info">across ${dp.pkg_count||0} packages</span>`);
    (dp.packages||[]).slice(0,6).forEach(p=>{
      put(`    <span class="val">${esc(p.name)} ${esc(p.version)}</span> <span class="info">${p.count} ${p.count===1?'advisory':'advisories'}${p.fix?' → '+esc(p.fix):''}</span>`);
    });
  }
  const clean=(b.high||0)===0 && (b.medium||0)===0 && (dp.vuln_count||0)===0 && !b.error && !dp.error;
  if(clean) put(`<span class="ok">    ✓ no open issues — clean audit.</span>`);
}

const CONF_RANK={possible:0,probable:1,confirmed:2};
function dedupe(profiles){
  // Merge duplicate sites by host, keeping the BEST confidence — so a WhatsMyName
  // CONFIRMED isn't shadowed by a Sherlock POSSIBLE for the same site, whatever order.
  const by=new Map();
  for(const p of profiles){
    let h; try{h=new URL(p.url).hostname.replace(/^www\./,"")}catch{h=p.url}
    const prev=by.get(h);
    if(!prev){ by.set(h,{...p}); }
    else if((CONF_RANK[p.confidence]??-1)>(CONF_RANK[prev.confidence]??-1)){ prev.confidence=p.confidence; }
  }
  return [...by.values()];
}

function renderResult(d,secs){
  const seed=d.seed;
  const cat=c=>d.findings.filter(f=>f.category===c);
  const accounts=dedupe(cat("accounts").flatMap(f=>f.data.profiles||[]));
  // XposedOrNot returns `breaches`; LeakCheck returns `sources`. Both are named
  // breach lists, so count and display either shape.
  const dos=d.dossier||{};
  const breaches=cat("breaches").reduce((n,f)=>n+((f.data.breaches||f.data.sources||[]).length),0);

  put(`<span class="ok">[ok]</span> <span class="info">scan complete —</span> <span class="val">${esc(seed.value)}</span> <span class="info">(${esc(seed.type)}) [${secs}s]</span>`);

  // Identity scans now report what was actually queried, so an empty result is
  // never mistaken for "nothing was checked" (the same ledger as Footprint).
  const checks=d.source_checks||{}, checkKeys=Object.keys(checks);
  if(checkKeys.length){
    put(`<span class="plabel">SOURCE CHECKS — what was actually checked</span>`);
    put(`<span class="info">“not found” = queried, no public match; “manual” = needs a key or a separate lookup.</span>`);
    const CS={found:"st-good",unavailable:"st-bad",manual:"st-manual","not_found":"st-muted",not_run:"st-muted"};
    for(const [name,c] of Object.entries(checks)){
      put(`<div class="fp-check"><span class="fp-check-name">${esc(name)}</span><span class="fp-status ${CS[c.status]||"st-muted"}">${esc(String(c.status||"").replace("_"," "))}</span><span class="fp-check-detail">${esc(c.detail||"")}</span></div>`);
    }
  }

  const risk=dos.risk;
  if(risk){
    const RC={Critical:"#f87171",High:"#f87171",Medium:"#c2a24f",Low:"#5fd88f"};
    const col=RC[risk.tier]||"#9d8fb0";
    put(`<span style="color:${col}">[risk] ${risk.score}/100 · ${esc(risk.tier)}</span>`);
    (risk.factors||[]).forEach(f=>put(`    <span class="kv">→ ${esc(f.label)}</span> <span class="info">+${f.points}</span>`));
  }

  if(dos.primary_name){
    const bits=[dos.primary_name, ...(dos.locations||[]).slice(0,1), ...(dos.companies||[]).slice(0,1)];
    put(`<span class="plus">[+]</span> <span class="kv">identity:</span> <span class="val">${esc(bits.filter(Boolean).join(" · "))}</span>`);
  }
  (dos.emails||[]).slice(0,4).forEach(e=>
    put(`<span class="plus">[+]</span> <span class="kv">email:</span> <span class="val">${esc(e.email)}</span>${e.noreply?' <span class="info">(noreply)</span>':""}`));

  // Profile-enrichment fields the dossier already returns but the terminal
  // used to drop: alternate names, bios, avatars, off-site links, Keybase-style
  // proof accounts and the platforms that were actually checked.
  const enrich=[];
  if((dos.names||[]).length>1) enrich.push(`<span class="kv">also known as:</span> <span class="val">${esc(dos.names.slice(0,8).join(" · "))}</span>`);
  if((dos.enriched_platforms||[]).length) enrich.push(`<span class="kv">profiles checked:</span> <span class="info">${esc(dos.enriched_platforms.join(", "))}</span>`);
  (dos.bios||[]).slice(0,3).forEach(b=>enrich.push(`<span class="kv">bio (${esc(b.platform)}):</span> <span class="info">${esc(String(b.text||"").slice(0,180))}</span>`));
  (dos.avatars||[]).slice(0,6).forEach(a=>{ const href=safeHref(a.url); if(href!=="#") enrich.push(`<a href="${href}" target="_blank" rel="noopener noreferrer" title="${esc(a.platform)} avatar"><img src="${href}" alt="" style="width:18px;height:18px;border-radius:50%;vertical-align:middle;object-fit:cover;border:1px solid var(--border)"></a>`); });
  (dos.links||[]).slice(0,8).forEach(l=>enrich.push(`<a class="match" href="${safeHref(l)}" target="_blank" rel="noopener noreferrer">${esc(l)}</a>`));
  (dos.linked_accounts||[]).slice(0,8).forEach(a=>enrich.push(a.url?`<a class="match" href="${safeHref(a.url)}" target="_blank" rel="noopener noreferrer">${esc(a.service||a.platform||"proof")}: ${esc(a.handle||"")}</a>`:`<span class="info">${esc(a.service||a.platform||"proof")}: ${esc(a.handle||"")}</span>`));
  if(enrich.length) put(`<span class="plus">[+]</span> <span class="kv">enrichment:</span> ${enrich.join(" · ")}`);

  if(accounts.length){
    const conf=accounts.filter(p=>(p.confidence||"possible")==="confirmed");
    const unv=accounts.filter(p=>(p.confidence||"possible")!=="confirmed");
    put(`<span class="plus">[+]</span> <span class="kv">${accounts.length} accounts — </span><span class="ok">${conf.length} verified</span><span class="kv"> · </span><span class="info">${unv.length} unverified</span>`);
    // Verified (control-checked): show ALL, grouped, as clickable profile links.
    if(conf.length){
      const g={}; conf.forEach(p=>{const k=(p.category||"other").replace(/xx/gi,"").trim()||"other"; (g[k]=g[k]||[]).push(p);});
      Object.entries(g).sort((a,b)=>b[1].length-a[1].length).forEach(([c,ps])=>{
        const names=ps.map(p=>`<a class="match" href="${safeHref(p.url)}" target="_blank" rel="noopener noreferrer">${esc(p.platform)}</a>`).join(" ");
        put(`    <span class="kv">${esc(c)}:</span> ${names}`);
      });
    }
    // Unverified (status-code guesses — many 404): dimmed, collapsed, expandable.
    if(unv.length){
      const id="unv_"+Math.random().toString(36).slice(2,9);
      put(`    <span class="info">unverified (status-code guesses — some don't exist): </span><a class="expander" data-t="${id}" data-n="${unv.length}">show ${unv.length} ▸</a>`);
      const links=unv.map(p=>`<a href="${safeHref(p.url)}" target="_blank" rel="noopener noreferrer" class="unv-link">${esc(p.platform)}</a>`).join(" ");
      put(`<span id="${id}" style="display:none">      ${links}</span>`);
    }
  }
  cat("infrastructure").slice(0,4).forEach(f=>put(`<span class="plus">[+]</span> <span class="kv">${esc(f.analyzer)}:</span> <span class="val">${esc(f.title)}</span>`));
  const tl=(d.timeline||[]).length; if(tl) put(`<span class="plus">[+]</span> <span class="kv">timeline:</span> <span class="val">${tl} dated events</span>`);
  put(`<span class="${breaches?'err':'info'}">[${breaches?'!':'i'}] breaches: ${breaches}</span>`);
  cat("breaches").slice(0,3).forEach(f=>{
    const src=f.data.source||f.analyzer;
    const names=(f.data.breaches||f.data.sources||[]).map(b=>typeof b==="string"?b:(b.name||"")).filter(Boolean);
    const shown=names.slice(0,10).join(", ");
    const more=names.length>10?` (+${names.length-10} more)`:"";
    // LeakCheck's terms ask for attribution when its public API is used.
    const attr=src==="LeakCheck"?` · <a class="match" href="https://leakcheck.io" target="_blank" rel="noopener noreferrer">Powered by LeakCheck</a>`:"";
    if(shown) put(`    <span class="kv">${esc(src)}:</span> <span class="info">${esc(shown)}${esc(more)}</span>${attr}`);
  });
  if(!d.findings.length && !accounts.length && !dos.primary_name && !(dos.emails||[]).length && !cat("infrastructure").length)
    put(`<span class="info">    ${checkKeys.length?"no public data matched — see Source checks above for what was queried.":"no results — try a different value or type."}</span>`);
}

function updateFromResult(d,type,value){
  const n=dedupe(d.findings.filter(f=>f.category==="accounts").flatMap(f=>f.data.profiles||[])).length;
  const breaches=d.findings.filter(f=>f.category==="breaches").reduce((a,f)=>a+((f.data.breaches||f.data.sources||[]).length),0);
  const hit=n>0||!!(d.dossier&&d.dossier.primary_name)||d.findings.length>0;
  state.stats.scanned++; if(hit)state.stats.hits++; state.stats.found+=n;
  state.stats.risk = (d.dossier && d.dossier.risk) || state.stats.risk || null;
  store.set("kyther_stats",state.stats); renderStats();
  addLog(type,value,hit?`${n} accounts`:"no hits",d);
}

function handleCommand(raw){
  const s=raw.trim(); if(!s) return;
  if(s==="clear"){ term.innerHTML=""; banner(); return; }
  if(s==="help"){
    put('<span class="ok">commands:</span>');
    put('  <span class="val">search --&lt;type&gt; &lt;value&gt;</span>  <span class="info">type = username|email|domain|ip|phone|person|company</span>');
    put('  <span class="val">audit</span>  <span class="info">run a security self-audit (source + dependencies)</span>');
    put('  <span class="val">clear</span>  <span class="info">clear the terminal</span>');
    put('<span class="info">or just type a value and pick a type in Quick Search.</span>'); put("&nbsp;");
    return;
  }
  let m=s.match(/^search\s+--(\w+)\s+(.+)$/);
  if(m && TYPES.includes(m[1])){ runSearch(m[1],m[2]); return; }
  if(s==="audit"||s==="audit --self"){ runAudit(); return; }
  m=s.match(/^(sherlock|holehe)\s+(.+)$/);
  if(m){ runSearch(m[1]==="holehe"?"email":"username",m[2]); return; }
  if(!s.startsWith("search")){ runSearch(state.TYPE,s); return; }
  put(`<span class="err">[x] unknown command.</span> <span class="info">try: search --username &lt;value&gt;  (or \`help\`)</span>`); put("&nbsp;");
}
cmdIn.addEventListener("keydown",e=>{ if(e.key==="Enter"){ const v=cmdIn.value; cmdIn.value=""; handleCommand(v); } });

$("#qsBtns").addEventListener("click",e=>{ const b=e.target.closest(".qs-btn"); if(!b)return;
  document.querySelectorAll(".qs-btn").forEach(x=>x.classList.remove("on")); b.classList.add("on"); state.TYPE=b.dataset.type; $("#qval").focus(); });
$("#qgo").addEventListener("click",()=>{ const v=$("#qval").value; $("#qval").value=""; runSearch(state.TYPE,v); });
$("#auditGo").addEventListener("click",()=>runAudit());
$("#qval").addEventListener("keydown",e=>{ if(e.key==="Enter"){ const v=$("#qval").value; $("#qval").value=""; runSearch(state.TYPE,v); } });
$("#logClear").addEventListener("click",()=>{ state.log=[]; store.set("kyther_log",state.log); renderLog(); });
// ---- Generate Report: re-scans the last target and downloads a PDF ----
async function generateReport(btn=$("#reportBtn")){
  if(!state.LAST_SEARCH) return;
  const st=$("#reportStatus"), done=setButtonBusy(btn);
  st.className="report-status busy";
  st.textContent="Generating report… (runs a fresh scan, ~30–60s)";
  try{
    const blob=await requestBlob("report",API+"/api/report",{method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({target:state.LAST_SEARCH.value,type:state.LAST_SEARCH.type,depth:1})});
    const url=URL.createObjectURL(blob), a=document.createElement("a");
    a.href=url; a.download=`kyther-${state.LAST_SEARCH.type}-report.pdf`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(()=>URL.revokeObjectURL(url), 5000);
    st.className="report-status ok"; st.textContent=`✓ Downloaded kyther-${state.LAST_SEARCH.type}-report.pdf`;
  }catch(e){
    if(isAbort(e)) return;
    st.className="report-status err"; st.textContent="✗ Report failed: "+e.message;
  }finally{ done(); }
}
$("#reportBtn").addEventListener("click", generateReport);
function setType(t){ if(!TYPES.includes(t)) return; state.TYPE=t; document.querySelectorAll(".qs-btn").forEach(x=>x.classList.toggle("on",x.dataset.type===t)); }

Object.assign(K, {runSearch, runAudit, dedupe, renderResult,
  updateFromResult, generateReport, setType});
})(window.Kyther = window.Kyther || {});
