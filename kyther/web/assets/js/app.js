// Entry point: wire view hooks, navigation and the initial dashboard load.
(function(K){
"use strict";
const {$, cmdIn, registerViewHooks, setRefreshLogs, showView,
       banner, renderStats, renderLog, loadNews, renderAttacks, loadThreats,
       initPulse, renderLogsFull, initImage} = K;

// Entry point: wire view hooks, navigation and the initial dashboard load.
setRefreshLogs(renderLogsFull);
registerViewHooks({
  logs: renderLogsFull,
  attacks: renderAttacks,
  threats: ()=>{ loadThreats(); },
  pulse: initPulse,
  footprint: ()=>{ $("#fpInput").focus(); },
  imageintel: initImage,
});

document.querySelector(".side-nav").addEventListener("click",e=>{
  const b=e.target.closest(".nav-item");
  if(b) showView(b.dataset.view);
});

banner(); renderStats(); renderLog(); loadNews(); cmdIn.focus();

// PWA: register the service worker (silently no-ops over plain HTTP / unsupported)
if("serviceWorker" in navigator){
  window.addEventListener("load",()=>navigator.serviceWorker.register("/sw.js").catch(()=>{}));
}

})(window.Kyther = window.Kyther || {});
