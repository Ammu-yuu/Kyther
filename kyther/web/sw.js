/* Kyther service worker — network-first so content is always fresh, with an
   offline fallback to the cached app shell. Only registers over HTTPS or
   localhost (e.g. a Tailscale *.ts.net URL); a no-op over plain HTTP. */
const CACHE = "kyther-shell-v7";
const SHELL = ["/manifest.webmanifest",
               "/assets/base.css", "/assets/views.css",
               "/assets/js/app.js", "/assets/js/core.js", "/assets/js/scan.js",
               "/assets/js/feeds.js", "/assets/js/views.js",
               "/icons/icon-192.png", "/icons/icon-512.png"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET") return;                 // never cache API POSTs
  const url = new URL(req.url);
  if (url.pathname.startsWith("/api/")) return;     // API always live
  // Never serve the HTML shell from Cache Storage: a stale document is exactly
  // what breaks a redeploy (old <script> tags, missing new assets).
  if (req.mode === "navigate") {
    e.respondWith(fetch(req, {cache: "reload"}));
    return;
  }
  e.respondWith(
    // Bypass the browser HTTP cache too: an old asset can otherwise survive a
    // redeploy even when this service worker is network-first.
    fetch(req, {cache: "reload"})
      .then((res) => {
        if (res && res.ok && res.type === "basic") {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(req, copy));
        }
        return res;
      })
      .catch(() => caches.match(req).then((m) => m || caches.match("/")))
  );
});
