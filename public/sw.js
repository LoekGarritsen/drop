// Service worker: makes the PWA installable and turns OS share-sheet POSTs
// into a client-side handoff. Nothing is cached except the app shell.
const SHELL = ["/", "/style.css", "/app.js", "/crypto.js", "/icon.svg", "/manifest.webmanifest"];
self.addEventListener("install", (e) => {
  e.waitUntil(caches.open("drop-shell-v1").then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (e.request.method === "POST" && url.pathname === "/share") {
    e.respondWith((async () => {
      const form = await e.request.formData();
      const cache = await caches.open("drop-share");
      const files = form.getAll("files");
      const payload = { title: form.get("title") || "", text: form.get("text") || "", url: form.get("url") || "",
        files: files.map((f) => ({ name: f.name, type: f.type })) };
      await cache.put("/share-payload", new Response(JSON.stringify(payload)));
      await Promise.all(files.map((f, i) => cache.put(`/share-file-${i}`, new Response(f))));
      return Response.redirect("/?shared=1", 303);
    })());
    return;
  }
  if (e.request.method !== "GET" || url.pathname.startsWith("/api/")) return;
  e.respondWith(fetch(e.request).catch(() => caches.match(e.request.url.endsWith("/") || url.pathname.startsWith("/i/") ? "/" : e.request)));
});
