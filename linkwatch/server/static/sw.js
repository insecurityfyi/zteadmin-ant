// VisCon1 service worker (served at /sw.js so it covers the whole site).
// Pages always come from the network, because monitoring data must be live; when the network is down
// the app shows an offline page instead of the browser's error. Versioned static files are cached.
// It also shows alert notifications pushed by the server and opens the right page when one is tapped.
"use strict";
const VERSION = "__VERSION__";
const CACHE = "viscon1-" + VERSION;
const OFFLINE = "/offline";
const PRECACHE = [OFFLINE, "/static/app.css?v=" + VERSION, "/static/pwa.js?v=" + VERSION, "/static/brand/icon-dark-192.png?v=" + VERSION];

self.addEventListener("install", event => {
  event.waitUntil(caches.open(CACHE).then(c => c.addAll(PRECACHE)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", event => {
  event.waitUntil((async () => {
    for (const key of await caches.keys()) if (key.startsWith("viscon1-") && key !== CACHE) await caches.delete(key);
    await self.clients.claim();
  })());
});

self.addEventListener("fetch", event => {
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  if (req.mode === "navigate") {
    event.respondWith(fetch(req).catch(async () => (await caches.match(OFFLINE)) || Response.error()));
    return;
  }
  // static files carry ?v=<version>, so a cached copy is always the right one
  if (url.pathname.startsWith("/static/")) {
    event.respondWith((async () => {
      const cache = await caches.open(CACHE);
      const hit = await cache.match(req);
      if (hit) return hit;
      const resp = await fetch(req);
      if (resp.ok && url.searchParams.has("v")) cache.put(req, resp.clone());
      return resp;
    })());
  }
});

self.addEventListener("push", event => {
  let m = {};
  try { m = event.data ? event.data.json() : {}; } catch (e) { m = { title: "VisCon1", body: event.data && event.data.text() }; }
  const options = {
    body: m.body || "", tag: m.tag || undefined, renotify: !!(m.tag && m.renotify),
    requireInteraction: !!m.requireInteraction, icon: "/static/brand/icon-dark-192.png",
    badge: "/static/brand/badge-96.png", timestamp: Date.now(), data: { url: m.url || "/alerts?state=open" }
  };
  event.waitUntil(self.registration.showNotification(m.title || "VisCon1", options));
});

self.addEventListener("notificationclick", event => {
  event.notification.close();
  const target = new URL(event.notification.data && event.notification.data.url || "/", self.location.origin).href;
  event.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const w of wins) {
      if (new URL(w.url).origin === self.location.origin && "focus" in w) {
        await w.focus();
        if ("navigate" in w) return w.navigate(target);
        return;
      }
    }
    return self.clients.openWindow(target);
  })());
});

// the browser replaced this device's subscription (keys rotated or expired): tell the server the new one
self.addEventListener("pushsubscriptionchange", event => {
  const old = event.oldSubscription;
  event.waitUntil((async () => {
    const sub = event.newSubscription || (old && await self.registration.pushManager.subscribe(old.options));
    if (!sub) return;
    await fetch("/account/push/subscribe", {
      method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...sub.toJSON(), old_endpoint: old ? old.endpoint : "" })
    });
  })());
});
