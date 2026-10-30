// Heimdall's service worker (served as /sw.js, pwa.go). It makes the hub
// installable as an app and shows a small offline page when the hub can't
// be reached. It caches only static files: CSS, scripts and icons, whose
// URLs carry a version. Pages and API answers are never cached; they're
// behind a sign-in and always come from the hub. It also shows push
// notifications, and opens the hub when one is tapped.
"use strict";

var VERSION = "__VERSION__"; // the hub's and the branding's (pwa.go)
var CACHE = "heimdall-static-" + VERSION;
var OFFLINE = "/offline";
// The offline page and everything it loads, at the URLs it uses (pwa.go).
var PRECACHE = ["__PRECACHE__"];
// Notifications' icon (the hub's app icon) and status-bar badge (pwa.go).
var ICON = "__ICON__";
var BADGE = "__BADGE__";

self.addEventListener("install", function (event) {
  event.waitUntil(caches.open(CACHE).then(function (cache) {
    return cache.addAll(PRECACHE);
  }).then(function () { return self.skipWaiting(); }));
});

self.addEventListener("activate", function (event) {
  event.waitUntil(caches.keys().then(function (keys) {
    return Promise.all(keys.filter(function (k) {
      return k.indexOf("heimdall-static-") === 0 && k !== CACHE;
    }).map(function (k) { return caches.delete(k); }));
  }).then(function () { return self.clients.claim(); }));
});

// isStatic: a versioned file that's the same for everyone.
function isStatic(url) {
  return url.origin === self.location.origin &&
    (url.pathname.indexOf("/static/") === 0 || url.pathname.indexOf("/branding/") === 0);
}

self.addEventListener("fetch", function (event) {
  var req = event.request;
  if (req.method !== "GET") return;
  var url = new URL(req.url);
  if (req.mode === "navigate") {
    // Pages: always the network. Only when it fails, the offline page.
    event.respondWith(fetch(req).catch(function () {
      return caches.open(CACHE).then(function (cache) { return cache.match(OFFLINE); });
    }));
    return;
  }
  if (!isStatic(url)) return; // the browser's own handling, uncached
  // Static files: the cached copy, or fetch and keep it. Pages ask for
  // them with ?v=<version>, so a new version is a new URL.
  event.respondWith(caches.open(CACHE).then(function (cache) {
    return cache.match(req).then(function (hit) {
      return hit || fetch(req).then(function (res) {
        if (res.ok && res.type === "basic") cache.put(req, res.clone());
        return res;
      });
    });
  }));
});

// Push notifications (internal/push): the hub sends a small encrypted
// JSON message, {title, body, url, tag}, that the browser decrypts. A
// newer one with the same tag replaces the one showing. Nothing is kept
// or cached; the notification only opens a page of the hub.
self.addEventListener("push", function (event) {
  var m = {};
  try { m = event.data ? event.data.json() : {}; } catch (e) {}
  var opts = {
    body: typeof m.body === "string" ? m.body : "",
    tag: typeof m.tag === "string" && m.tag ? m.tag : "heimdall",
    renotify: true,
    icon: ICON,
    data: { url: sameSite(m.url) }
  };
  if (BADGE) opts.badge = BADGE;
  var title = typeof m.title === "string" && m.title ? m.title : "Heimdall needs attention";
  event.waitUntil(self.registration.showNotification(title, opts));
});

// sameSite keeps a notification's link on the hub: a path, never a URL
// elsewhere.
function sameSite(u) {
  if (typeof u !== "string" || u.charAt(0) !== "/" || u.charAt(1) === "/" || u.charAt(1) === "\\") return "/";
  return u;
}

// A tap opens the page: in a window of the app that's already open if
// there is one, else a new one.
self.addEventListener("notificationclick", function (event) {
  event.notification.close();
  var target = new URL(sameSite(event.notification.data && event.notification.data.url), self.location.origin).href;
  event.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then(function (wins) {
    for (var i = 0; i < wins.length; i++) {
      var w = wins[i];
      if (new URL(w.url).origin === self.location.origin && "focus" in w) {
        return w.focus().then(function (fw) { return (fw || w).navigate ? (fw || w).navigate(target) : null; });
      }
    }
    return self.clients.openWindow(target);
  }));
});
