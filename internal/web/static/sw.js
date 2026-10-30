// Heimdall's service worker (served as /sw.js, pwa.go). It makes the hub
// installable as an app and shows a small offline page when the hub can't
// be reached. It caches only static files: CSS, scripts and icons, whose
// URLs carry a version. Pages and API answers are never cached; they're
// behind a sign-in and always come from the hub.
"use strict";

var VERSION = "__VERSION__"; // the hub's and the branding's (pwa.go)
var CACHE = "heimdall-static-" + VERSION;
var OFFLINE = "/offline";
// The offline page and everything it loads, at the URLs it uses (pwa.go).
var PRECACHE = ["__PRECACHE__"];

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
