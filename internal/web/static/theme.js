// Applies the viewer's saved theme before the page is drawn, so there is
// no flash of the other one. Loaded without defer, on purpose; it's tiny.
(function () {
  try {
    var t = localStorage.getItem("heimdall-theme");
    if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
  } catch (e) {}
})();
