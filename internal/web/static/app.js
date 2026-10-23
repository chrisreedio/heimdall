// Progressive enhancement only: copy buttons for upgrade commands.
// Buttons stay hidden unless the Clipboard API is available.
document.addEventListener("DOMContentLoaded", function () {
  if (!navigator.clipboard) return;
  document.querySelectorAll("button[data-copy]").forEach(function (btn) {
    var target = document.getElementById(btn.getAttribute("data-copy"));
    if (!target) return;
    btn.hidden = false;
    btn.addEventListener("click", function () {
      navigator.clipboard.writeText(target.textContent).then(function () {
        btn.textContent = "Copied";
        setTimeout(function () { btn.textContent = "Copy"; }, 1500);
      });
    });
  });
});

// Theme switcher: System -> Light -> Dark, remembered in this browser.
// theme.js applies the saved choice before the page is drawn.
document.addEventListener("DOMContentLoaded", function () {
  var btn = document.querySelector(".theme-toggle");
  if (!btn) return;
  var order = ["system", "light", "dark"];
  var mode = "system";
  try { mode = localStorage.getItem("heimdall-theme") || "system"; } catch (e) {}
  if (order.indexOf(mode) < 0) mode = "system";
  function show() {
    btn.setAttribute("data-mode", mode);
    var label = "Theme: " + mode + " (click for " + order[(order.indexOf(mode) + 1) % 3] + ")";
    btn.setAttribute("aria-label", label);
    btn.title = label;
  }
  show();
  btn.hidden = false;
  btn.addEventListener("click", function () {
    mode = order[(order.indexOf(mode) + 1) % 3];
    if (mode === "system") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", mode);
    try {
      if (mode === "system") localStorage.removeItem("heimdall-theme");
      else localStorage.setItem("heimdall-theme", mode);
    } catch (e) {}
    show();
  });
});
