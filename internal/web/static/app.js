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

// Tag badge input: an <input data-tags> becomes chips plus a text box.
// Enter, comma or Tab adds a tag, Backspace on an empty box removes the
// last one, x removes one. The original input stays in the form (hidden)
// holding the comma-separated value, so the server sees the same field.
document.addEventListener("DOMContentLoaded", function () {
  var valid = /^[a-z0-9:._-]{1,64}$/;
  document.querySelectorAll("input[data-tags]").forEach(function (orig) {
    var box = document.createElement("div");
    box.className = "tag-input";
    var text = document.createElement("input");
    text.type = "text";
    text.placeholder = orig.placeholder;
    text.setAttribute("autocomplete", "off");
    text.setAttribute("autocapitalize", "none");
    text.setAttribute("spellcheck", "false");
    if (orig.id) { text.id = orig.id; orig.removeAttribute("id"); }
    var tags = [];
    function sync() { orig.value = tags.join(", "); }
    function render() {
      box.querySelectorAll(".chip-tag").forEach(function (c) { c.remove(); });
      tags.forEach(function (t, i) {
        var chip = document.createElement("span");
        chip.className = "chip-tag" + (valid.test(t) ? "" : " bad");
        if (!valid.test(t)) chip.title = "Tags are up to 64 lowercase letters, digits or :._-";
        chip.appendChild(document.createTextNode(t));
        var x = document.createElement("button");
        x.type = "button";
        x.textContent = "×";
        x.setAttribute("aria-label", "Remove " + t);
        x.addEventListener("click", function () { tags.splice(i, 1); render(); text.focus(); });
        chip.appendChild(x);
        box.insertBefore(chip, text);
      });
      sync();
    }
    function add(raw) {
      raw.split(",").forEach(function (t) {
        t = t.trim().toLowerCase();
        if (t && tags.indexOf(t) < 0) tags.push(t);
      });
      text.value = "";
      render();
    }
    text.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === ",") {
        if (text.value.trim()) { e.preventDefault(); add(text.value); }
        else if (e.key === ",") e.preventDefault();
      } else if (e.key === "Tab" && text.value.trim()) {
        add(text.value);
      } else if (e.key === "Backspace" && !text.value && tags.length) {
        tags.pop(); render();
      }
    });
    text.addEventListener("blur", function () { if (text.value.trim()) add(text.value); });
    text.addEventListener("paste", function () { setTimeout(function () { if (text.value.indexOf(",") >= 0) add(text.value); }, 0); });
    box.addEventListener("click", function (e) { if (e.target === box) text.focus(); });
    var form = orig.form;
    if (form) form.addEventListener("submit", function () { if (text.value.trim()) add(text.value); });
    orig.type = "hidden";
    orig.parentNode.insertBefore(box, orig);
    box.appendChild(text);
    add(orig.value);
  });
});
