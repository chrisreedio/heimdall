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

// "New environment..." in environment pickers: the separate field is only
// shown once that option is chosen (without JavaScript it's always there).
document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll(".new-env[data-new-env-for]").forEach(function (box) {
    var select = document.getElementById(box.getAttribute("data-new-env-for"));
    var input = box.querySelector("input");
    if (!select || !input) return;
    var opt = document.createElement("option");
    // Keep the "org/" prefix the add-host picker's values carry.
    var first = select.options.length ? select.options[0].value : "";
    opt.value = (first.indexOf("/") > 0 ? first.slice(0, first.indexOf("/") + 1) : "") + "__new__";
    opt.textContent = "New environment…";
    select.appendChild(opt);
    var label = box.querySelector("label");
    if (label && label.firstChild && label.firstChild.nodeType === 3) label.firstChild.textContent = "New environment ";
    var opt2 = label && label.querySelector(".optional");
    if (opt2) opt2.remove();
    function sync() {
      var on = select.value === opt.value;
      box.hidden = !on;
      if (!on) input.value = "";
    }
    if (input.value) select.value = opt.value;
    select.addEventListener("change", function () { sync(); if (select.value === opt.value) input.focus(); });
    document.documentElement.classList.add("js-new-env");
    sync();
  });
});

// AI analysis: while a brief or host explanation is being written, reload
// the page every few seconds until it's done (no reload without JS; the
// page says to refresh).
document.addEventListener("DOMContentLoaded", function () {
  if (!document.querySelector("[data-ai-running]")) return;
  setTimeout(function () {
    var u = new URL(location.href);
    u.searchParams.delete("ai"); // the "started" notice was for the first view
    location.replace(u.toString());
  }, 5000);
});
