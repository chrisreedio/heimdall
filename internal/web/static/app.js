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
    // The URL has a #fragment (the card's anchor), and replacing a URL
    // with itself plus a fragment only scrolls, it doesn't reload.
    if (u.toString() === location.href) location.reload();
    else location.replace(u.toString());
  }, 5000);
});

// Selects and radio buttons marked data-autosubmit submit their form on
// change (the hand-off's agent and target pickers); the form's button is
// then hidden. Without JavaScript the button stays.
document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll("select[data-autosubmit], input[data-autosubmit]").forEach(function (sel) {
    if (!sel.form) return;
    sel.addEventListener("change", function () { sel.form.submit(); });
    sel.form.querySelectorAll("[data-autosubmit-hide]").forEach(function (b) { b.hidden = true; });
  });
});

// Sidebar: fold to an icon rail and back, remembered in this browser.
// theme.js applies the saved choice before the page is drawn.
document.addEventListener("DOMContentLoaded", function () {
  var btn = document.querySelector(".side-collapse");
  if (!btn) return;
  var root = document.documentElement;
  function show() {
    var rail = root.getAttribute("data-side") === "rail";
    var label = rail ? "Expand the sidebar" : "Collapse the sidebar";
    btn.setAttribute("aria-label", label);
    btn.title = label;
    btn.setAttribute("aria-expanded", rail ? "false" : "true");
  }
  show();
  btn.hidden = false;
  btn.addEventListener("click", function () {
    var rail = root.getAttribute("data-side") !== "rail";
    if (rail) root.setAttribute("data-side", "rail");
    else root.removeAttribute("data-side");
    try {
      if (rail) localStorage.setItem("heimdall-side", "rail");
      else localStorage.removeItem("heimdall-side");
    } catch (e) {}
    show();
  });
});

// Collector options on Add host and Add servers. Beside the install
// commands, the checkboxes rewrite the flags in each command in place
// (<span data-collector-flags>), so the token or key shown once is never
// reissued, and the copy buttons copy the text as it now stands. Without
// JavaScript they stay hidden and the commands keep the form's choice.
// On the forms, picking an environment in another org resets the
// checkboxes to that org's default (each option's data-opts).
document.addEventListener("DOMContentLoaded", function () {
  function has(flags, f) { return (" " + flags + " ").indexOf(" " + f + " ") >= 0; }
  document.querySelectorAll("fieldset[data-collector-opts]").forEach(function (box) {
    var checks = box.querySelectorAll("input[data-collector-flag]");
    function sync() {
      var flags = "";
      checks.forEach(function (c) { if (c.checked) flags += " " + c.getAttribute("data-collector-flag"); });
      document.querySelectorAll("[data-collector-flags]").forEach(function (s) { s.textContent = flags; });
    }
    checks.forEach(function (c) { c.addEventListener("change", sync); });
    box.hidden = false;
    sync(); // a restored page may bring back other checkbox states
  });
  document.querySelectorAll("fieldset[data-collector-defaults]").forEach(function (box) {
    var select = document.getElementById(box.getAttribute("data-collector-defaults"));
    if (!select) return;
    function org() { return select.value.split("/")[0]; }
    var last = org();
    select.addEventListener("change", function () {
      if (org() === last) return;
      last = org();
      var opt = select.options[select.selectedIndex];
      var d = opt ? opt.getAttribute("data-opts") : null;
      if (d === null) return;
      box.querySelectorAll("input[type=checkbox][name^=watch_]").forEach(function (c) {
        c.checked = has(d, "--" + c.name.replace(/_/g, "-"));
      });
    });
  });
});
