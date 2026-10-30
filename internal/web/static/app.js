// Progressive enhancement only: copy buttons for commands. The Clipboard
// API needs HTTPS, which tailscale serve gives the app; without it, or if
// the browser refuses, the text is copied the old way, and failing that
// it's left selected, ready to copy by hand (a long press on a phone).
document.addEventListener("DOMContentLoaded", function () {
  function oldCopy(text) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.className = "copy-buffer";
    document.body.appendChild(ta);
    ta.select();
    ta.setSelectionRange(0, text.length); // iOS
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (e) {}
    ta.remove();
    return ok;
  }
  function select(el) {
    var range = document.createRange();
    range.selectNodeContents(el);
    var sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }
  document.querySelectorAll("button[data-copy]").forEach(function (btn) {
    var target = document.getElementById(btn.getAttribute("data-copy"));
    if (!target) return;
    btn.hidden = false;
    btn.addEventListener("click", function () {
      var text = target.textContent;
      function done(ok) {
        if (!ok) select(target);
        btn.textContent = ok ? "Copied" : "Selected";
        setTimeout(function () { btn.textContent = "Copy"; }, 1500);
      }
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(oldCopy(text)); });
      } else {
        done(oldCopy(text));
      }
    });
  });
});

// Step-up codes (stepup.go): when the page says which actions need a
// fresh code (body data-stepup), a form sent to one of them asks for it in
// a dialog first and goes with the code, so nothing typed or chosen is
// lost. Without JavaScript, or a browser without <dialog>, the hub asks on
// a page of its own instead.
document.addEventListener("DOMContentLoaded", function () {
  var paths = (document.body.getAttribute("data-stepup") || "").split(" ").filter(Boolean);
  var dialog = document.querySelector("dialog.stepup-dialog");
  if (!paths.length || !dialog || !dialog.showModal) return;
  var input = dialog.querySelector("input[name=stepup_code]");
  var pending = null;
  function covered(form) {
    if ((form.getAttribute("method") || "").toLowerCase() !== "post") return false;
    var path = new URL(form.action, document.baseURI).pathname;
    return paths.some(function (p) { return path.indexOf(p) === 0; });
  }
  function hidden(form, name, value) {
    var el = document.createElement("input");
    el.type = "hidden";
    el.name = name;
    el.value = value;
    form.appendChild(el);
  }
  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (form === dialog.querySelector("form") || !covered(form) || form.querySelector("input[name=stepup_code]")) return;
    e.preventDefault();
    pending = { form: form, submitter: e.submitter };
    input.value = "";
    dialog.returnValue = "";
    dialog.showModal();
  }, true);
  dialog.addEventListener("close", function () {
    var p = pending;
    pending = null;
    if (!p || dialog.returnValue !== "ok" || !input.value.trim()) return;
    hidden(p.form, "stepup_code", input.value.trim());
    // form.submit() doesn't send the clicked button's name and value.
    if (p.submitter && p.submitter.name) hidden(p.form, p.submitter.name, p.submitter.value);
    p.form.submit();
  });
});

// After a Microsoft sign-in for a step-up, the waiting action is sent on
// (stepup_resume.html); its Continue button does it without JavaScript.
document.addEventListener("DOMContentLoaded", function () {
  var form = document.querySelector("form[data-resume]");
  if (form) form.submit();
});

// The installable app (pwa.go): register the service worker, which shows
// an offline page when the hub can't be reached. Browsers allow it only on
// HTTPS (or localhost), which tailscale serve provides.
if ("serviceWorker" in navigator && window.isSecureContext) {
  navigator.serviceWorker.register("/sw.js", { scope: "/" }).catch(function () {});
}

// Theme switcher: System -> Light -> Dark, remembered in this browser.
// theme.js applies the saved choice before the page is drawn. There can be
// more than one button (the sidebar's and the phone header's).
document.addEventListener("DOMContentLoaded", function () {
  var btns = document.querySelectorAll(".theme-toggle");
  if (!btns.length) return;
  var order = ["system", "light", "dark"];
  var mode = "system";
  try { mode = localStorage.getItem("heimdall-theme") || "system"; } catch (e) {}
  if (order.indexOf(mode) < 0) mode = "system";
  function show() {
    var label = "Theme: " + mode + " (click for " + order[(order.indexOf(mode) + 1) % 3] + ")";
    btns.forEach(function (btn) {
      btn.setAttribute("data-mode", mode);
      btn.setAttribute("aria-label", label);
      btn.title = label;
    });
  }
  function next() {
    mode = order[(order.indexOf(mode) + 1) % 3];
    if (mode === "system") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", mode);
    try {
      if (mode === "system") localStorage.removeItem("heimdall-theme");
      else localStorage.setItem("heimdall-theme", mode);
    } catch (e) {}
    show();
  }
  show();
  btns.forEach(function (btn) {
    btn.hidden = false;
    btn.addEventListener("click", next);
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

// Anomalies: a select-all box, shift-click to tick a run of rows, and a
// count on the bulk form. Without JavaScript the row boxes still post with
// the form; only these niceties are missing.
document.addEventListener("DOMContentLoaded", function () {
  var form = document.querySelector("form[data-bulk]");
  if (!form) return;
  var rows = Array.prototype.slice.call(document.querySelectorAll("input[data-bulk-row]"));
  var alls = Array.prototype.slice.call(document.querySelectorAll("input[data-bulk-all]"));
  var count = form.querySelector("[data-bulk-count]");
  var hint = count ? count.textContent : "";
  var buttons = form.querySelectorAll("button[type=submit]");
  var last = null;
  function update() {
    var n = rows.filter(function (r) { return r.checked; }).length;
    if (count) count.textContent = n ? n + (n === 1 ? " anomaly" : " anomalies") + " selected." : hint;
    alls.forEach(function (all) {
      all.checked = n > 0 && n === rows.length;
      all.indeterminate = n > 0 && n < rows.length;
    });
    buttons.forEach(function (b) { b.disabled = n === 0; });
  }
  rows.forEach(function (box) {
    box.addEventListener("click", function (ev) {
      if (ev.shiftKey && last && last !== box) {
        var a = rows.indexOf(last), b = rows.indexOf(box);
        rows.slice(Math.min(a, b), Math.max(a, b) + 1).forEach(function (r) { r.checked = box.checked; });
      }
      last = box;
      update();
    });
  });
  if (rows.length) {
    alls.forEach(function (all) {
      (all.closest("label[hidden]") || all).hidden = false;
      all.hidden = false;
      all.addEventListener("change", function () {
        rows.forEach(function (r) { r.checked = all.checked; });
        update();
      });
    });
  }
  update();
});

// Times: the server writes instants in UTC (<time data-ts>, and snapshot
// <option>s with data-at); show them in this browser's time zone, named
// ("Oct 29, 2026 2:14 PM CDT"). Their tooltips keep UTC. data-ts is
// "datetime", "date", or "dayago" (web.dayAgo's wording, with today and
// yesterday as they are here). Without JavaScript the UTC text stands.
document.addEventListener("DOMContentLoaded", function () {
  if (!window.Intl || !Intl.DateTimeFormat.prototype.formatToParts) return;
  var opts = { month: "short", day: "numeric", year: "numeric", hour: "numeric", minute: "2-digit", timeZoneName: "short" };
  var fmt;
  try { fmt = new Intl.DateTimeFormat("en-US", opts); } catch (e) { return; }
  function parts(d) {
    var p = {};
    fmt.formatToParts(d).forEach(function (x) { p[x.type] = x.value; });
    return p;
  }
  function date(p) { return p.month + " " + p.day + ", " + p.year; }
  function clock(p) { return p.hour + ":" + p.minute + " " + p.dayPeriod + " " + p.timeZoneName; }
  function ago(d, now) {
    var m = Math.floor((now - d) / 60000);
    if (m < 1) return "just now";
    if (m < 60) return m + "m ago";
    if (m < 48 * 60) return Math.floor(m / 60) + "h ago";
    return Math.floor(m / 1440) + "d ago";
  }
  // dayNumber counts days in this time zone, so their difference is how
  // many midnights apart two instants are here.
  function dayNumber(d) { return Math.round(new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime() / 864e5); }
  function text(kind, d, now) {
    var p = parts(d);
    if (kind === "date") return date(p);
    if (kind === "dayago") {
      var days = dayNumber(now) - dayNumber(d);
      if (days === 0) return "Today " + clock(p) + " (" + ago(d, now) + ")";
      if (days === 1) return "Yesterday " + clock(p);
      if (days > 1 && days < 30) return days + " days ago";
      return date(p);
    }
    return date(p) + " " + clock(p);
  }
  var now = new Date();
  document.querySelectorAll("time[data-ts]").forEach(function (el) {
    var d = new Date(el.getAttribute("datetime"));
    if (!isNaN(d)) el.textContent = text(el.getAttribute("data-ts"), d, now);
  });
  document.querySelectorAll("option[data-at]").forEach(function (el) {
    var d = new Date(el.getAttribute("data-at"));
    if (!isNaN(d)) el.textContent = (el.getAttribute("data-prefix") || "") + text(el.getAttribute("data-ts"), d, now);
  });
});
