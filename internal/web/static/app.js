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
