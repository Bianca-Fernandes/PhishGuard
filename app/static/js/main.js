/* PhishGuard front-end script (no libraries needed) */
(function () {
  "use strict";

  // ---------- mobile menu
  var toggle = document.querySelector("[data-toggle=nav]");
  if (toggle) {
    toggle.addEventListener("click", function () {
      document.getElementById("nav").classList.toggle("open");
    });
  }

  // ---------- close flash messages
  document.querySelectorAll(".flash-close").forEach(function (btn) {
    btn.addEventListener("click", function () { btn.parentElement.remove(); });
  });

  // ---------- confirm before dangerous actions
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      if (!window.confirm(form.getAttribute("data-confirm"))) e.preventDefault();
    });
  });

  // ---------- copy buttons
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var text = btn.getAttribute("data-copy");
      if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(function () {
          var old = btn.textContent;
          btn.textContent = "Copied";
          setTimeout(function () { btn.textContent = old; }, 1500);
        });
      }
    });
  });

  // ---------- scan form: quick check + progress steps
  var form = document.getElementById("scan-form");
  if (form) {
    var input = document.getElementById("url");
    var hint = document.getElementById("url-hint");
    var defaultHint = hint.textContent;

    function quickCheck(value) {
      var v = value.trim();
      if (!v) return "Please paste a link first.";
      if (v.length > 2048) return "This link is too long (max 2048 characters).";
      if (/^(javascript|data|vbscript|file|mailto|ftp):/i.test(v)) return "Only http:// and https:// links can be checked.";
      if (/:\/\//.test(v) && !/^https?:\/\//i.test(v.replace(/^hxxps?/i, "http"))) return "Only http:// and https:// links can be checked.";
      return "";
    }

    input.addEventListener("input", function () {
      hint.textContent = defaultHint;
      hint.classList.remove("error");
    });

    form.addEventListener("submit", function (e) {
      var problem = quickCheck(input.value);
      if (problem) {
        e.preventDefault();
        hint.textContent = problem;
        hint.classList.add("error");
        input.focus();
        return;
      }
      var btn = document.getElementById("scan-btn");
      btn.disabled = true;
      btn.classList.add("loading");
      btn.querySelector(".btn-label").textContent = "Scanning…";

      var progress = document.getElementById("scan-progress");
      var steps = progress.querySelectorAll("li");
      progress.hidden = false;
      var i = 0;
      steps[0].classList.add("now");
      var timer = setInterval(function () {
        if (i >= steps.length - 1) { clearInterval(timer); return; }
        steps[i].classList.remove("now");
        steps[i].classList.add("done");
        i += 1;
        steps[i].classList.add("now");
      }, 900);
    });
  }

  // ---------- password strength meter
  var pw = document.getElementById("password");
  var meter = document.getElementById("pw-meter");
  if (pw && meter) {
    pw.addEventListener("input", function () {
      var v = pw.value, s = 0;
      if (v.length >= 8) s++;
      if (/[A-Z]/.test(v) && /[a-z]/.test(v)) s++;
      if (/\d/.test(v)) s++;
      if (/[^A-Za-z0-9]/.test(v) || v.length >= 14) s++;
      meter.className = "pw-meter" + (v ? " s" + s : "");
    });
  }
})();
