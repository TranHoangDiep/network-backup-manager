/* Minimal progressive enhancement: confirmations, dynamic forms, job status polling. */
(function () {
  "use strict";

  // Confirmation dialogs for destructive forms
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (!window.confirm(form.getAttribute("data-confirm"))) { event.preventDefault(); }
    });
  });

  // Show/hide password buttons
  document.querySelectorAll("[data-toggle-password]").forEach(function (button) {
    button.addEventListener("click", function () {
      var input = document.getElementById(button.getAttribute("data-toggle-password"));
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      button.querySelector("i").className = show ? "bi bi-eye" : "bi bi-eye-slash";
      button.setAttribute("aria-label", show ? "Hide password" : "Show password");
    });
  });

  function toggle(el, show) { if (el) { el.classList.toggle("d-none", !show); } }

  // ------------------------------------------------------- device form ---
  var vendor = document.getElementById("vendor");
  var platform = document.getElementById("platform");
  var method = document.getElementById("connection_method");
  var credential = document.getElementById("credential_id");
  if (vendor && platform && method && credential) {
    var refresh = function () {
      // Platforms of the selected vendor only
      Array.prototype.forEach.call(platform.options, function (opt) {
        opt.hidden = opt.dataset.vendor !== vendor.value;
      });
      if (platform.selectedOptions[0] && platform.selectedOptions[0].hidden) {
        var first = Array.prototype.find.call(platform.options, function (o) { return !o.hidden; });
        if (first) { platform.value = first.value; }
      }
      // Connection methods supported by the platform driver
      var methods = (platform.selectedOptions[0] ? platform.selectedOptions[0].dataset.methods : "ssh").split(",");
      Array.prototype.forEach.call(method.options, function (opt) {
        opt.hidden = methods.indexOf(opt.value) === -1;
      });
      if (methods.indexOf(method.value) === -1) { method.value = methods[0]; }
      // Credential profiles matching SSH/API
      Array.prototype.forEach.call(credential.options, function (opt) {
        if (opt.value) { opt.hidden = opt.dataset.type !== method.value; }
      });
      if (credential.selectedOptions[0] && credential.selectedOptions[0].hidden) { credential.value = ""; }
      toggle(document.getElementById("vdom-group"), platform.value === "fortinet" && method.value === "api");
    };
    [vendor, platform, method].forEach(function (el) { el.addEventListener("change", refresh); });
    refresh();
  }

  // --------------------------------------------------- credential form ---
  var credType = document.getElementById("cred_type");
  if (credType) {
    var showSection = function () {
      document.querySelectorAll(".cred-section").forEach(function (section) {
        toggle(section, section.dataset.section === credType.value);
      });
    };
    credType.addEventListener("change", showSection);
    showSection();
  }

  // ------------------------------------------------------- policy form ---
  var scheduleType = document.getElementById("schedule_type");
  if (scheduleType) {
    var showSchedule = function () {
      document.querySelectorAll(".sched").forEach(function (el) {
        toggle(el, el.classList.contains("sched-" + scheduleType.value));
      });
    };
    scheduleType.addEventListener("change", showSchedule);
    showSchedule();
  }

  // ---------------------------------------------------- job polling ---
  var BADGES = { success: "success", partial: "warning", failed: "danger", interrupted: "secondary",
                 queued: "info", running: "primary", cancelled: "secondary" };
  function poll(el) {
    var id = el.dataset.jobId;
    fetch("/jobs/" + encodeURIComponent(id) + ".json", { credentials: "same-origin", headers: { "Accept": "application/json" } })
      .then(function (r) { if (!r.ok) { throw new Error(r.status); } return r.json(); })
      .then(function (job) {
        el.textContent = job.status + (job.attempt > 1 ? " (try " + job.attempt + "/" + job.max_attempts + ")" : "");
        el.className = "badge text-bg-" + (BADGES[job.status] || "light");
        var msg = document.querySelector('[data-job-message="' + id + '"]');
        if (msg && job.message) { msg.textContent = job.message; }
        if (job.active) { setTimeout(function () { poll(el); }, 3000); }
        else if (el.dataset.reload) { setTimeout(function () { window.location.href = window.location.pathname; }, 1500); }
      })
      .catch(function () { setTimeout(function () { poll(el); }, 10000); });
  }
  document.querySelectorAll("[data-job-id]").forEach(poll);
})();
