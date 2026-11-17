// CPPM Monitor UI behaviour (no inline scripts: CSP is script-src 'self').
(function () {
  "use strict";
  var root = document.documentElement;

  function store(key, val) { try { localStorage.setItem(key, val); } catch (e) { /* storage blocked */ } }

  // Theme toggle
  document.querySelectorAll("[data-theme-toggle]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      store("cppmmon.theme", next);
    });
  });

  // Sidebar collapse
  var app = document.getElementById("app");
  if (app) {
    if (root.classList.contains("sidebar-collapsed")) app.classList.add("collapsed");
    document.querySelectorAll("[data-sidebar-toggle]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var collapsed = app.classList.toggle("collapsed");
        root.classList.toggle("sidebar-collapsed", collapsed);
        store("cppmmon.sidebar", collapsed ? "collapsed" : "expanded");
      });
    });
  }

  // User menu
  document.querySelectorAll("[data-menu-toggle]").forEach(function (btn) {
    var menu = btn.parentElement.querySelector(".menu");
    btn.addEventListener("click", function (e) {
      e.stopPropagation();
      var open = menu.classList.toggle("open");
      btn.setAttribute("aria-expanded", open ? "true" : "false");
    });
    document.addEventListener("click", function () { menu.classList.remove("open"); btn.setAttribute("aria-expanded", "false"); });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape") { menu.classList.remove("open"); btn.setAttribute("aria-expanded", "false"); } });
  });

  // Password reveal
  document.querySelectorAll("[data-reveal]").forEach(function (btn) {
    var input = document.getElementById(btn.getAttribute("data-reveal"));
    btn.addEventListener("click", function () {
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.setAttribute("aria-pressed", show ? "true" : "false");
      btn.setAttribute("aria-label", show ? "Hide password" : "Show password");
      input.focus();
    });
  });

  // Display-zone clock (IST by default)
  var clock = document.querySelector("[data-clock]");
  if (clock) {
    var fmt;
    try {
      fmt = new Intl.DateTimeFormat("en-GB", { timeZone: clock.dataset.tz, hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
    } catch (e) {
      fmt = new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
    }
    var tick = function () { clock.textContent = fmt.format(new Date()) + " " + clock.dataset.label; };
    tick();
    setInterval(tick, 1000);
  }

  // Conditional sections: [data-show-when="group=value"] driven by inputs with data-toggle-group.
  // Checkboxes report "on"/"off"; radios report the checked value.
  function groupValue(form, group) {
    var inputs = form.querySelectorAll('[data-toggle-group="' + group + '"]');
    for (var i = 0; i < inputs.length; i++) {
      var el = inputs[i];
      if (el.type === "checkbox") return el.checked ? "on" : "off";
      if (el.type === "radio" && el.checked) return el.value;
    }
    return "";
  }
  function applyToggles(form) {
    form.querySelectorAll("[data-show-when]").forEach(function (sec) {
      var parts = sec.getAttribute("data-show-when").split("=");
      sec.classList.toggle("is-hidden", groupValue(form, parts[0]) !== parts[1]);
    });
  }
  document.querySelectorAll("form").forEach(function (form) {
    if (!form.querySelector("[data-show-when]")) return;
    applyToggles(form);
    form.addEventListener("change", function () { applyToggles(form); });
  });

  // Clickable table rows
  document.querySelectorAll("tr[data-href]").forEach(function (tr) {
    tr.addEventListener("click", function (e) {
      if (e.target.closest("a, button, input")) return;
      window.location = tr.getAttribute("data-href");
    });
  });

  // Expandable event rows (event delegation so live-inserted rows work too)
  document.querySelectorAll("tbody").forEach(function (tb) {
    tb.addEventListener("click", function (e) {
      var row = e.target.closest("tr[data-expand]");
      if (!row || e.target.closest("a")) return;
      var detail = document.getElementById(row.getAttribute("data-expand"));
      if (!detail) return;
      detail.hidden = !detail.hidden;
      row.classList.toggle("open", !detail.hidden);
    });
  });

  // Live tail: poll data-live-tail URL with after_id, prepend new rows (newest first)
  var MAX_ROWS = 1000;
  document.querySelectorAll("[data-live-tail]").forEach(function (tbody) {
    var base = tbody.getAttribute("data-live-tail");
    var interval = parseInt(tbody.getAttribute("data-interval") || "5000", 10);
    var toggle = document.querySelector('[data-live-toggle="' + tbody.id + '"]');
    var live = true, busy = false;
    if (toggle) {
      toggle.addEventListener("click", function () {
        live = !live;
        toggle.classList.toggle("on", live);
        toggle.setAttribute("aria-pressed", live ? "true" : "false");
        toggle.querySelector(".live-label").textContent = live ? "Live" : "Paused";
      });
    }
    function poll() {
      if (!live || busy || document.hidden) return;
      busy = true;
      var url = base + (base.indexOf("?") < 0 ? "?" : "&") + "after_id=" + encodeURIComponent(tbody.getAttribute("data-after-id") || "0");
      fetch(url, { credentials: "same-origin", headers: { "Accept": "text/html" } })
        .then(function (r) {
          if (r.redirected || r.status === 401) { window.location.reload(); return null; }
          if (!r.ok) throw new Error("HTTP " + r.status);
          var maxId = r.headers.get("X-Max-Id");
          return r.text().then(function (html) { return { html: html, maxId: maxId }; });
        })
        .then(function (res) {
          if (!res || !res.html.trim()) return;
          var before = tbody.rows.length;
          tbody.insertAdjacentHTML("afterbegin", res.html);
          for (var i = 0; i < tbody.rows.length - before; i++) {
            if (tbody.rows[i].classList.contains("ev-row")) tbody.rows[i].classList.add("ev-new");
          }
          if (res.maxId) tbody.setAttribute("data-after-id", res.maxId);
          while (tbody.rows.length > MAX_ROWS) tbody.deleteRow(tbody.rows.length - 1);
          var empty = document.querySelector('[data-empty-for="' + tbody.id + '"]');
          if (empty) empty.remove();
        })
        .catch(function () { /* transient: retry next tick */ })
        .then(function () { busy = false; });
    }
    setInterval(poll, interval);
  });

  // Confirmation prompts on destructive buttons
  document.querySelectorAll("[data-confirm]").forEach(function (btn) {
    btn.addEventListener("click", function (e) {
      if (!window.confirm(btn.getAttribute("data-confirm"))) e.preventDefault();
    });
  });

  // Select-all + selection counter for bulk actions
  document.querySelectorAll("[data-select-all]").forEach(function (master) {
    var form = master.closest("form");
    var name = master.getAttribute("data-select-all");
    var boxes = function () { return form.querySelectorAll('input[type=checkbox][name="' + name + '"]'); };
    var counter = form.querySelector("[data-sel-count]");
    var needs = form.querySelectorAll("[data-needs-selection]");
    function sync() {
      var n = 0; boxes().forEach(function (b) { if (b.checked) n++; });
      if (counter) counter.textContent = n + " selected";
      needs.forEach(function (b) { b.disabled = n === 0; });
      master.checked = n > 0 && n === boxes().length;
      master.indeterminate = n > 0 && n < boxes().length;
    }
    master.addEventListener("change", function () { boxes().forEach(function (b) { b.checked = master.checked; }); sync(); });
    form.addEventListener("change", function (e) { if (e.target.name === name) sync(); });
    sync();
  });

  // Copy-to-clipboard buttons (ticket text)
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var el = document.getElementById(btn.getAttribute("data-copy"));
      if (!el || !navigator.clipboard) return;
      navigator.clipboard.writeText(el.textContent).then(function () {
        var old = btn.textContent; btn.textContent = "Copied"; setTimeout(function () { btn.textContent = old; }, 1500);
      });
    });
  });

  // CSRF header on every HTMX request
  document.body.addEventListener("htmx:configRequest", function (e) {
    var m = document.querySelector('meta[name="csrf-token"]');
    if (m) e.detail.headers["X-CSRFToken"] = m.content;
  });
})();
