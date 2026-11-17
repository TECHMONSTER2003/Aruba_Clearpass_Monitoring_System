// Node overview charts (Chart.js, vendored). No date adapter: linear x axis in epoch ms,
// ticks formatted in the display time zone (IST by default).
(function () {
  "use strict";
  if (typeof Chart === "undefined") return;

  // Series palette (no orange/amber), validated for light + dark.
  var PALETTE = ["#0A65C2", "#16A34A", "#0D9488", "#7C3AED", "#0891B2", "#DB2777", "#64748B"];
  var LABELS = {
    cpu_pct: "CPU", mem_pct: "Memory", disk_pct: "Disk", auth_per_min: "Total", auth_fail_per_min: "Failed",
    icmp_rtt_ms: "RTT", auth_src_fail_per_min: "Failures", if_in_bps: "In", if_out_bps: "Out"
  };

  function css(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }

  function label(key) {
    var parts = key.split("|");
    var base = LABELS[parts[0]] || parts[0];
    return parts[1] ? parts[1] + " · " + base : base;
  }

  function fmtValue(v, unit) {
    if (v === null || v === undefined) return "—";
    if (unit === "bps") {
      if (v >= 1e9) return (v / 1e9).toFixed(2) + " Gb/s";
      if (v >= 1e6) return (v / 1e6).toFixed(2) + " Mb/s";
      if (v >= 1e3) return (v / 1e3).toFixed(1) + " kb/s";
      return v.toFixed(0) + " b/s";
    }
    var d = Math.abs(v) >= 100 ? 0 : 1;
    return v.toFixed(d) + (unit === "%" ? "%" : unit === "ms" ? " ms" : unit === "/min" ? "/min" : "");
  }

  function build(canvas) {
    var tz = canvas.dataset.tz || undefined;
    var hours = parseFloat(canvas.dataset.hours || "24");
    var timeFmt;
    try {
      timeFmt = new Intl.DateTimeFormat("en-GB", hours > 48
        ? { timeZone: tz, day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", hour12: false }
        : { timeZone: tz, hour: "2-digit", minute: "2-digit", hour12: false });
    } catch (e) {
      timeFmt = new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit", hour12: false });
    }
    fetch(canvas.dataset.chart, { credentials: "same-origin" })
      .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
      .then(function (data) {
        var keys = Object.keys(data.series || {}).sort();
        var empty = canvas.parentElement.querySelector(".chart-empty");
        if (!keys.length) { canvas.hidden = true; if (empty) empty.hidden = false; return; }
        var grid = css("--border"), text = css("--text-3");
        var datasets = keys.map(function (k, i) {
          var color = k.indexOf("auth_fail_per_min") === 0 ? css("--crit-dot") : PALETTE[i % PALETTE.length];
          return {
            label: label(k), data: data.series[k].map(function (p) { return { x: p[0], y: p[1] }; }),
            borderColor: color, backgroundColor: color + "22", borderWidth: 2, pointRadius: 0, pointHitRadius: 6,
            tension: 0.25, fill: keys.length === 1, spanGaps: false
          };
        });
        var isPct = data.unit === "%";
        new Chart(canvas, {
          type: "line",
          data: { datasets: datasets },
          options: {
            responsive: true, maintainAspectRatio: false, animation: false, parsing: false, normalized: true,
            interaction: { mode: "nearest", axis: "x", intersect: false },
            scales: {
              x: { type: "linear", grid: { color: grid }, ticks: { color: text, maxTicksLimit: 8, callback: function (v) { return timeFmt.format(new Date(v)); } } },
              y: { beginAtZero: true, max: isPct ? 100 : undefined, grid: { color: grid },
                   ticks: { color: text, callback: function (v) { return fmtValue(v, data.unit); } } }
            },
            plugins: {
              legend: { display: keys.length > 1, labels: { color: css("--text-2"), boxWidth: 10, boxHeight: 10, usePointStyle: true } },
              tooltip: { callbacks: {
                title: function (items) { return items.length ? timeFmt.format(new Date(items[0].parsed.x)) : ""; },
                label: function (item) { return item.dataset.label + ": " + fmtValue(item.parsed.y, data.unit); }
              } }
            }
          }
        });
      })
      .catch(function () {
        var empty = canvas.parentElement.querySelector(".chart-empty");
        if (empty) { empty.textContent = "Chart data could not be loaded."; empty.hidden = false; }
        canvas.hidden = true;
      });
  }

  document.querySelectorAll("canvas[data-chart]").forEach(build);
})();
