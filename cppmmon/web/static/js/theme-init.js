// Runs in <head> before first paint so the page never flashes the wrong theme.
(function () {
  var t = null;
  try { t = localStorage.getItem("cppmmon.theme"); } catch (e) { /* storage blocked */ }
  if (t !== "light" && t !== "dark") {
    t = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  document.documentElement.setAttribute("data-theme", t);
  var c = null;
  try { c = localStorage.getItem("cppmmon.sidebar"); } catch (e) { /* storage blocked */ }
  if (c === "collapsed") document.documentElement.classList.add("sidebar-collapsed");
})();
