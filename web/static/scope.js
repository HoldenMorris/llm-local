// The whole client. External rather than inline because the CSP allows no inline script, and
// small enough that a framework would be the larger half of the page.
(function () {
  "use strict";

  // --- copy a url without ever putting it in an href ---------------------------------------
  document.addEventListener("click", function (e) {
    var b = e.target.closest("button.copy");
    if (!b) return;
    var text = b.dataset.copy || "", was = b.textContent;
    var done = function () {
      b.textContent = "copied"; b.classList.add("done");
      setTimeout(function () { b.textContent = was; b.classList.remove("done"); }, 1200);
    };
    var fallback = function () {
      var ta = document.createElement("textarea");
      ta.value = text; ta.setAttribute("readonly", "");
      ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); done(); } catch (_) { /* nothing else to try */ }
      document.body.removeChild(ta);
    };
    if (navigator.clipboard) navigator.clipboard.writeText(text).then(done, fallback);
    else fallback();
  });

  // --- evidence tabs -------------------------------------------------------------------------
  // All panes are already in the page; a tab is a class toggle, not a request. The data is small
  // and it is already on disk, so a round-trip per tab would buy nothing.
  document.addEventListener("click", function (e) {
    var t = e.target.closest(".tabstrip button");
    if (!t) return;
    var wrap = t.closest(".paned");
    wrap.querySelectorAll(".tabstrip button").forEach(function (b) { b.classList.toggle("on", b === t); });
    wrap.querySelectorAll(".pane").forEach(function (p) { p.hidden = p.dataset.pane !== t.dataset.pane; });
  });

  // --- the phase timeline ----------------------------------------------------------------------
  // Derived from the lines url-analyze.sh already prints. These markers are the section headers
  // and progress lines in the script itself -- when one is reworded the phase quietly stops
  // lighting up, which is why the timeline is decoration and the log underneath is the truth.
  var PHASES = [
    ["static",   "1  static url",        null],
    ["domain",   "2  domain facts",      /^Domain Info/],
    ["fetch",    "3  page fetch",        /^- Fetching page content/],
    ["login",    "3.2  login link",      /following login link/],
    ["redirect", "3.2b  destination",    /following the decoded destination|301s to:/],
    ["deob",     "3.5  deobfuscation",   /^Deobfuscation/],
    ["vision",   "3.7  vision",          /^- visual check/],
    ["llm",      "4  verdict llm",       /^- LLM analyzing|^Model$/],
    ["verdict",  "verdict",              /^Signals \(/]
  ];

  function timeline(root) {
    var ol = root.querySelector(".phases");
    var seen = {}, order = [];
    return function (line) {
      for (var i = 0; i < PHASES.length; i++) {
        var re = PHASES[i][2];
        if (re && re.test(line) && !seen[PHASES[i][0]]) {
          seen[PHASES[i][0]] = true; order.push(PHASES[i]);
          break;
        }
      }
      if (!order.length) return;
      ol.hidden = false;
      ol.innerHTML = "";
      // Everything before the newest marker has finished; the newest one is what is happening now.
      order.forEach(function (p, i) {
        var li = document.createElement("li");
        li.className = i === order.length - 1 ? "now" : "was";
        li.textContent = p[1];
        ol.appendChild(li);
      });
    };
  }

  // --- the live job view -------------------------------------------------------------------
  document.querySelectorAll(".jobview").forEach(function (view) {
    var id = view.dataset.job;
    if (!id) return;
    var log = view.querySelector(".log");
    var head = view.querySelector(".state");
    var feed = timeline(view);
    if (head && (head.textContent || "").trim() === "done") return;   // already finished server-side

    // Replay is server-side by design (the stream starts at line 0), so a reload shows the whole
    // scan. Clear what the template rendered rather than print it twice.
    log.textContent = "";
    var es = new EventSource("/job/" + encodeURIComponent(id) + "/stream");

    es.onmessage = function (ev) {
      // The server escaped this; assigning to textContent keeps it inert either way.
      var atBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 80;
      var text = decodeEntities(ev.data);
      log.appendChild(document.createTextNode(text + "\n"));
      feed(text);
      if (atBottom) log.scrollTop = log.scrollHeight;
    };

    es.addEventListener("end", function (ev) {
      es.close();
      if (head) { head.textContent = ev.data; head.className = "state " + ev.data; }
      // The record view is where a finished scan belongs: the workbench reads verdict.json and
      // the artifacts, none of which existed while it was still running.
      var open = view.querySelector("a.open-when-done");
      if (open && ev.data === "done") open.classList.add("ready");
    });

    es.onerror = function () {
      // A closed stream is not an error worth shouting about -- the state line already says where
      // the job got to, and the page can be reloaded to replay it.
      es.close();
    };
  });

  function decodeEntities(s) {
    var d = document.createElement("textarea");
    d.innerHTML = s;
    return d.value;
  }

  // --- the keyboard layer ------------------------------------------------------------------
  document.addEventListener("keydown", function (e) {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    var t = e.target;
    if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable)) return;

    if (e.key === "Escape") {
      var back = document.querySelector("a.back");
      if (back) { e.preventDefault(); location.href = back.getAttribute("href"); }
    }
    if (e.key === "Enter") {
      var open = document.querySelector("a.open-when-done.ready, tr a.btn[href^='/scan/']");
      if (open) { e.preventDefault(); location.href = open.getAttribute("href"); }
    }
    // Evidence panes by number, so reading a scan does not need the mouse.
    if (/^[1-9]$/.test(e.key)) {
      var tabs = document.querySelectorAll(".tabstrip button");
      var want = tabs[parseInt(e.key, 10) - 1];
      if (want) { e.preventDefault(); want.click(); }
    }
  });
})();
