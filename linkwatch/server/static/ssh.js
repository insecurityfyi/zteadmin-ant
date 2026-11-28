/* SSH console pop-out: xterm.js in the browser, SSH on the VisCon1 server, bytes through the poller's tunnel. */
(function () {
  "use strict";
  const target = JSON.parse(document.getElementById("target").textContent);
  const form = document.getElementById("f");
  const msg = document.getElementById("msg");
  const pill = document.getElementById("state");
  const discBtn = document.getElementById("disconnect");
  const enc = new TextEncoder();
  let auth = "password", ws = null, term = null, fit = null, keepalive = null, live = false;

  function setState(text, kind) { pill.textContent = text; pill.className = "pill" + (kind ? " " + kind : ""); }
  function say(text, cls) { if (msg) { msg.textContent = text || ""; msg.className = "msg " + (cls || ""); } }

  document.querySelectorAll("[data-auth]").forEach(function (b) {
    b.addEventListener("click", function () {
      auth = b.dataset.auth;
      document.querySelectorAll("[data-auth]").forEach(function (x) { x.setAttribute("aria-pressed", String(x === b)); });
      document.querySelectorAll("[data-pane]").forEach(function (p) { p.hidden = p.dataset.pane !== auth; });
    });
  });

  function ensureTerm() {
    if (term) return;
    const css = getComputedStyle(document.documentElement);
    term = new Terminal({
      cursorBlink: true, fontSize: 13, scrollback: 5000, convertEol: false,
      fontFamily: (css.getPropertyValue("--mono") || "ui-monospace, Menlo, monospace").trim(),
      theme: { background: "#0b0f14", foreground: "#d7dee5", cursor: (css.getPropertyValue("--accent") || "#3cc3d3").trim() }
    });
    fit = new FitAddon.FitAddon();
    term.loadAddon(fit);
    term.open(document.getElementById("term"));
    term.onData(function (d) { if (ws && ws.readyState === 1 && live) ws.send(enc.encode(d)); });
    term.onBinary(function (d) {
      if (!(ws && ws.readyState === 1 && live)) return;
      const buf = new Uint8Array(d.length);
      for (let i = 0; i < d.length; i++) buf[i] = d.charCodeAt(i) & 255;
      ws.send(buf);
    });
    term.onResize(function (sz) { if (ws && ws.readyState === 1) ws.send(JSON.stringify({ type: "resize", cols: sz.cols, rows: sz.rows })); });
    window.addEventListener("resize", function () { try { fit.fit(); } catch (e) { /* hidden */ } });
  }

  function connect(hello) {
    ensureTerm();
    document.body.classList.add("live");
    fit.fit();
    term.reset();
    term.write("\x1b[2m" + "Connecting to " + target.host + " port " + target.port + "…\x1b[0m\r\n");
    setState("connecting");
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    ws = new WebSocket(proto + "//" + location.host + "/api/poller/ws/console");
    ws.binaryType = "arraybuffer";
    ws.onopen = function () {
      ws.send(JSON.stringify(Object.assign({}, target, hello, { cols: term.cols, rows: term.rows })));
      keepalive = setInterval(function () { if (ws.readyState === 1) ws.send(JSON.stringify({ type: "ping" })); }, 25000);
    };
    ws.onmessage = function (ev) {
      if (typeof ev.data !== "string") { term.write(new Uint8Array(ev.data)); return; }
      let m; try { m = JSON.parse(ev.data); } catch (e) { return; }
      if (m.type === "status") term.write("\x1b[2m" + m.text + "\x1b[0m\r\n");
      else if (m.type === "hostkey") {
        if (m.new) term.write("\x1b[33mFirst connection to this host. Its key " + m.fingerprint + " is now pinned; a different key will be refused.\x1b[0m\r\n");
      } else if (m.type === "ready") {
        live = true; setState("connected", "ok"); discBtn.hidden = false; document.title = "SSH " + m.text.replace(/^Connected to /, "");
        term.focus();
      } else if (m.type === "error") {
        term.write("\r\n\x1b[31m" + m.text + "\x1b[0m\r\n");
        backToLogin(m.text, m.hostkey);
      } else if (m.type === "closed") {
        if (live) term.write("\r\n\x1b[2mSession closed: " + m.text + "\x1b[0m\r\n");
        end("closed");
      }
    };
    ws.onclose = function () { end(live ? "closed" : null); };
  }

  function end(state) {
    if (keepalive) { clearInterval(keepalive); keepalive = null; }
    const wasLive = live;
    live = false; discBtn.hidden = true;
    if (state) setState(state);
    if (wasLive) {
      term.write("\x1b[2mPress Enter to reconnect, or close this window.\x1b[0m\r\n");
      const sub = term.onData(function (d) { if (d === "\r") { sub.dispose(); backToLogin(""); } });
    }
  }

  function backToLogin(text, hostkey) {
    if (!text) { document.body.classList.remove("live"); return; }
    setTimeout(function () {
      document.body.classList.remove("live");
      say(text, "bad");
      setState("failed", "bad");
      if (hostkey) { const fk = document.getElementById("forget-key"); if (fk) fk.focus(); }
    }, 1200);
  }

  discBtn.addEventListener("click", function () {
    if (ws && ws.readyState === 1) ws.send(JSON.stringify({ type: "close" }));
  });

  if (form) form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    const fd = new FormData(form);
    const hello = { username: fd.get("username"), save: fd.get("save") === "on" };
    if (auth === "password") hello.password = fd.get("password");
    else { hello.key = fd.get("key"); hello.passphrase = fd.get("passphrase"); }
    say("");
    connect(hello);
    form.querySelectorAll("input[type=password],textarea").forEach(function (i) { i.value = ""; });
  });
  const useSaved = document.getElementById("use-saved");
  if (useSaved) useSaved.addEventListener("click", function () { say(""); connect({ use_saved: true }); });
  window.addEventListener("beforeunload", function () { if (ws && ws.readyState === 1) ws.close(); });
})();
