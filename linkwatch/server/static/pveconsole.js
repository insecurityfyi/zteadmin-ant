/* Proxmox text console pop-out: xterm.js here, the Proxmox console opened by the poller, bytes relayed by the server. */
(function () {
  "use strict";
  const target = JSON.parse(document.getElementById("target").textContent);
  const msg = document.getElementById("msg");
  const pill = document.getElementById("state");
  const discBtn = document.getElementById("disconnect");
  const enc = new TextEncoder();
  let ws = null, term = null, fit = null, keepalive = null, live = false;

  function setState(text, kind) { pill.textContent = text; pill.className = "pill" + (kind ? " " + kind : ""); }
  function say(text, cls) { if (msg) { msg.textContent = text || ""; msg.className = "msg " + (cls || ""); } }

  function ensureTerm() {
    if (term) return;
    const css = getComputedStyle(document.documentElement);
    term = new Terminal({
      cursorBlink: true, fontSize: 13, scrollback: 5000,
      fontFamily: (css.getPropertyValue("--mono") || "ui-monospace, Menlo, monospace").trim(),
      theme: { background: "#0b0f14", foreground: "#d7dee5", cursor: (css.getPropertyValue("--accent") || "#3cc3d3").trim() }
    });
    fit = new FitAddon.FitAddon();
    term.loadAddon(fit);
    term.open(document.getElementById("term"));
    term.onData(function (d) { if (ws && ws.readyState === 1 && live) ws.send(enc.encode(d)); });
    term.onResize(function (sz) { if (ws && ws.readyState === 1) ws.send(JSON.stringify({ type: "resize", cols: sz.cols, rows: sz.rows })); });
    window.addEventListener("resize", function () { try { fit.fit(); } catch (e) { /* hidden */ } });
  }

  function connect() {
    ensureTerm();
    document.body.classList.add("live");
    fit.fit();
    term.reset();
    setState("connecting");
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    ws = new WebSocket(proto + "//" + location.host + "/api/poller/ws/pveconsole");
    ws.binaryType = "arraybuffer";
    ws.onopen = function () {
      ws.send(JSON.stringify(Object.assign({}, target, { cols: term.cols, rows: term.rows })));
      keepalive = setInterval(function () { if (ws.readyState === 1) ws.send(JSON.stringify({ type: "ping" })); }, 25000);
    };
    ws.onmessage = function (ev) {
      if (typeof ev.data !== "string") { term.write(new Uint8Array(ev.data)); return; }
      let m; try { m = JSON.parse(ev.data); } catch (e) { return; }
      if (m.type === "status") term.write("\x1b[2m" + m.text + "\x1b[0m\r\n");
      else if (m.type === "ready") {
        live = true; setState("connected", "ok"); discBtn.hidden = false;
        term.write("\x1b[2m" + m.text + ". Press Enter if the screen stays blank.\x1b[0m\r\n");
        ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
        term.focus();
      } else if (m.type === "error") {
        term.write("\r\n\x1b[31m" + m.text + "\x1b[0m\r\n");
        setTimeout(function () { document.body.classList.remove("live"); say(m.text, "bad"); setState("failed", "bad"); }, 1200);
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
      const sub = term.onData(function (d) { if (d === "\r") { sub.dispose(); connect(); } });
    }
  }

  discBtn.addEventListener("click", function () { if (ws && ws.readyState === 1) ws.send(JSON.stringify({ type: "close" })); });
  document.getElementById("connect").addEventListener("click", function () { say(""); connect(); });
  window.addEventListener("beforeunload", function () { if (ws && ws.readyState === 1) ws.close(); });
  connect();
})();
