/* Remote desktop pop-out: Apache Guacamole's client in the browser, guacd on the server, RDP through the poller. */
(function () {
  "use strict";
  const target = JSON.parse(document.getElementById("target").textContent);
  const form = document.getElementById("f");
  const msg = document.getElementById("msg");
  const pill = document.getElementById("state");
  const discBtn = document.getElementById("disconnect");
  const screenEl = document.getElementById("screen");
  const bar = document.querySelector(".sshbar");
  let client = null, keyboard = null, resizeTimer = null, failed = null;

  function setState(text, kind) { pill.textContent = text; pill.className = "pill" + (kind ? " " + kind : ""); }
  function say(text, cls) { if (msg) { msg.textContent = text || ""; msg.className = "msg " + (cls || ""); } }
  function area() { return { width: Math.max(640, window.innerWidth), height: Math.max(480, window.innerHeight - bar.offsetHeight) }; }

  async function start(body) {
    say(""); failed = null;
    setState("connecting");
    const size = area();
    let res, data;
    try {
      res = await fetch("/rdp/session", {
        method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin",
        body: JSON.stringify(Object.assign({}, target, body, size, { dpi: Math.round(96 * (window.devicePixelRatio || 1)) }))
      });
      data = await res.json();
    } catch (e) { data = { error: "Could not reach the VisCon1 server." }; }
    if (!res || !res.ok || !data.token) { setState("failed", "bad"); say(data.error || data.detail || "Could not start the session.", "bad"); return; }
    open(data.token);
  }

  function open(token) {
    document.body.classList.add("live");
    screenEl.innerHTML = "";
    const tunnel = new Guacamole.WebSocketTunnel("/api/poller/ws/rdp");
    client = new Guacamole.Client(tunnel);
    const display = client.getDisplay();
    const el = display.getElement();
    el.className = "disp";
    screenEl.appendChild(el);

    const fit = function () {
      const a = area(), w = display.getWidth(), h = display.getHeight();
      if (w && h) display.scale(Math.min(a.width / w, a.height / h, 1));
    };
    display.onresize = fit;

    client.onstatechange = function (s) {
      if (s === 3) { setState("connected", "ok"); discBtn.hidden = false; screenEl.focus(); document.title = "Remote desktop " + target.host; }
      else if (s === 1 || s === 2) setState("connecting");
      else if (s === 5) finish();
    };
    client.onerror = function (status) { failed = status.message || "The remote desktop session failed."; };
    tunnel.onerror = function (status) { if (!failed) failed = status.message || "The connection to the server was lost."; };
    client.onclipboard = function (stream, mimetype) {
      if (!/^text\//.test(mimetype)) return;
      const reader = new Guacamole.StringReader(stream);
      let text = "";
      reader.ontext = function (t) { text += t; };
      reader.onend = function () { if (navigator.clipboard) navigator.clipboard.writeText(text).catch(function () {}); };
    };

    const mouse = new Guacamole.Mouse(el);
    mouse.onEach(["mousedown", "mouseup", "mousemove"], function (e) { client.sendMouseState(e.state, true); });
    keyboard = new Guacamole.Keyboard(screenEl);
    keyboard.onkeydown = function (keysym) { client.sendKeyEvent(1, keysym); };
    keyboard.onkeyup = function (keysym) { client.sendKeyEvent(0, keysym); };
    screenEl.addEventListener("mousedown", function () { screenEl.focus(); });
    screenEl.addEventListener("contextmenu", function (e) { e.preventDefault(); });

    client.connect("token=" + encodeURIComponent(token));
  }

  function finish() {
    discBtn.hidden = true;
    if (keyboard) { keyboard.reset(); keyboard.onkeydown = keyboard.onkeyup = null; keyboard = null; }
    document.body.classList.remove("live");
    if (failed) { setState("failed", "bad"); say(failed, "bad"); }
    else { setState("closed"); say("Session closed. Connect again, or close this window."); }
    client = null;
  }

  window.addEventListener("resize", function () {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(function () {
      if (!client) return;
      const a = area();
      client.sendSize(a.width, a.height);
    }, 250);
  });

  discBtn.addEventListener("click", function () { if (client) client.disconnect(); });
  document.getElementById("cad").addEventListener("click", function () {
    if (!client) return;
    const keys = [0xFFE3, 0xFFE9, 0xFFFF];            // Control_L, Alt_L, Delete
    keys.forEach(function (k) { client.sendKeyEvent(1, k); });
    keys.slice().reverse().forEach(function (k) { client.sendKeyEvent(0, k); });
    screenEl.focus();
  });
  document.getElementById("paste").addEventListener("click", async function () {
    if (!client) return;
    let text = "";
    try { text = await navigator.clipboard.readText(); } catch (e) { text = window.prompt("Text to send to the remote clipboard:") || ""; }
    if (!text) return;
    const writer = new Guacamole.StringWriter(client.createClipboardStream("text/plain"));
    writer.sendText(text); writer.sendEnd();
    screenEl.focus();
  });
  document.getElementById("full").addEventListener("click", function () {
    if (document.fullscreenElement) document.exitFullscreen(); else document.documentElement.requestFullscreen().catch(function () {});
  });

  if (form) form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    const fd = new FormData(form);
    start({ username: fd.get("username"), password: fd.get("password"), domain: fd.get("domain"),
            security: fd.get("security"), ignore_cert: fd.get("ignore_cert") === "on", save: fd.get("save") === "on" });
    form.querySelector("input[name=password]").value = "";
  });
  const useSaved = document.getElementById("use-saved");
  if (useSaved) useSaved.addEventListener("click", function () { start({ use_saved: true }); });
  window.addEventListener("beforeunload", function () { if (client) client.disconnect(); });
})();
