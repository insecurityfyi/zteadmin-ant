// VisCon1 as an installed app: registers the service worker, offers "Install", and turns alert
// notifications (Web Push) on or off for this device from Your account.
(function () {
  "use strict";
  const swOK = "serviceWorker" in navigator && window.isSecureContext;
  const standalone = () => matchMedia("(display-mode: standalone)").matches || navigator.standalone === true;
  const ios = /iPhone|iPad|iPod/.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
  let installEvent = null;

  if (swOK) {
    window.addEventListener("load", () => {
      navigator.serviceWorker.register("/sw.js", { scope: "/" }).catch(err => console.warn("VisCon1: service worker", err));
    });
  }
  window.addEventListener("beforeinstallprompt", e => { e.preventDefault(); installEvent = e; refreshInstall(); refreshLinks(); });
  window.addEventListener("appinstalled", () => { installEvent = null; refreshInstall(); refreshLinks(); });

  // ---------------------------------------------------------------- "Install app" in the top bar and the user menu
  const safariMac = !ios && /Safari\//.test(navigator.userAgent) && !/Chrome|Chromium|Edg\/|OPR\//.test(navigator.userAgent);
  const firefoxDesktop = /Firefox\//.test(navigator.userAgent) && !/Android|Mobile/.test(navigator.userAgent);
  function refreshLinks() {
    const installed = standalone();
    document.querySelectorAll("[data-install-app]").forEach(a => {
      // shown until the app is installed; the top-bar chip is left out only in desktop Firefox, which can't install
      a.hidden = installed || (!a.hasAttribute("data-install-menu") && firefoxDesktop && !installEvent);
    });
  }
  const shareIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-label="Share"><path d="M12 3v13M7 8l5-5 5 5"/><path d="M5 12v8h14v-8"/></svg>';
  function showSteps() {
    let d = document.getElementById("install-dialog");
    if (!d) {
      d = document.createElement("dialog");
      d.id = "install-dialog";
      d.className = "hv-dialog";
      const steps = ios
        ? `<li>Open this page in <b>Safari</b> (or Chrome).</li><li>Tap ${shareIcon} <b>Share</b> (at the bottom on iPhone, the top on iPad).</li><li>Scroll down and tap <b>Add to Home Screen</b>, then <b>Add</b>.</li><li>Open VisCon1 from its Home Screen icon. Turn on alert notifications from there under Your account.</li>`
        : safariMac
        ? `<li>In the menu bar choose <b>File › Add to Dock</b> (or ${shareIcon} Share › Add to Dock).</li><li>Click <b>Add</b>. VisCon1 opens from the Dock in its own window.</li>`
        : `<li><b>Chrome:</b> menu ⋮ › <b>Cast, save and share › Install page as app</b>, or the install icon at the right of the address bar.</li><li><b>Edge:</b> menu ⋯ › <b>Apps › Install this site as an app</b>.</li><li><b>Android:</b> menu ⋮ › <b>Install app</b> or <b>Add to Home screen</b>.</li><li><b>Firefox</b> on a computer can't install web apps; use Chrome, Edge or Safari.</li>`;
      d.innerHTML = `<h2>Install VisCon1</h2><p class="dim" style="margin:0">It gets its own icon and window, and can show alert notifications.</p><ol class="install-steps">${steps}</ol><form method="dialog" style="display:flex;gap:8px;justify-content:flex-end"><a class="btn" href="/account#app">More on Your account</a><button class="btn pri">OK</button></form>`;
      document.body.appendChild(d);
    }
    if (d.showModal) d.showModal(); else location.href = "/account#app";
  }
  document.addEventListener("click", async e => {
    const a = e.target.closest("[data-install-app]");
    if (!a) return;
    e.preventDefault();
    a.closest("details") && (a.closest("details").open = false);
    if (installEvent) {
      const ev = installEvent;
      installEvent = null;
      ev.prompt();
      try { await ev.userChoice; } catch (err) { /* dismissed */ }
      refreshLinks(); refreshInstall();
      return;
    }
    showSteps();
  });
  document.addEventListener("DOMContentLoaded", refreshLinks);

  const $ = sel => document.querySelector(sel);
  function refreshInstall() {
    const btn = $("[data-pwa-install]"), help = $("[data-pwa-install-help]"), state = $("[data-pwa-install-state]");
    if (!btn) return;
    if (standalone()) {
      state.textContent = "You're using the installed VisCon1 app.";
      btn.hidden = true; help.hidden = true;
      return;
    }
    btn.hidden = false;      // a click installs (Chrome, Edge, Android) or shows the steps for this browser
    if (installEvent) { help.hidden = true; return; }
    help.hidden = false;
    help.textContent = ios
      ? "On iPhone or iPad: open this page in Safari, tap Share, then Add to Home Screen."
      : "Use your browser's menu: Install VisCon1, Install app, or Add to Home screen. In Chrome and Edge it is also the install icon at the right of the address bar.";
  }

  // ---------------------------------------------------------------- notifications
  const b64ToBytes = s => {
    const raw = atob((s + "=".repeat((4 - s.length % 4) % 4)).replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from(raw, c => c.charCodeAt(0));
  };
  const post = (url, body) => fetch(url, {
    method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body)
  }).then(async r => { const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.detail || r.statusText); return j; });

  async function currentSub() {
    const reg = await navigator.serviceWorker.ready;
    return reg.pushManager.getSubscription();
  }

  function initPush() {
    const panel = $("[data-pwa-panel]");
    if (!panel) return;
    refreshInstall();
    const st = $("[data-push-state]"), on = $("[data-push-on]"), off = $("[data-push-off]"), test = $("[data-push-test]");
    const sev = $("[data-push-severity]"), msg = $("[data-push-msg]");
    const say = (text, kind) => { msg.hidden = !text; msg.textContent = text || ""; msg.className = "flash " + (kind || "ok"); };
    const show = (subscribed) => { on.hidden = subscribed; off.hidden = test.hidden = !subscribed; };

    if (!swOK || !("PushManager" in window) || !("Notification" in window)) {
      st.textContent = ios && !standalone()
        ? "On iPhone and iPad, add VisCon1 to your Home Screen first (see above), then open it from there to turn notifications on."
        : "This browser can't receive notifications from VisCon1" + (window.isSecureContext ? "." : " (the page must be served over HTTPS).");
      sev.closest("label").hidden = true;
      return;
    }
    async function refresh() {
      if (Notification.permission === "denied") {
        st.textContent = "Blocked. Allow notifications for this site in your browser or system settings, then reload.";
        show(false); on.hidden = true; return;
      }
      const sub = await currentSub();
      if (!sub) { st.textContent = "Off."; show(false); return; }
      const info = await post("/account/push/status", { endpoint: sub.endpoint }).catch(() => ({}));
      // the browser still has a subscription the server doesn't know (removed from the list, or another account):
      // treat it as off; "Turn on" registers it again
      if (!info.subscribed) { st.textContent = "Off."; show(false); return; }
      sev.value = info.min_severity;
      st.textContent = "On.";
      show(true);
    }
    on.addEventListener("click", async () => {
      say("");
      try {
        if (await Notification.requestPermission() !== "granted") { await refresh(); return; }
        const { publicKey } = await fetch("/account/push/key", { credentials: "same-origin" }).then(r => r.json());
        const reg = await navigator.serviceWorker.ready;
        let sub = await reg.pushManager.getSubscription();
        if (!sub) sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: b64ToBytes(publicKey) });
        await post("/account/push/subscribe", { ...sub.toJSON(), min_severity: sev.value });
        say("Notifications are on for this device. Reload to see it in the list below.");
        await refresh();
      } catch (e) { say("Couldn't turn notifications on: " + e.message, "warn"); }
    });
    off.addEventListener("click", async () => {
      say("");
      const sub = await currentSub();
      if (sub) { await post("/account/push/unsubscribe", { endpoint: sub.endpoint }).catch(() => null); await sub.unsubscribe(); }
      say("Notifications are off for this device.");
      await refresh();
    });
    test.addEventListener("click", async () => {
      say("");
      const sub = await currentSub();
      try { await post("/account/push/test", { endpoint: sub.endpoint }); say("Test sent. It should appear in a few seconds."); }
      catch (e) { say(e.message, "warn"); refresh(); }
    });
    sev.addEventListener("change", async () => {
      const sub = await currentSub();
      if (sub) { await post("/account/push/subscribe", { ...sub.toJSON(), min_severity: sev.value }).catch(e => say(e.message, "warn")); say("Saved."); }
    });
    refresh().catch(e => { st.textContent = "Couldn't check: " + e.message; });
  }
  document.addEventListener("DOMContentLoaded", initPush);
})();
