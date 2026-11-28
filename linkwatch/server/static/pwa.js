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
  window.addEventListener("beforeinstallprompt", e => { e.preventDefault(); installEvent = e; refreshInstall(); });
  window.addEventListener("appinstalled", () => { installEvent = null; refreshInstall(); });

  const $ = sel => document.querySelector(sel);
  function refreshInstall() {
    const btn = $("[data-pwa-install]"), help = $("[data-pwa-install-help]"), state = $("[data-pwa-install-state]");
    if (!btn) return;
    if (standalone()) {
      state.textContent = "You're using the installed VisCon1 app.";
      btn.hidden = true; help.hidden = true;
      return;
    }
    btn.hidden = !installEvent;
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
