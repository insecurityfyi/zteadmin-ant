// Wireless dashboard: filter every table by site, SSID, band, channel, AP and search; recompute the KPIs from what is
// visible; point the history graphs at the most specific roll-up (AP, then channel, SSID or band). Filters live in the URL.
(function () {
  const root = document.getElementById("wl");
  if (!root) return;
  const iid = root.dataset.iid;
  const F = {};
  const ctl = {};
  root.querySelectorAll("[data-f]").forEach(e => { ctl[e.dataset.f] = e; });
  const clear = root.querySelector("[data-f-clear]");
  const scopeNote = root.querySelector(".wl-scope");
  const num = v => (v === "" || v == null ? null : +v);
  const avg = a => a.length ? a.reduce((x, y) => x + y, 0) / a.length : null;
  const setK = (k, text, cls) => { const e = root.querySelector(`[data-k="${k}"]`); if (!e) return; e.textContent = text; if (cls !== undefined) e.className = cls; };

  function read() {
    for (const k in ctl) F[k] = ctl[k].type === "checkbox" ? ctl[k].checked : ctl[k].value.trim();
  }
  function fromUrl() {
    const p = new URLSearchParams(location.search);
    for (const k in ctl) {
      const v = p.get(k); if (v == null) continue;
      if (ctl[k].type === "checkbox") ctl[k].checked = v === "1"; else ctl[k].value = v;
    }
  }
  function toUrl() {
    const p = new URLSearchParams(location.search);
    for (const k in ctl) { const v = F[k]; if (v === true) p.set(k, "1"); else if (v) p.set(k, v); else p.delete(k); }
    history.replaceState(null, "", location.pathname + (p.toString() ? "?" + p : ""));
  }

  function match(tr, table) {
    const d = tr.dataset;
    if (F.site && d.site !== undefined && d.site !== F.site) return false;
    if (F.problems && !d.problem) return false;
    if (table === "ssids") {
      if (F.ssid && d.ssid !== F.ssid) return false;
      if (F.ap && d.aps !== undefined) { const ap = ctl.ap.selectedOptions[0]?.text; if (!d.aps.split("|").includes(ap)) return false; }
      return true;
    }
    if (F.ssid) { if (d.ssids !== undefined) { if (!d.ssids.split("|").includes(F.ssid)) return false; } else if (d.ssid !== undefined && d.ssid !== F.ssid) return false; }
    if (F.band && d.band !== undefined && d.band !== F.band) return false;
    if (F.ch && d.ch !== undefined && d.ch !== F.ch) return false;
    if (F.ap && d.ap !== undefined && d.ap !== F.ap) return false;
    if (F.q && table === "clients" && !(d.q || "").includes(F.q.toLowerCase())) return false;
    return true;
  }

  function scope() {
    if (F.ap) return ["ap:" + F.ap, "access point " + ctl.ap.selectedOptions[0].text];
    if (F.ch) return ["chan:" + F.ch, "channel " + F.ch.split("/")[1] + " (" + F.ch.split("/")[0] + ")"];
    if (F.ssid) return ["ssid:" + F.ssid, "SSID " + F.ssid];
    if (F.band) return ["band:" + F.band, F.band];
    return ["all", ""];
  }

  function apply() {
    read(); toUrl();
    const vis = {};
    root.querySelectorAll("[data-wtable]").forEach(box => {
      const t = box.dataset.wtable; let n = 0; vis[t] = [];
      box.querySelectorAll("tbody tr[data-site], tbody tr[data-ssid]").forEach(tr => { const ok = match(tr, t); tr.hidden = !ok; if (ok) { n++; vis[t].push(tr); } });
      const c = box.querySelector("[data-count]"); if (c) c.textContent = n;
    });
    root.querySelectorAll(".p:not([data-wtable]) tbody tr[data-ap]").forEach(tr => { tr.hidden = !!(F.ap && tr.dataset.ap !== F.ap) || !!(F.ssid && tr.dataset.ssid !== undefined && tr.dataset.ssid !== F.ssid); });
    root.querySelectorAll("[data-ch-pick]").forEach(b => {
      const [band] = b.dataset.chPick.split("/");
      b.setAttribute("aria-pressed", b.dataset.chPick === F.ch);
      b.classList.toggle("off", !!((F.band && band !== F.band) || (F.ch && b.dataset.chPick !== F.ch)));
    });
    const active = Object.values(F).some(Boolean);
    if (clear) clear.hidden = !active;

    // KPIs from the visible clients and radios
    const cl = vis.clients || [], rd = vis.radios || [];
    const rssi = cl.map(r => num(r.dataset.rssi)).filter(v => v != null);
    const snr = cl.map(r => num(r.dataset.snr)).filter(v => v != null);
    const retry = cl.map(r => num(r.dataset.retry)).filter(v => v != null);
    const util = rd.map(r => num(r.dataset.util)).filter(v => v != null);
    const T = { good: -67, retryBad: 15, utilBad: 60 };
    setK("clients", String(cl.length));
    const bands = {}; cl.forEach(r => { const b = r.dataset.band; if (b) bands[b] = (bands[b] || 0) + 1; });
    setK("bands", Object.entries(bands).map(([b, n]) => `${n} on ${b}`).join(" · "));
    const a = avg(rssi); setK("signal", a == null ? "–" : Math.round(a) + " dBm");
    setK("good", rssi.length ? Math.round(100 * rssi.filter(v => v >= T.good).length / rssi.length) + "% at -67 dBm or better" : "");
    const s = avg(snr); setK("snr", s == null ? "–" : Math.round(s) + " dB");
    const rt = avg(retry); setK("retry", rt == null ? "–" : rt.toFixed(1) + "%");
    const hi = retry.filter(v => v > T.retryBad).length; setK("hiretry", `${hi} client${hi === 1 ? "" : "s"} above 15%`);
    const weak = rssi.filter(v => v < T.good).length; setK("weak", String(weak), weak ? "wa" : "");
    const cong = util.filter(v => v >= T.utilBad).length; setK("cong", `${cong} / ${rd.length}`, cong ? "bad" : "");
    setK("util", util.length ? `average ${Math.round(avg(util))}% busy, busiest ${Math.round(Math.max(...util))}%` : "");
    const st = cl.filter(r => r.dataset.sticky).length; setK("sticky", String(st), st ? "wa" : "");

    // graphs
    const [key, label] = scope();
    root.querySelectorAll(".fig[data-wkey]").forEach(f => {
      let k = key;
      if (f.dataset.wkey === "wev") k = key.startsWith("ssid:") ? key.slice(5) : "all";
      const src = `/ui/metrics/integration/${iid}/${encodeURIComponent(f.dataset.wkey + ":" + k)}`;
      if (f.dataset.src !== src) { f.dataset.src = src; if (window.lwCharts) window.lwCharts.load(f); }
    });
    if (scopeNote) scopeNote.textContent = (active ? "Filtered. " : "Showing everything. ") +
      (label ? `Graphs show ${label}.` : "Graphs follow the most specific filter: access point, then channel, SSID or band.") +
      (F.ap && (F.ssid || F.band || F.ch) ? " (Graphs can show one filter at a time; the tables and figures above use them all.)" : "");
  }

  fromUrl();
  for (const k in ctl) ctl[k].addEventListener(ctl[k].type === "search" ? "input" : "change", apply);
  if (clear) clear.addEventListener("click", () => { for (const k in ctl) { if (ctl[k].type === "checkbox") ctl[k].checked = false; else ctl[k].value = ""; } apply(); });
  root.querySelectorAll("[data-ch-pick]").forEach(b => b.addEventListener("click", () => {
    ctl.ch.value = ctl.ch.value === b.dataset.chPick ? "" : b.dataset.chPick; apply();
  }));

  // sortable columns
  root.querySelectorAll("[data-wtable]").forEach(box => {
    const tb = box.querySelector("tbody");
    box.querySelectorAll("th[data-sort]").forEach((th, _, all) => {
      th.style.cursor = "pointer"; th.title = "Sort";
      th.addEventListener("click", () => {
        const i = [...th.parentNode.children].indexOf(th), isNum = th.dataset.sort === "num";
        const dir = th.dataset.dir === "desc" ? "asc" : "desc"; all.forEach(o => delete o.dataset.dir); th.dataset.dir = dir;
        const rows = [...tb.querySelectorAll("tr")].sort((x, y) => {
          const p = x.children[i], q = y.children[i]; if (!p || !q) return 0;
          const r = isNum ? (+p.dataset.v || 0) - (+q.dataset.v || 0) : p.textContent.trim().localeCompare(q.textContent.trim());
          return dir === "desc" ? -r : r;
        });
        tb.append(...rows);
      });
    });
  });
  // charts.js loads every .fig on DOMContentLoaded; set the right sources before that if a filter came from the URL
  apply();
})();
