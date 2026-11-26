// Small SVG line charts. Each <div class="fig" data-src="/ui/metrics/..." data-series='[...]'> is filled in on load.
(function () {
  const NS = "http://www.w3.org/2000/svg";
  const el = (t, a) => { const e = document.createElementNS(NS, t); for (const k in a) e.setAttribute(k, a[k]); return e; };
  const nice = m => { if (m <= 0) return 1; const p = Math.pow(10, Math.floor(Math.log10(m))); const f = m / p; return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10) * p; };
  const fmt = {
    pct: v => Math.round(v) + "%",
    ms: v => (v === 0 ? "0" : v < 1 ? v.toFixed(2) : v < 10 ? v.toFixed(1) : Math.round(v)) + " ms",
    bps: v => { const u = ["b/s", "k", "M", "G", "T"]; let i = 0; while (v >= 1000 && i < 4) { v /= 1000; i++; } return (v < 10 && i ? v.toFixed(1) : Math.round(v)) + (i ? u[i] : " " + u[0]); },
    num: v => String(Math.round(v)),
    dbm: v => Math.round(v) + " dBm",
    bytes: v => { const u = ["B", "kB", "MB", "GB", "TB", "PB"]; let i = 0; while (v >= 1000 && i < 5) { v /= 1000; i++; } return (v < 10 && i ? v.toFixed(1) : Math.round(v)) + " " + u[i]; },
  };

  function draw(host, data, series, opts) {
    const ts = data.ts.map(t => Date.parse(t));
    if (ts.length < 2) { host.innerHTML = '<div class="empty">Not enough data yet. Graphs fill in after a few polls.</div>'; return; }
    const W = Math.max(280, host.clientWidth || 600), H = +(opts.h || 160), L = 52, R = 10, T = 8, B = 22;
    const vals = series.flatMap(s => data[s.key].filter(v => v != null));
    const min = opts.min ? +opts.min : 0;
    let max = opts.max ? +opts.max : nice((Math.max(0, ...vals) || 1) * 1.1);
    if (!opts.max && (opts.unit || "num") === "num" && !opts.suffix && max < 40) max = Math.max(4, Math.ceil(max / 4) * 4);   // whole-number ticks for counts
    const t0 = ts[0], t1 = ts[ts.length - 1] === t0 ? t0 + 1 : ts[ts.length - 1];
    const x = t => L + (W - L - R) * (t - t0) / (t1 - t0), y = v => T + (H - T - B) * (1 - (v - min) / (max - min));
    const f = opts.suffix ? (v => (Math.abs(v) < 10 && v !== 0 ? v.toFixed(1) : Math.round(v)) + " " + opts.suffix) : fmt[opts.unit || "num"];
    const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": opts.label || "chart" });
    for (let k = 0; k <= 4; k++) {
      const v = min + (max - min) * k / 4, yy = y(v);
      svg.append(el("line", { x1: L, x2: W - R, y1: yy, y2: yy, class: "gl" }));
      const t = el("text", { x: L - 6, y: yy + 3.5, "text-anchor": "end", class: "ax" }); t.textContent = f(v); svg.append(t);
    }
    const span = t1 - t0, ticks = W < 520 ? 2 : 4;
    for (let k = 0; k <= ticks; k++) {
      const tt = t0 + span * k / ticks, d = new Date(tt);
      const label = span > 2 * 86400e3 ? d.toLocaleDateString([], { day: "numeric", month: "short" }) : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
      const t = el("text", { x: x(tt), y: H - 5, "text-anchor": k === 0 ? "start" : k === ticks ? "end" : "middle", class: "ax" });
      t.textContent = label; svg.append(t);
    }
    series.forEach(s => {
      const segs = []; let cur = [];
      data[s.key].forEach((v, i) => { if (v == null) { if (cur.length) segs.push(cur); cur = []; } else cur.push([x(ts[i]), y(Math.max(min, Math.min(v, max)))]); });
      if (cur.length) segs.push(cur);
      segs.forEach(seg => {
        const d = seg.map(p => p[0].toFixed(1) + "," + p[1].toFixed(1)).join("L");
        if (s.area !== false && !s.dash) svg.append(el("path", { d: `M${seg[0][0]},${y(min)}L${d}L${seg[seg.length - 1][0]},${y(min)}Z`, fill: s.color, "fill-opacity": .12 }));
        svg.append(el("path", { d: "M" + d, fill: "none", stroke: s.color, "stroke-width": 1.6, "stroke-linejoin": "round", "stroke-dasharray": s.dash ? "4 3" : "" }));
      });
      const last = segs.length ? segs[segs.length - 1].slice(-1)[0] : null;
      if (last) svg.append(el("circle", { cx: last[0], cy: last[1], r: 3, fill: s.color }));
    });
    host.replaceChildren(svg);
  }

  async function load(host) {
    const series = JSON.parse(host.dataset.series);
    const rng = host.dataset.range || "24h";
    try {
      const r = await fetch(host.dataset.src + "?range=" + encodeURIComponent(rng), { credentials: "same-origin" });
      if (!r.ok) throw new Error(r.status);
      host._data = await r.json();
      draw(host, host._data, series, host.dataset);
    } catch (e) { host.innerHTML = '<div class="empty">Could not load graph data.</div>'; }
  }

  function all() { document.querySelectorAll(".fig[data-src]").forEach(load); }
  window.lwCharts = { reload: all, load };
  document.addEventListener("DOMContentLoaded", () => {
    all();
    document.querySelectorAll("[data-range-set]").forEach(b => b.addEventListener("click", () => {
      document.querySelectorAll("[data-range-set]").forEach(o => o.setAttribute("aria-pressed", o === b));
      document.querySelectorAll(".fig[data-src]").forEach(f => { f.dataset.range = b.dataset.rangeSet; load(f); });
    }));
    let t; window.addEventListener("resize", () => { clearTimeout(t); t = setTimeout(() => document.querySelectorAll(".fig[data-src]").forEach(f => { if (f._data) draw(f, f._data, JSON.parse(f.dataset.series), f.dataset); }), 150); });
  });
})();
