// Layer 3 (subnets) and Layer 2 (VLANs) maps under the network map, in the same Dark NOC look. No libraries.
// Data: /ui/map/l3 and /ui/map/l2 (layers.py). Bubbles are subnets or VLANs; devices hang off them.
(function () {
  const NS = "http://www.w3.org/2000/svg";
  const el = (t, a, parent) => { const e = document.createElementNS(NS, t); for (const k in a) e.setAttribute(k, a[k]); if (parent) parent.append(e); return e; };
  const NOC = { bg: "#08111c", dot: "#14273a", panel: "#0d1b2a", ink: "#e3edf6", mute: "#7f93a6", pill: "#0b1826", pillLine: "#1c3247",
                up: "#39e58c", warn: "#ffc23d", down: "#ff5a63", off: "#56677a", gw: "#4c9bff" };
  const RING = { up: NOC.up, warn: NOC.warn, down: NOC.down, external: NOC.off, unknown: NOC.off, off: NOC.off };
  const LINK = { gateway: NOC.gw, access: NOC.up, trunk: NOC.warn, host: NOC.off, client: "#3a4d60" };
  const HUES = ["#4c9bff", "#22d3c5", "#8f7cff", "#ff9d4c", "#39e58c", "#ff6fae", "#ffc23d", "#5fd0ff", "#c38cff", "#9be15d"];
  const P = d => ["path", { d }];
  const arrow = (x1, y1, x2, y2) => { const a = Math.atan2(y2 - y1, x2 - x1), h = 3.2;
    return P(`M${x1},${y1}L${x2},${y2}M${x2 - h * Math.cos(a - 0.6)},${y2 - h * Math.sin(a - 0.6)}L${x2},${y2}L${x2 - h * Math.cos(a + 0.6)},${y2 - h * Math.sin(a + 0.6)}`); };
  // the same line symbols as the network map
  const GLYPH = {
    Router: [["ellipse", { cx: 0, cy: 0, rx: 11, ry: 11 }], arrow(-8.5, -2.5, -2, -2.5), arrow(8.5, 2.5, 2, 2.5), arrow(2.5, -8.5, 2.5, -2), arrow(-2.5, 8.5, -2.5, 2)],
    Switch: [["rect", { x: -11, y: -8, width: 22, height: 16, rx: 2 }], arrow(-7, -3, 7, -3), arrow(7, 3, -7, 3)],
    Firewall: [P("M0,-11L9.5,-7V0c0,6 -4.5,9.5 -9.5,11c-5,-1.5 -9.5,-5 -9.5,-11V-7Z"), P("M-4.5,0l3,3L5,-3.5")],
    Wireless: [P("M-8,-1.5a11.3,11.3 0 0 1 16,0"), P("M-4.6,2a6.5,6.5 0 0 1 9.2,0"), ["circle", { cx: 0, cy: 6, r: 1.8, fill: 1 }], P("M-12.5,-5a17,17 0 0 1 25,0")],
    Server: [["rect", { x: -6.5, y: -11, width: 13, height: 22, rx: 1.5 }], P("M-3.5,-6.5H3.5M-3.5,-3H3.5M-3.5,0.5H3.5"), ["circle", { cx: 0, cy: 6.5, r: 1.3, fill: 1 }]],
    Hypervisor: [["rect", { x: -11, y: 5, width: 22, height: 5, rx: 1 }], ["rect", { x: -10, y: -9, width: 5.5, height: 11, rx: 1 }],
                 ["rect", { x: -2.75, y: -9, width: 5.5, height: 11, rx: 1 }], ["rect", { x: 4.5, y: -9, width: 5.5, height: 11, rx: 1 }]],
    Storage: [P("M-9,-7v14a9,3.2 0 0 0 18,0v-14"), ["ellipse", { cx: 0, cy: -7, rx: 9, ry: 3.2 }], P("M-9,0a9,3.2 0 0 0 18,0")],
    Network: [["rect", { x: -11, y: -6, width: 22, height: 12, rx: 2 }], P("M-7,1v2M-3,1v2M1,1v2M5,1v2"), ["circle", { cx: 7.5, cy: -2, r: 1, fill: 1 }]],
  };
  GLYPH.NAS = GLYPH.Storage; GLYPH.VM = GLYPH.Server; GLYPH.Container = GLYPH.Server;
  function glyph(parent, parts, col) {
    const gg = el("g", { fill: "none", stroke: col, "stroke-width": 1.7, "stroke-linecap": "round", "stroke-linejoin": "round" }, parent);
    parts.forEach(([tag, a]) => { const x = Object.assign({}, a); if (x.fill) { x.fill = col; x.stroke = "none"; } el(tag, x, gg); });
  }
  const hue = n => {
    const k = n.kind === "vlan" ? n.vid : n.vlan;
    if (k) return HUES[k % HUES.length];
    let h = 0; for (const c of String(n.name || n.id)) h = (h * 31 + c.charCodeAt(0)) >>> 0;
    return HUES[h % HUES.length];
  };
  const isBubble = n => n.kind === "vlan" || n.kind === "subnet";
  const radius = n => {
    if (n.kind === "client") return 6;
    if (!isBubble(n)) return 23;
    const size = n.kind === "vlan" ? (n.devices || 0) + (n.clients || 0) / 4 : (n.gateways || []).length + (n.hosts || 0) / 3;
    return (n.kind === "subnet" ? 54 : 42) + Math.min(24, Math.sqrt(size) * 6);
  };

  function layout(nodes, links, W, H, iterations, saved) {
    const byId = new Map(nodes.map(n => [n.id, n]));
    const bubbles = nodes.filter(isBubble);
    nodes.forEach((n, i) => {
      const s = saved[n.id];
      if (s) { n.x = s[0]; n.y = s[1]; n.fixed = true; }
      else if (isBubble(n)) {   // bubbles start on a ring, devices near the middle
        const j = bubbles.indexOf(n), a = 2 * Math.PI * j / Math.max(1, bubbles.length);
        n.x = W / 2 + Math.cos(a) * W * 0.3; n.y = H / 2 + Math.sin(a) * H * 0.3;
      } else { n.x = W / 2 + (Math.random() - 0.5) * W * 0.4; n.y = H / 2 + (Math.random() - 0.5) * H * 0.4; }
      n.vx = 0; n.vy = 0;
    });
    const L = links.map(l => ({ a: byId.get(l.source), b: byId.get(l.target), kind: l.kind, label: l.label })).filter(l => l.a && l.b);
    const k = Math.sqrt((W * H) / Math.max(1, nodes.length)) * 0.42;
    for (let it = 0; it < iterations; it++) {
      const t = 1 - it / iterations;
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i];
        for (let j = i + 1; j < nodes.length; j++) {
          const b = nodes[j]; const dx = a.x - b.x, dy = a.y - b.y; const d2 = dx * dx + dy * dy || 0.01;
          const room = radius(a) + radius(b);
          const f = ((k * k) / d2) * (a.kind === "client" && b.kind === "client" ? 0.15 : 1) + (d2 < room * room ? 2.5 : 0);
          a.vx += dx * f * 0.05; a.vy += dy * f * 0.05; b.vx -= dx * f * 0.05; b.vy -= dy * f * 0.05;
        }
      }
      L.forEach(({ a, b, kind }) => {
        const want = kind === "client" ? radius(b) + 26 : radius(a) + radius(b) + 40 + k * 0.6;
        const dx = b.x - a.x, dy = b.y - a.y, d = Math.sqrt(dx * dx + dy * dy) || 0.01, f = (d - want) / d * 0.08;
        a.vx += dx * f; a.vy += dy * f; b.vx -= dx * f; b.vy -= dy * f;
      });
      nodes.forEach(n => {
        n.vx += (W / 2 - n.x) * 0.003; n.vy += (H / 2 - n.y) * 0.003;
        if (!n.fixed) { const sp = Math.hypot(n.vx, n.vy) || 1, m = Math.min(40 * t + 2, sp); n.x += n.vx / sp * m; n.y += n.vy / sp * m; }
        n.vx *= 0.5; n.vy *= 0.5;
      });
    }
    return L;
  }

  function text(parent, x, y, s, a) { const t = el("text", Object.assign({ x, y, "text-anchor": "middle", fill: NOC.ink, "font-size": 12 }, a || {}), parent); t.textContent = s; return t; }
  function pill(parent, x, y, s, col) {
    const g = el("g", { transform: `translate(${x},${y})` }, parent);
    const w = Math.max(24, s.length * 6.3 + 12);
    el("rect", { x: -w / 2, y: -9, width: w, height: 18, rx: 9, fill: NOC.pill, stroke: col || NOC.pillLine, "stroke-width": 1 }, g);
    text(g, 0, 4, s, { "font-size": 11, fill: col ? NOC.ink : NOC.mute, "font-family": "ui-monospace,SFMono-Regular,Menlo,monospace" });
  }

  function setup(svg) {
    const panel = svg.closest(".p");
    const which = svg.dataset.layer, KEY = `lw-layer-${which}-pos`;
    const empty = panel.querySelector("[data-layer-empty]");
    const opts = () => Array.from(panel.querySelectorAll("[data-layer-opt]")).filter(i => i.checked).map(i => `&${i.dataset.layerOpt}=1`).join("");
    let data = null;
    const W = () => svg.clientWidth || 1000, H = () => svg.clientHeight || 640;
    const view = { x: 0, y: 0, s: 1 };
    let root;

    function saved() { try { return JSON.parse(localStorage.getItem(KEY) || "{}"); } catch (e) { return {}; } }
    function save() { try { const pos = {}; data.nodes.forEach(n => { pos[n.id] = [Math.round(n.x), Math.round(n.y)]; }); localStorage.setItem(KEY, JSON.stringify(pos)); } catch (e) { /* storage blocked */ } }

    async function load() {
      try { const r = await fetch(svg.dataset.src + opts(), { credentials: "same-origin" }); data = await r.json(); }
      catch (e) { svg.replaceChildren(); text(svg, W() / 2, 60, "Could not load this map.", { fill: NOC.mute }); return; }
      const none = !data.nodes.length;
      svg.hidden = none; empty.hidden = !none;
      if (!none) draw(true);
    }

    function draw(keep) {
      const w = W(), h = H();
      svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
      svg.replaceChildren();
      const defs = el("defs", {}, svg);
      const glow = el("filter", { id: `glow-${which}`, x: "-50%", y: "-50%", width: "200%", height: "200%" }, defs);
      el("feGaussianBlur", { stdDeviation: 4, result: "b" }, glow);
      const fm = el("feMerge", {}, glow); el("feMergeNode", { in: "b" }, fm); el("feMergeNode", { in: "SourceGraphic" }, fm);
      const dots = el("pattern", { id: `dots-${which}`, width: 28, height: 28, patternUnits: "userSpaceOnUse" }, defs);
      el("circle", { cx: 1, cy: 1, r: 1, fill: NOC.dot }, dots);
      el("rect", { x: -w, y: -h, width: 3 * w, height: 3 * h, fill: NOC.bg }, svg);
      el("rect", { x: -w, y: -h, width: 3 * w, height: 3 * h, fill: `url(#dots-${which})` }, svg);
      root = el("g", {}, svg);
      const gl = el("g", {}, root), glab = el("g", {}, root), gn = el("g", {}, root);
      const L = layout(data.nodes, data.links, w, h, keep ? 300 : 450, keep ? saved() : {});
      const lines = [];
      L.forEach(l => {
        const col = LINK[l.kind] || NOC.off;
        const ln = el("line", { stroke: col, "stroke-width": l.kind === "client" ? 1 : l.kind === "host" ? 1.4 : 2.2, "stroke-opacity": l.kind === "client" ? 0.7 : 0.9,
          "stroke-dasharray": l.kind === "host" || l.kind === "client" ? "5 5" : "" }, gl);
        lines.push({ ln, l, label: l.label, col });
      });
      function place() {
        lines.forEach(({ ln, l }) => { ln.setAttribute("x1", l.a.x); ln.setAttribute("y1", l.a.y); ln.setAttribute("x2", l.b.x); ln.setAttribute("y2", l.b.y); });
        glab.replaceChildren();
        lines.forEach(({ l, label, col }) => {
          if (!label) return;
          // centre the label in the visible part of the line, between the two node edges
          const dx = l.b.x - l.a.x, dy = l.b.y - l.a.y, d = Math.hypot(dx, dy) || 1;
          const t = (radius(l.a) + (d - radius(l.a) - radius(l.b)) / 2) / d;
          pill(glab, l.a.x + dx * t, l.a.y + dy * t, label.length > 34 ? label.slice(0, 33) + "…" : label, l.kind === "gateway" || l.kind === "trunk" || l.kind === "access" ? col : null);
        });
        data.nodes.forEach(n => n.g && n.g.setAttribute("transform", `translate(${n.x},${n.y})`));
      }
      data.nodes.forEach(n => {
        const g = el("g", { style: "cursor:pointer" }, gn); n.g = g;
        const title = el("title", {}, g);
        if (isBubble(n)) {
          const col = hue(n), r = radius(n);
          el("circle", { r, fill: col, "fill-opacity": 0.12, stroke: col, "stroke-width": 2, filter: `url(#glow-${which})` }, g);
          el("circle", { r: r - 6, fill: "none", stroke: col, "stroke-opacity": 0.35, "stroke-dasharray": "2 5" }, g);
          if (n.kind === "vlan") {
            text(g, 0, -10, n.name || "VLAN", { "font-weight": 700, "font-size": 13 });
            text(g, 0, 10, n.vid ? `VLAN ${n.vid}` : "untagged", { fill: col, "font-weight": 700, "font-size": 15 });
            const sub = (n.subnets || [])[0];
            text(g, 0, 27, sub || (n.clients ? `${n.clients} client${n.clients === 1 ? "" : "s"}` : `${n.devices} device${n.devices === 1 ? "" : "s"}`), { fill: NOC.mute, "font-size": 11 });
            title.textContent = [`${n.name || "VLAN"}${n.vid ? " · VLAN " + n.vid : ""}`, (n.subnets || []).length ? "Subnets: " + n.subnets.join(", ") : "",
              (n.ssids || []).length ? "SSIDs: " + n.ssids.join(", ") : "", `${n.devices} device(s), ${n.clients} client(s)`].filter(Boolean).join("\n");
          } else {
            text(g, 0, -8, n.name, { "font-weight": 700, "font-size": 13, "font-family": "ui-monospace,SFMono-Regular,Menlo,monospace" });
            text(g, 0, 11, n.vlan ? `VLAN ${n.vlan}${n.label ? " · " + n.label : ""}` : (n.label || "subnet"), { fill: col, "font-weight": 600, "font-size": 12 });
            if (n.hosts) text(g, 0, 28, `${n.hosts} more host${n.hosts === 1 ? "" : "s"}`, { fill: NOC.mute, "font-size": 11 });
            title.textContent = [n.name, n.vlan ? `VLAN ${n.vlan}` : "", n.label || "", "Gateway: " + (n.gateways || []).join(", "),
              (n.host_names || []).length ? "Hosts: " + n.host_names.join(", ") + (n.hosts > n.host_names.length ? "…" : "") : ""].filter(Boolean).join("\n");
          }
        } else if (n.kind === "client") {
          const s = n.signal, col = n.wired || s == null ? "#8aa0b4" : s >= -67 ? NOC.up : s >= -75 ? NOC.warn : NOC.down;
          el("circle", { r: 5.5, fill: col, stroke: NOC.bg, "stroke-width": 1.5 }, g);
          title.textContent = [n.name, n.ip, n.wired ? "wired" : (n.ssid ? `${n.ssid}${s != null ? ", " + s + " dBm" : ""}` : "wireless")].filter(Boolean).join("\n");
        } else {
          const ring = RING[n.status] || NOC.off;
          el("circle", { r: 23, fill: NOC.panel, stroke: ring, "stroke-width": 2.5, filter: `url(#glow-${which})` }, g);
          glyph(g, GLYPH[n.type] || GLYPH.Network, NOC.ink);
          text(g, 0, 40, n.name, { "font-size": 12, "font-weight": 600 });
          if (n.ip) text(g, 0, 54, n.ip, { "font-size": 10.5, fill: NOC.mute, "font-family": "ui-monospace,SFMono-Regular,Menlo,monospace" });
          title.textContent = [n.name, n.type, n.ip, n.status].filter(Boolean).join(" · ");
        }
        drag(g, n, place);
      });
      place();
      apply();
      if (!keep || !Object.keys(saved()).length) fit();
    }

    function apply() { if (root) root.setAttribute("transform", `translate(${view.x},${view.y}) scale(${view.s})`); }
    function pt(e) { const r = svg.getBoundingClientRect(); return { x: (e.clientX - r.left) * (W() / r.width), y: (e.clientY - r.top) * (H() / r.height) }; }
    function drag(g, n, place) {
      let start = null, moved = false;
      g.addEventListener("pointerdown", e => { e.stopPropagation(); g.setPointerCapture(e.pointerId); start = pt(e); moved = false; });
      g.addEventListener("pointermove", e => {
        if (!start) return; const p = pt(e);
        if (!moved && Math.hypot(p.x - start.x, p.y - start.y) < 4) return;
        moved = true; n.x = (p.x - view.x) / view.s; n.y = (p.y - view.y) / view.s; n.fixed = true; place();
      });
      g.addEventListener("pointerup", () => {
        if (!start) return; start = null;
        if (moved) save();
        else if (n.kind === "device" && /^\d+$/.test(String(n.id))) window.location.href = `/devices/${n.id}`;
      });
    }
    function fit() {
      if (!data || !data.nodes.length) return;
      const xs = data.nodes.flatMap(n => [n.x - radius(n), n.x + radius(n)]), ys = data.nodes.flatMap(n => [n.y - radius(n), n.y + radius(n) + 30]);
      const x0 = Math.min(...xs), x1 = Math.max(...xs), y0 = Math.min(...ys), y1 = Math.max(...ys);
      const s = Math.min(1.6, (W() - 40) / Math.max(1, x1 - x0), (H() - 70) / Math.max(1, y1 - y0));
      view.s = s; view.x = W() / 2 - (x0 + x1) / 2 * s; view.y = (H() + 30) / 2 - (y0 + y1) / 2 * s; apply();
    }
    // pan and zoom
    let pan = null;
    svg.addEventListener("pointerdown", e => { pan = { p: pt(e), x: view.x, y: view.y }; svg.setPointerCapture(e.pointerId); svg.style.cursor = "grabbing"; });
    svg.addEventListener("pointermove", e => { if (!pan) return; const p = pt(e); view.x = pan.x + p.x - pan.p.x; view.y = pan.y + p.y - pan.p.y; apply(); });
    svg.addEventListener("pointerup", () => { pan = null; svg.style.cursor = "grab"; });
    svg.addEventListener("wheel", e => {
      e.preventDefault(); const p = pt(e), f = Math.exp(-e.deltaY * 0.0015), s = Math.min(4, Math.max(0.15, view.s * f));
      view.x = p.x - (p.x - view.x) * (s / view.s); view.y = p.y - (p.y - view.y) * (s / view.s); view.s = s; apply();
    }, { passive: false });
    panel.querySelector("[data-layer-fit]").addEventListener("click", fit);
    panel.querySelector("[data-layer-relayout]").addEventListener("click", () => {
      try { localStorage.removeItem(KEY); } catch (e) { /* storage blocked */ }
      if (data) { data.nodes.forEach(n => { n.fixed = false; }); draw(false); }
    });
    panel.querySelectorAll("[data-layer-opt]").forEach(i => {
      try { i.checked = localStorage.getItem(`${KEY}-${i.dataset.layerOpt}`) === "1"; } catch (e) { /* storage blocked */ }
      i.addEventListener("change", () => { try { localStorage.setItem(`${KEY}-${i.dataset.layerOpt}`, i.checked ? "1" : "0"); } catch (e) { /* storage blocked */ } load(); });
    });
    load();
  }

  function init() { document.querySelectorAll("svg.layer-map").forEach(setup); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
})();
