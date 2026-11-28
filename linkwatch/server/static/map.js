// Network map: a small force-directed layout drawn in SVG. No libraries.
(function () {
  const NS = "http://www.w3.org/2000/svg";
  const el = (t, a, parent) => { const e = document.createElementNS(NS, t); for (const k in a) e.setAttribute(k, a[k]); if (parent) parent.append(e); return e; };
  const css = v => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
  const STATUS = { up: "--up", warn: "--warn", down: "--down", external: "--off", unknown: "--off", off: "--off" };
  // Dark NOC look: the map is always drawn on a dark wall-screen background, whatever the page theme.
  const NOC = { bg: "#08111c", dot: "#14273a", panel: "#0d1b2a", ink: "#e3edf6", mute: "#7f93a6", pill: "#0b1826", pillLine: "#1c3247",
                up: "#39e58c", warn: "#ffc23d", down: "#ff5a63", off: "#56677a", idle: "#2a3d50", wanLine: "#1e6f99", wanInk: "#bfe9ff" };
  const RING = { up: NOC.up, warn: NOC.warn, down: NOC.down, external: NOC.off, unknown: NOC.off, off: NOC.off };
  const ROLE = { Router: "#2f6fde", Firewall: "#d9483b", Switch: "#139a8c", Wireless: "#7c4dd8", Hypervisor: "#e07b16", NAS: "#3d8b3d",
                 Storage: "#3d8b3d", Server: "#56677a" };
  const ISP_RING = { fiber: ["#4c9bff", "#8dc0ff"], cable: ["#22d3c5", "#5ff0e3"], satellite: ["#8f7cff", "#b6a9ff"],
                     cellular: ["#ff9d4c", "#ffc08d"], globe: ["#4cc3ff", "#a6e3ff"] };
  // Network-diagram style symbols, drawn here (no stencil artwork): line art in a 24 px box centred on 0,0.
  // Each is a list of [tag, attrs]; "fill" marks solid parts, everything else is stroked in the status colour.
  const P = d => ["path", { d }];
  const arrow = (x1, y1, x2, y2) => { const a = Math.atan2(y2 - y1, x2 - x1), h = 3.2;
    return P(`M${x1},${y1}L${x2},${y2}M${x2 - h * Math.cos(a - 0.6)},${y2 - h * Math.sin(a - 0.6)}L${x2},${y2}L${x2 - h * Math.cos(a + 0.6)},${y2 - h * Math.sin(a + 0.6)}`); };
  const GLYPH = {
    // router: a disc with arrows in and out on both axes
    Router: [["ellipse", { cx: 0, cy: 0, rx: 11, ry: 11 }], arrow(-8.5, -2.5, -2, -2.5), arrow(8.5, 2.5, 2, 2.5), arrow(2.5, -8.5, 2.5, -2), arrow(-2.5, 8.5, -2.5, 2)],
    // switch: a box with arrows running both ways
    Switch: [["rect", { x: -11, y: -8, width: 22, height: 16, rx: 2 }], arrow(-7, -3, 7, -3), arrow(7, 3, -7, 3)],
    // firewall: a brick wall
    // firewall: a shield
    Firewall: [P("M0,-11L9.5,-7V0c0,6 -4.5,9.5 -9.5,11c-5,-1.5 -9.5,-5 -9.5,-11V-7Z"), P("M-4.5,0l3,3L5,-3.5")],
    // wireless access point: a puck sending waves
    Wireless: [P("M-8,-1.5a11.3,11.3 0 0 1 16,0"), P("M-4.6,2a6.5,6.5 0 0 1 9.2,0"), ["circle", { cx: 0, cy: 6, r: 1.8, fill: 1 }], P("M-12.5,-5a17,17 0 0 1 25,0")],
    // server: a tower with drive bays
    Server: [["rect", { x: -6.5, y: -11, width: 13, height: 22, rx: 1.5 }], P("M-3.5,-6.5H3.5M-3.5,-3H3.5M-3.5,0.5H3.5"), ["circle", { cx: 0, cy: 6.5, r: 1.3, fill: 1 }]],
    // hypervisor: a host carrying guest boxes
    Hypervisor: [["rect", { x: -11, y: 5, width: 22, height: 5, rx: 1 }], ["rect", { x: -10, y: -9, width: 5.5, height: 11, rx: 1 }],
                 ["rect", { x: -2.75, y: -9, width: 5.5, height: 11, rx: 1 }], ["rect", { x: 4.5, y: -9, width: 5.5, height: 11, rx: 1 }]],
    // storage / NAS: a disk stack
    Storage: [P("M-9,-7v14a9,3.2 0 0 0 18,0v-14"), ["ellipse", { cx: 0, cy: -7, rx: 9, ry: 3.2 }], P("M-9,0a9,3.2 0 0 0 18,0")],
    Printer: [P("M-6,-4V-10H6V-4"), ["rect", { x: -10, y: -4, width: 20, height: 9, rx: 1.5 }], P("M-6,2V9H6V2")],
    Camera: [["rect", { x: -10, y: -6, width: 15, height: 11, rx: 2 }], P("M5,-2L10,-5V4L5,1"), ["circle", { cx: -2.5, cy: -0.5, r: 2.6 }]],
    Power: [P("M2,-11L-7,1H0L-2,11L7,-1H0Z")],
    // anything else: a generic box with ports
    Network: [["rect", { x: -11, y: -6, width: 22, height: 12, rx: 2 }], P("M-7,1v2M-3,1v2M1,1v2M5,1v2"), ["circle", { cx: 7.5, cy: -2, r: 1, fill: 1 }]],
  };
  GLYPH.NAS = GLYPH.Storage;
  // ISP circles: a glyph for how the line arrives
  const ISP_GLYPH = {
    satellite: [["rect", { x: -3.5, y: -3.5, width: 7, height: 7, rx: 1, transform: "rotate(-45)" }],
                ["rect", { x: -13, y: -2.5, width: 7, height: 5, transform: "rotate(-45)" }], ["rect", { x: 6, y: -2.5, width: 7, height: 5, transform: "rotate(-45)" }],
                P("M3.5,6a5,5 0 0 0 4,-4M3,10.5a9,9 0 0 0 8,-8")],
    fiber: [P("M-11,4C-5,4 -5,-4 0,-4S5,4 11,4"), P("M-11,-1C-5,-1 -4,-8 1,-8S6,-1 11,-1"), ["circle", { cx: 11, cy: 4, r: 1.6, fill: 1 }], ["circle", { cx: 11, cy: -1, r: 1.6, fill: 1 }]],
    cable: [["circle", { cx: 0, cy: 0, r: 8 }], ["circle", { cx: 0, cy: 0, r: 4 }], ["circle", { cx: 0, cy: 0, r: 1.2, fill: 1 }]],
    cellular: [P("M0,-2V10M-4,10H4"), ["circle", { cx: 0, cy: -4, r: 1.8, fill: 1 }], P("M-5,-9a7,7 0 0 0 0,10M5,-9a7,7 0 0 1 0,10M-8.5,-12a12,12 0 0 0 0,16M8.5,-12a12,12 0 0 1 0,16")],
    globe: [["circle", { cx: 0, cy: 0, r: 10 }], ["ellipse", { cx: 0, cy: 0, rx: 4.5, ry: 10 }], P("M-10,0H10M-8.5,-5H8.5M-8.5,5H8.5")],
  };
  function glyph(parent, parts, col, scale) {
    const gg = el("g", { fill: "none", stroke: col, "stroke-width": 1.7 / (scale || 1), "stroke-linecap": "round", "stroke-linejoin": "round",
      transform: scale ? `scale(${scale})` : "" }, parent);
    parts.forEach(([tag, a]) => { const x = Object.assign({}, a); if (x.fill) { x.fill = col; x.stroke = "none"; } el(tag, x, gg); });
  }
  const fmtBps = v => { const u = ["b/s", "kb/s", "Mb/s", "Gb/s", "Tb/s"]; let i = 0; while (v >= 1000 && i < 4) { v /= 1000; i++; } return (v < 10 && i ? v.toFixed(1) : Math.round(v)) + " " + u[i]; };
  const KEY = "lw-map-pos";

  function layout(nodes, links, W, H, iterations, keep) {
    const byId = new Map(nodes.map(n => [n.id, n]));
    let saved = {};
    try { saved = JSON.parse(localStorage.getItem(KEY) || "{}"); } catch (e) { saved = {}; }
    nodes.forEach((n, i) => {
      const s = keep && saved[n.id];
      if (s) { n.x = s[0]; n.y = s[1]; n.fixed = true; }
      else if (n.isp) { n.x = W / 2 + (i % 5 - 2) * 140; n.y = 50; }
      else { const a = 2 * Math.PI * i / Math.max(1, nodes.length); n.x = W / 2 + Math.cos(a) * W / 3 + Math.random() * 20; n.y = H / 2 + Math.sin(a) * H / 3 + Math.random() * 20; }
      n.vx = 0; n.vy = 0;
    });
    // WAN uplinks get a longer spring so the Internet cloud sits clear of its gateway and the labels have room
    const L = links.map(l => ({ a: byId.get(l.source), b: byId.get(l.target), len: l.protocol === "wan" ? 2.4 : 1.35 })).filter(l => l.a && l.b);
    const k = Math.sqrt((W * H) / Math.max(1, nodes.length)) * 0.75;
    for (let it = 0; it < iterations; it++) {
      const t = 1 - it / iterations;
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i];
        for (let j = i + 1; j < nodes.length; j++) {
          const b = nodes[j]; let dx = a.x - b.x, dy = a.y - b.y; let d2 = dx * dx + dy * dy || 0.01;
          const f = (k * k) / d2; a.vx += dx * f * 0.05; a.vy += dy * f * 0.05; b.vx -= dx * f * 0.05; b.vy -= dy * f * 0.05;
        }
      }
      L.forEach(({ a, b, len }) => {
        const dx = b.x - a.x, dy = b.y - a.y, d = Math.sqrt(dx * dx + dy * dy) || 0.01, f = (d - k * len) / d * 0.08;
        a.vx += dx * f; a.vy += dy * f; b.vx -= dx * f; b.vy -= dy * f;
      });
      nodes.forEach(n => {
        n.vx += (W / 2 - n.x) * 0.002; n.vy += (H / 2 - n.y) * 0.002;
        if (!n.fixed) { const m = Math.min(40 * t + 2, Math.hypot(n.vx, n.vy)); const s = Math.hypot(n.vx, n.vy) || 1; n.x += n.vx / s * m; n.y += n.vy / s * m; }
        n.vx *= 0.5; n.vy *= 0.5;
      });
    }
    // the forces can push a small map far beyond the view, so Fit would shrink every node: pull free nodes back in
    const free = nodes.filter(n => !n.fixed);
    if (free.length > 1) {
      const xs = free.map(n => n.x), ys = free.map(n => n.y);
      const x0 = Math.min(...xs), x1 = Math.max(...xs), y0 = Math.min(...ys), y1 = Math.max(...ys);
      const f = Math.min(1, (W - 160) / Math.max(1, x1 - x0), (H - 120) / Math.max(1, y1 - y0));
      if (f < 1) free.forEach(n => { n.x = W / 2 + (n.x - (x0 + x1) / 2) * f; n.y = H / 2 + (n.y - (y0 + y1) / 2) * f; });
    }
    return L;
  }

  async function init() {
    const svg = document.getElementById("netmap");
    if (!svg) return;
    let data;
    try { const r = await fetch(svg.dataset.src, { credentials: "same-origin" }); data = await r.json(); }
    catch (e) { svg.outerHTML = '<div class="empty-state"><p>Could not load the map.</p></div>'; return; }
    if (!data.nodes.length) { svg.hidden = true; document.getElementById("map-empty").hidden = false; return; }
    const W = svg.clientWidth || 1000, H = svg.clientHeight || 700;
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    const view = { x: 0, y: 0, s: 1 };
    const defs = el("defs", {}, svg);
    const glow = el("filter", { id: "noc-glow", x: "-50%", y: "-50%", width: "200%", height: "200%" }, defs);
    el("feGaussianBlur", { stdDeviation: 4, result: "b" }, glow);
    const fm = el("feMerge", {}, glow); el("feMergeNode", { in: "b" }, fm); el("feMergeNode", { in: "SourceGraphic" }, fm);
    const dots = el("pattern", { id: "noc-dots", width: 28, height: 28, patternUnits: "userSpaceOnUse" }, defs);
    el("circle", { cx: 1, cy: 1, r: 1, fill: NOC.dot }, dots);
    el("rect", { x: -W, y: -H, width: 3 * W, height: 3 * H, fill: NOC.bg }, svg);
    el("rect", { x: -W, y: -H, width: 3 * W, height: 3 * H, fill: "url(#noc-dots)" }, svg);
    const root = el("g", {}, svg), gl = el("g", {}, root), gn = el("g", {}, root);
    const apply = () => root.setAttribute("transform", `translate(${view.x},${view.y}) scale(${view.s})`);

    function draw(keep) {
      gl.replaceChildren(); gn.replaceChildren();
      const L = layout(data.nodes, data.links, W, H, keep ? 120 : 400, keep);
      const byId = new Map(data.nodes.map(n => [n.id, n]));
      // links between the same two nodes (three WANs to the Internet, a LAG) fan out as curves
      const pairs = new Map();
      data.links.forEach(l => { const k = [String(l.source), String(l.target)].sort().join("|"); (pairs.get(k) || pairs.set(k, []).get(k)).push(l); });
      const lines = data.links.map(l => {
        const a = byId.get(l.source), b = byId.get(l.target); if (!a || !b) return null;
        const sib = pairs.get([String(l.source), String(l.target)].sort().join("|"));
        const i = sib.indexOf(l), bend = (i - (sib.length - 1) / 2) * 28 * (String(l.source) < String(l.target) ? 1 : -1);
        const u = l.util, wan = l.protocol === "wan", down = wan && l.up === false;
        const color = down ? NOC.down : u == null ? NOC.idle : u >= 80 ? NOC.down : u >= 50 ? NOC.warn : NOC.up;
        const w = l.speed >= 10000 ? 3.6 : l.speed >= 1000 ? 2.4 : 1.6;
        const g = el("g", {}, gl);
        // a soft halo under a glowing core; idle links stay dim
        el("path", { fill: "none", stroke: l.mesh ? NOC.mute : color, "stroke-width": w + 5, opacity: u == null && !down ? 0.25 : 0.16, "stroke-linecap": "round", class: "halo" }, g);
        const line = el("path", { fill: "none", stroke: l.mesh ? NOC.mute : color, "stroke-width": l.mesh ? 1.8 : w, "stroke-linecap": "round",
          filter: u == null && !down ? "" : "url(#noc-glow)", "stroke-dasharray": l.mesh || down ? "6 6" : "" }, g);
        const hit = el("path", { fill: "none", stroke: "transparent", "stroke-width": 14 }, g);
        // the label: speed, and for a WAN its name and speed over its live throughput
        // every link: its speed, and under it the live traffic each way. The arrows follow the drawing: ↑ is traffic
        // towards the node higher up (for a WAN, upload to the ISP), ↓ towards the one lower down.
        const ab = wan ? l.up_bps : l.ab_bps, ba = wan ? l.down_bps : l.ba_bps;
        const tp = ab != null || ba != null ? { ab: fmtBps(ab || 0), ba: fmtBps(ba || 0) } : null;
        const head = wan ? [l.wan, l.speed_label || "speed ?", down ? "down" : ""].filter(Boolean).join(" · ")
                         : (l.mesh ? "mesh" + (l.speed_label ? " · " + l.speed_label : "") : (l.speed_label || "speed ?"));    // every link gets a label
        const rows = [head, tp ? "↑" + tp.ab + " ↓" + tp.ba : ""].filter(Boolean);
        let tag = null;
        if (rows.length) {
          tag = el("g", { "pointer-events": "none" }, g);
          const bg = el("rect", { rx: 8, fill: NOC.pill, stroke: wan ? (down ? NOC.down : NOC.wanLine) : NOC.pillLine, "stroke-width": 1 }, tag);
          const tx = el("text", { "text-anchor": "middle", "font-size": wan ? 10.5 : 9.5, "font-weight": 600, fill: wan ? NOC.wanInk : "#9fb6cb", "font-family": css("--mono") }, tag);
          rows.forEach((r, k) => { const ts = el("tspan", { x: 0, dy: k ? 13 : 0 }, tx); ts.textContent = r; });
          tx.setAttribute("y", rows.length > 1 ? -2 : 3.5);
          tag._bg = bg; tag._tx = tx; tag._rows = rows; tag._tp = tp;
        }
        const t = el("title", {}, hit);
        const speed = l.speed ? (l.speed >= 1000 ? l.speed / 1000 + " Gb/s" : l.speed + " Mb/s") : "speed unknown";
        const via = { lldp: "LLDP", cdp: "CDP", manual: "drawn by hand", "unifi-port": "seen on a UniFi switch port", wan: "WAN uplink" };
        const how = (l.sources || [l.protocol]).map(p => via[p] || (p || "").toUpperCase()).join(", ");
        t.textContent = wan
          ? `${a.name} ${l.wan || ""} → ${b.name}\n${down ? "DOWN · " : ""}${speed}${l.wan_ip ? " · " + l.wan_ip : ""}` +
            `${l.down_bps != null ? "\n↓ " + fmtBps(l.down_bps) + "  ↑ " + fmtBps(l.up_bps || 0) : ""}${u != null ? " (" + Math.round(u) + "% used)" : ""}` +
            `${l.latency_ms != null ? "\nlatency " + l.latency_ms + " ms" : ""}${l.loss_pct != null ? ", loss " + l.loss_pct + "%" : ""}`
          : `${a.name} ${l.a_port || ""} ↔ ${b.name} ${l.b_port || ""}\n${l.mesh ? "Wireless mesh uplink" : how}, ${speed}${u != null ? ", " + Math.round(u) + "% used" : ""}${l.bps != null ? " (" + fmtBps(l.bps) + ")" : ""}`;
        return { a, b, line, hit, tag, bend, halo: g.querySelector(".halo") };
      }).filter(Boolean);
      const nodes = data.nodes.map(n => {
        const g = el("g", { style: "cursor:pointer" }, gn);
        const ext = n.status === "external";
        const col = RING[n.status] || NOC.off;
        let r, labelY = 40;
        if (n.isp) {
          // an ISP: a glowing circle with how the line arrives (fibre, cable, satellite...) and its name under it
          const [ring, ink] = ISP_RING[n.kind] || ISP_RING.globe;
          r = el("circle", { r: 27, fill: NOC.pill, stroke: n.status === "down" ? NOC.down : ring, "stroke-width": 2.5, filter: "url(#noc-glow)",
            "stroke-dasharray": n.named ? "" : "4 3" }, g);
          glyph(g, ISP_GLYPH[n.kind] || ISP_GLYPH.globe, ink, 1.25);
          labelY = 45;
        } else {
          r = el("circle", { r: 23, fill: NOC.panel, stroke: col, "stroke-width": 2.5, filter: ext ? "" : "url(#noc-glow)",
            "stroke-dasharray": ext ? "4 3" : "" }, g);
          el("circle", { r: 18, fill: ROLE[n.ap ? "Wireless" : n.type] || "#56677a", opacity: 0.2 }, g);
          if (ext) {
            const q = el("text", { "text-anchor": "middle", y: 5, "font-size": 14, "font-weight": 600, fill: NOC.mute, "font-family": css("--mono") }, g);
            q.textContent = "?";
          } else {
            glyph(g, GLYPH[n.ap ? "Wireless" : n.type] || GLYPH.Network, NOC.ink, 1.05);
          }
        }
        const lbl = el("text", { "text-anchor": "middle", y: labelY, "font-size": 12, fill: NOC.ink, "font-family": css("--body"), "font-weight": 600 }, g);
        lbl.textContent = n.name.length > 24 ? n.name.slice(0, 23) + "…" : n.name;
        const subText = n.ap && n.clients != null ? n.clients + (n.clients === 1 ? " client" : " clients") : (!n.isp && n.platform ? n.platform : "");
        if (subText) {
          const c = el("text", { "text-anchor": "middle", y: labelY + 14, "font-size": 10.5, fill: NOC.mute, "font-family": css("--body") }, g);
          c.textContent = subText.length > 30 ? subText.slice(0, 29) + "…" : subText;
        }
        const t = el("title", {}, g); t.textContent = n.isp ? `${n.name}\nInternet provider${n.named ? "" : " (name it under the map)"}` : `${n.name}\n${n.ap ? "Access point" : (n.type || "")}${n.ip ? " · " + n.ip : ""}${n.site ? " · " + n.site : ""}\n${n.status}${n.ap && n.clients != null ? " · " + n.clients + " clients" : ""}` +
          (n.merged && n.merged.length ? "\nSeen as: " + n.merged.map(m => m.name + " (" + m.source + ")").join(", ") : "");
        if (String(n.id) === svg.dataset.focus) r.setAttribute("stroke-width", 5);
        return { n, g };
      });
      const place = () => {
        lines.forEach(({ a, b, line, hit, tag, bend, halo }) => {
          const dx = b.x - a.x, dy = b.y - a.y, len = Math.hypot(dx, dy) || 1;
          const cx = (a.x + b.x) / 2 - dy / len * bend * 2, cy = (a.y + b.y) / 2 + dx / len * bend * 2;
          const d = `M${a.x},${a.y}Q${cx},${cy} ${b.x},${b.y}`;
          line.setAttribute("d", d); hit.setAttribute("d", d); if (halo) halo.setAttribute("d", d);
          if (tag) {
            const mx = (a.x + 2 * cx + b.x) / 4, my = (a.y + 2 * cy + b.y) / 4;     // the curve's midpoint
            tag.setAttribute("transform", `translate(${mx},${my})`);
            if (tag._tp) {          // keep ↑ pointing at whichever end is higher on screen
              const up = a.y >= b.y ? tag._tp.ab : tag._tp.ba, dn = a.y >= b.y ? tag._tp.ba : tag._tp.ab;
              const last = tag._tx.lastChild, txt = "↑" + up + " ↓" + dn;
              if (last.textContent !== txt) last.textContent = txt;
            }
            if (!tag._w) { try { tag._w = Math.max(...[...tag._tx.children].map(c => c.getComputedTextLength())); } catch (e) { tag._w = 0; } }
            const w = (tag._w || Math.max(...tag._rows.map(r => r.length)) * 6.3) + 12, h = tag._rows.length > 1 ? 31 : 15;
            tag._bg.setAttribute("x", -w / 2); tag._bg.setAttribute("y", tag._rows.length > 1 ? -14 : -7.5); tag._bg.setAttribute("width", w); tag._bg.setAttribute("height", h);
          }
        });
        nodes.forEach(({ n, g }) => g.setAttribute("transform", `translate(${n.x},${n.y})`));
      };
      place();
      nodes.forEach(({ n, g }) => {
        let moved = false;
        g.addEventListener("pointerdown", ev => {
          ev.stopPropagation(); g.setPointerCapture(ev.pointerId); moved = false;
          const start = { x: ev.clientX, y: ev.clientY, nx: n.x, ny: n.y };
          const move = e => { const dx = (e.clientX - start.x) / view.s * (W / svg.clientWidth), dy = (e.clientY - start.y) / view.s * (H / svg.clientHeight);
            if (Math.abs(dx) + Math.abs(dy) > 3) moved = true; n.x = start.nx + dx; n.y = start.ny + dy; n.fixed = true; place(); };
          const up = () => { g.removeEventListener("pointermove", move); g.removeEventListener("pointerup", up); save();
            if (!moved && typeof n.id === "number") location.href = "/devices/" + n.id + "?tab=neighbours"; };
          g.addEventListener("pointermove", move); g.addEventListener("pointerup", up);
        });
      });
      save();
    }
    function save() { try { const pos = {}; data.nodes.forEach(n => { pos[n.id] = [Math.round(n.x), Math.round(n.y)]; }); localStorage.setItem(KEY, JSON.stringify(pos)); } catch (e) { /* storage blocked */ } }
    function fit() {
      const xs = data.nodes.map(n => n.x), ys = data.nodes.map(n => n.y);
      const minX = Math.min(...xs) - 60, maxX = Math.max(...xs) + 60, minY = Math.min(...ys) - 50, maxY = Math.max(...ys) + 60;
      view.s = Math.min(2, W / (maxX - minX), H / (maxY - minY)); view.x = (W - (maxX + minX) * view.s) / 2; view.y = (H - (maxY + minY) * view.s) / 2; apply();
    }
    draw(true); fit();
    svg.addEventListener("wheel", ev => { ev.preventDefault(); const f = ev.deltaY < 0 ? 1.12 : 1 / 1.12;
      const r = svg.getBoundingClientRect(), mx = (ev.clientX - r.left) * W / r.width, my = (ev.clientY - r.top) * H / r.height;
      view.x = mx - (mx - view.x) * f; view.y = my - (my - view.y) * f; view.s *= f; apply(); }, { passive: false });
    svg.addEventListener("pointerdown", ev => {
      const start = { x: ev.clientX, y: ev.clientY, vx: view.x, vy: view.y }; svg.style.cursor = "grabbing";
      const move = e => { view.x = start.vx + (e.clientX - start.x) * W / svg.clientWidth; view.y = start.vy + (e.clientY - start.y) * H / svg.clientHeight; apply(); };
      const up = () => { window.removeEventListener("pointermove", move); window.removeEventListener("pointerup", up); svg.style.cursor = "grab"; };
      window.addEventListener("pointermove", move); window.addEventListener("pointerup", up);
    });
    document.getElementById("map-fit")?.addEventListener("click", fit);
    document.getElementById("map-relayout")?.addEventListener("click", () => { data.nodes.forEach(n => { n.fixed = false; }); try { localStorage.removeItem(KEY); } catch (e) { /* */ } draw(false); fit(); });
  }
  document.addEventListener("DOMContentLoaded", init);
})();
