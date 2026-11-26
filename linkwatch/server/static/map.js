// Network map: a small force-directed layout drawn in SVG. No libraries.
(function () {
  const NS = "http://www.w3.org/2000/svg";
  const el = (t, a, parent) => { const e = document.createElementNS(NS, t); for (const k in a) e.setAttribute(k, a[k]); if (parent) parent.append(e); return e; };
  const css = v => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
  const STATUS = { up: "--up", warn: "--warn", down: "--down", external: "--off", unknown: "--off", off: "--off" };
  const ICON = { Switch: "S", Router: "R", Firewall: "F", Wireless: "W", Server: "Sv", Hypervisor: "H", Storage: "St", Power: "P", Printer: "Pr", Camera: "C" };
  const fmtBps = v => { const u = ["b/s", "kb/s", "Mb/s", "Gb/s", "Tb/s"]; let i = 0; while (v >= 1000 && i < 4) { v /= 1000; i++; } return (v < 10 && i ? v.toFixed(1) : Math.round(v)) + " " + u[i]; };
  const KEY = "lw-map-pos";

  function layout(nodes, links, W, H, iterations, keep) {
    const byId = new Map(nodes.map(n => [n.id, n]));
    let saved = {};
    try { saved = JSON.parse(localStorage.getItem(KEY) || "{}"); } catch (e) { saved = {}; }
    nodes.forEach((n, i) => {
      const s = keep && saved[n.id];
      if (s) { n.x = s[0]; n.y = s[1]; n.fixed = true; }
      else { const a = 2 * Math.PI * i / Math.max(1, nodes.length); n.x = W / 2 + Math.cos(a) * W / 3 + Math.random() * 20; n.y = H / 2 + Math.sin(a) * H / 3 + Math.random() * 20; }
      n.vx = 0; n.vy = 0;
    });
    const L = links.map(l => ({ a: byId.get(l.source), b: byId.get(l.target) })).filter(l => l.a && l.b);
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
      L.forEach(({ a, b }) => {
        const dx = b.x - a.x, dy = b.y - a.y, d = Math.sqrt(dx * dx + dy * dy) || 0.01, f = (d - k) / d * 0.08;
        a.vx += dx * f; a.vy += dy * f; b.vx -= dx * f; b.vy -= dy * f;
      });
      nodes.forEach(n => {
        n.vx += (W / 2 - n.x) * 0.002; n.vy += (H / 2 - n.y) * 0.002;
        if (!n.fixed) { const m = Math.min(40 * t + 2, Math.hypot(n.vx, n.vy)); const s = Math.hypot(n.vx, n.vy) || 1; n.x += n.vx / s * m; n.y += n.vy / s * m; }
        n.vx *= 0.5; n.vy *= 0.5;
      });
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
    const root = el("g", {}, svg), gl = el("g", {}, root), gn = el("g", {}, root);
    const apply = () => root.setAttribute("transform", `translate(${view.x},${view.y}) scale(${view.s})`);

    function draw(keep) {
      gl.replaceChildren(); gn.replaceChildren();
      const L = layout(data.nodes, data.links, W, H, keep ? 120 : 400, keep);
      const byId = new Map(data.nodes.map(n => [n.id, n]));
      const lines = data.links.map(l => {
        const a = byId.get(l.source), b = byId.get(l.target); if (!a || !b) return null;
        const u = l.util;
        const color = u == null ? css("--off") : u >= 80 ? css("--down") : u >= 50 ? css("--warn") : css("--up");
        const w = l.speed >= 10000 ? 4 : l.speed >= 1000 ? 2.6 : 1.6;
        const g = el("g", {}, gl);
        const line = el("line", { stroke: color, "stroke-width": w, "stroke-linecap": "round", opacity: 0.85 }, g);
        const hit = el("line", { stroke: "transparent", "stroke-width": 12 }, g);
        const t = el("title", {}, hit);
        t.textContent = `${a.name} ${l.a_port || ""} ↔ ${b.name} ${l.b_port || ""}\n${(l.protocol || "").toUpperCase()}${l.speed ? ", " + (l.speed >= 1000 ? l.speed / 1000 + " Gb/s" : l.speed + " Mb/s") : ""}${u != null ? ", " + Math.round(u) + "% used" : ""}${l.bps ? " (" + fmtBps(l.bps) + ")" : ""}`;
        return { a, b, line, hit };
      }).filter(Boolean);
      const nodes = data.nodes.map(n => {
        const g = el("g", { style: "cursor:pointer" }, gn);
        const ext = n.status === "external";
        const r = el("rect", { x: -15, y: -15, width: 30, height: 30, rx: ext ? 15 : 8, fill: css("--panel"), stroke: css(STATUS[n.status] || "--off"),
          "stroke-width": 2.5, "stroke-dasharray": ext ? "4 3" : "" }, g);
        const ic = el("text", { "text-anchor": "middle", y: 4.5, "font-size": 11, "font-weight": 600, fill: css(STATUS[n.status] || "--off"), "font-family": css("--mono") }, g);
        ic.textContent = ext ? "?" : (ICON[n.type] || "•");
        const lbl = el("text", { "text-anchor": "middle", y: 30, "font-size": 11.5, fill: css("--ink"), "font-family": css("--body") }, g);
        lbl.textContent = n.name.length > 22 ? n.name.slice(0, 21) + "…" : n.name;
        const t = el("title", {}, g); t.textContent = `${n.name}\n${n.type || ""}${n.ip ? " · " + n.ip : ""}${n.site ? " · " + n.site : ""}\n${n.status}`;
        if (String(n.id) === svg.dataset.focus) r.setAttribute("stroke-width", 5);
        return { n, g };
      });
      const place = () => {
        lines.forEach(({ a, b, line, hit }) => { for (const e of [line, hit]) { e.setAttribute("x1", a.x); e.setAttribute("y1", a.y); e.setAttribute("x2", b.x); e.setAttribute("y2", b.y); } });
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
    document.getElementById("map-fit").addEventListener("click", fit);
    document.getElementById("map-relayout").addEventListener("click", () => { data.nodes.forEach(n => { n.fixed = false; }); try { localStorage.removeItem(KEY); } catch (e) { /* */ } draw(false); fit(); });
  }
  document.addEventListener("DOMContentLoaded", init);
})();
