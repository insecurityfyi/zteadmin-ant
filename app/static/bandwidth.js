// Draws the 7-day bandwidth area chart from JSON embedded in the page.
(() => {
  const el = document.getElementById('bw');
  const dataEl = document.getElementById('bw-data');
  if (!el || !dataEl) return;
  const pts = JSON.parse(dataEl.textContent);
  if (!pts.length) return;
  const fmt = (b) => { const u = ['B','KB','MB','GB','TB']; let i = 0; while (b >= 1000 && i < u.length - 1) { b /= 1000; i++; } return (i < 2 ? Math.round(b) : b.toFixed(1)) + ' ' + u[i]; };
  const draw = () => {
    const W = el.clientWidth, H = el.clientHeight, ml = 64, mr = 12, mt = 16, mb = 28, iw = W - ml - mr, ih = H - mt - mb;
    const max = Math.max(1, ...pts.map(p => p.down + p.up)) * 1.08, n = pts.length - 1 || 1;
    const x = i => ml + i * iw / n, y = v => mt + ih - v / max * ih;
    const area = (f) => `M${x(0)},${y(0)} ` + pts.map((p, i) => `L${x(i).toFixed(1)},${y(f(p)).toFixed(1)}`).join(' ') + ` L${x(n)},${y(0)}Z`;
    let g = '';
    [0, .25, .5, .75, 1].forEach(t => { const v = max / 1.08 * t; g += `<line x1="${ml}" x2="${W - mr}" y1="${y(v)}" y2="${y(v)}" stroke="var(--line)"/><text x="${ml - 8}" y="${y(v) + 4}" text-anchor="end">${fmt(v)}</text>`; });
    pts.forEach((p, i) => { const d = new Date(p.t); if (d.getUTCHours() === 0) { g += `<line x1="${x(i)}" x2="${x(i)}" y1="${mt}" y2="${mt + ih}" stroke="var(--line)"/>`; if (W >= 520 || d.getUTCDay() % 2 === 0) g += `<text x="${x(i) + 4}" y="${H - 8}">${d.toLocaleDateString('en-US', { weekday: 'short', timeZone: 'UTC' })}</text>`; } });
    g += `<path d="${area(p => p.down + p.up)}" fill="var(--ok)" opacity=".85"/>`;
    if (pts.some(p => p.up)) g += `<path d="${area(p => p.up)}" fill="var(--iso)" opacity=".9"/>`;
    const pk = pts.reduce((a, p, i) => (p.down + p.up > pts[a].down + pts[a].up ? i : a), 0), pd = new Date(pts[pk].t), right = pk > n * .7;
    g += `<circle cx="${x(pk)}" cy="${y(pts[pk].down + pts[pk].up)}" r="4" fill="var(--ink)"/><text x="${x(pk) + (right ? -8 : 8)}" y="${y(pts[pk].down + pts[pk].up) + 4}" text-anchor="${right ? 'end' : 'start'}" style="fill:var(--ink)">Peak ${fmt(pts[pk].down + pts[pk].up)}/h, ${pd.toLocaleDateString('en-US', { weekday: 'short', timeZone: 'UTC' })} ${pd.getUTCHours()}:00 UTC</text>`;
    el.innerHTML = g;
  };
  const ro = new ResizeObserver(draw); ro.observe(el);
})();
