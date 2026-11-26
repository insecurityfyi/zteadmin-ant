// Dashboard edit mode: move (drag or arrows), resize, configure, add and remove widgets. Every change saves.
(function () {
  const grid = document.getElementById("widgets");
  if (!grid) return;
  const WIDTHS = [3, 4, 6, 8, 12];
  const widgets = () => [...grid.querySelectorAll(".widget")];
  const layout = () => widgets().map(w => ({ id: w.dataset.id, type: w.dataset.type, w: +w.dataset.w, opts: JSON.parse(w.dataset.opts || "{}") }));
  const hint = document.getElementById("w-hint");
  let saving = Promise.resolve();

  function save(then) {
    const body = JSON.stringify({ layout: layout() });
    saving = saving.then(() => fetch("/account/dashboard", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body }))
      .then(r => { if (!r.ok) throw new Error("HTTP " + r.status); if (hint) hint.textContent = "Saved."; if (then) then(); })
      .catch(e => { if (hint) hint.textContent = "Couldn't save the layout (" + e.message + "). Try again."; });
    return saving;
  }
  // a change of hash alone doesn't reload the page, so set the URL and then reload
  const reload = id => { history.replaceState(null, "", "/?edit=1" + (id ? "#w-" + id : "")); location.reload(); };
  const setWidth = (w, n) => { WIDTHS.forEach(x => w.classList.remove("c" + x)); w.classList.add("c" + n); w.dataset.w = n; };

  // toolbar buttons
  grid.addEventListener("click", ev => {
    const w = ev.target.closest(".widget"); if (!w) return;
    if (ev.target.closest("[data-move]")) {
      const dir = +ev.target.closest("[data-move]").dataset.move;
      const sib = dir < 0 ? w.previousElementSibling : w.nextElementSibling;
      if (sib && sib.classList.contains("widget")) { dir < 0 ? grid.insertBefore(w, sib) : grid.insertBefore(sib, w); save(); ev.target.focus(); }
    } else if (ev.target.closest("[data-remove]")) {
      w.remove(); save();
    } else if (ev.target.closest("[data-settings]")) {
      const f = w.querySelector(".w-opts"); if (f) { f.hidden = !f.hidden; if (!f.hidden) f.querySelector("input,select,textarea")?.focus(); }
    } else if (ev.target.closest("[data-opts-cancel]")) {
      w.querySelector(".w-opts").hidden = true;
    }
  });
  grid.addEventListener("change", ev => {
    const sel = ev.target.closest("[data-width]"); if (!sel) return;
    const w = sel.closest(".widget"); setWidth(w, +sel.value); save();
  });

  // settings forms
  grid.addEventListener("submit", ev => {
    const f = ev.target.closest(".w-opts"); if (!f) return;
    ev.preventDefault();
    const w = f.closest(".widget"), opts = {};
    new FormData(f).forEach((v, k) => { if (!k.endsWith("_q") && String(v).trim() !== "") opts[k] = String(v); });
    w.dataset.opts = JSON.stringify(opts);
    save(() => reload(w.dataset.id));
  });

  // port search for the traffic widget
  let timer;
  grid.addEventListener("input", ev => {
    const q = ev.target.closest("[data-port-search]"); if (!q) return;
    const label = q.closest("label"), hidden = label.querySelector("input[type=hidden]"), hits = label.querySelector(".port-hits");
    if (!q.value.trim()) { hidden.value = ""; hits.replaceChildren(); return; }
    clearTimeout(timer);
    timer = setTimeout(async () => {
      const r = await fetch("/ui/dashboard/ports?q=" + encodeURIComponent(q.value), { credentials: "same-origin" });
      const rows = r.ok ? await r.json() : [];
      hits.replaceChildren(...rows.map(p => { const b = document.createElement("button"); b.type = "button"; b.className = "btn sm"; b.style.justifyContent = "flex-start";
        b.textContent = p.label; b.addEventListener("click", () => { hidden.value = p.id; q.value = p.label; hits.replaceChildren(); }); return b; }));
      if (!rows.length) hits.textContent = "No matching ports.";
    }, 200);
  });

  // add a widget
  const add = document.getElementById("w-add");
  if (add) add.addEventListener("change", () => {
    if (!add.value) return;
    const id = Math.random().toString(16).slice(2, 10);
    const lay = layout(); lay.push({ id, type: add.value, w: 0, opts: {} });
    fetch("/account/dashboard", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ layout: lay }) })
      .then(r => { if (r.ok) reload(id); else if (hint) hint.textContent = "Couldn't add the widget (HTTP " + r.status + ")."; });
  });

  // drag and drop by the handle
  let dragged = null;
  const clear = () => widgets().forEach(x => x.classList.remove("drop-before", "drop-after", "dragging"));
  grid.addEventListener("dragstart", ev => {
    const h = ev.target.closest(".w-handle"); if (!h) { ev.preventDefault(); return; }
    dragged = h.closest(".widget"); dragged.classList.add("dragging");
    ev.dataTransfer.effectAllowed = "move"; ev.dataTransfer.setData("text/plain", dragged.dataset.id);
    try { ev.dataTransfer.setDragImage(dragged, 20, 20); } catch (e) { /* older browsers */ }
  });
  const side = (w, ev) => { const r = w.getBoundingClientRect(); return (ev.clientX - r.left) < r.width / 2 ? "before" : "after"; };
  grid.addEventListener("dragover", ev => {
    if (!dragged) return; const w = ev.target.closest(".widget"); if (!w || w === dragged) return;
    ev.preventDefault(); widgets().forEach(x => x.classList.remove("drop-before", "drop-after")); w.classList.add("drop-" + side(w, ev));
  });
  grid.addEventListener("drop", ev => {
    if (!dragged) return; ev.preventDefault();
    const w = ev.target.closest(".widget");
    if (w && w !== dragged) grid.insertBefore(dragged, side(w, ev) === "before" ? w : w.nextElementSibling);
    clear(); dragged = null; save();
  });
  grid.addEventListener("dragend", () => { clear(); dragged = null; });

  if (location.hash) document.querySelector(location.hash)?.scrollIntoView({ block: "center" });
})();
