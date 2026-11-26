// Menus in the top bar, "select all" boxes, and live filtering of tables.
(function () {
  document.addEventListener("DOMContentLoaded", () => {
    // in the left-sidebar layout the section menus are an accordion that stays open; elsewhere they are dropdowns
    const sidebar = () => document.documentElement.dataset.layout === "sidebar" && matchMedia("(min-width: 901px)").matches;
    const all = [...document.querySelectorAll("details.menu")];
    const pops = () => sidebar() ? all.filter(m => !m.closest(".menus")) : all;
    if (!sidebar()) all.forEach(m => { m.open = false; });
    all.forEach(m => m.addEventListener("toggle", () => { if (m.open && pops().includes(m)) pops().forEach(o => { if (o !== m) o.open = false; }); }));
    document.addEventListener("click", e => { if (!e.target.closest("details.menu")) pops().forEach(m => { m.open = false; }); });
    document.addEventListener("keydown", e => { if (e.key === "Escape") pops().forEach(m => { if (m.open) { m.open = false; m.querySelector("summary").focus(); } }); });
    document.querySelectorAll("[data-check-all]").forEach(box => box.addEventListener("change", () => {
      document.querySelectorAll(`input[name="${box.dataset.checkAll}"]`).forEach(c => { c.checked = box.checked; });
    }));
  });
})();
