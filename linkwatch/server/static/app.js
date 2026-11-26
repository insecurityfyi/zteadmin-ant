// Menus in the top bar, "select all" boxes, and live filtering of tables.
(function () {
  document.addEventListener("DOMContentLoaded", () => {
    const menus = [...document.querySelectorAll("details.menu")];
    menus.forEach(m => m.addEventListener("toggle", () => { if (m.open) menus.forEach(o => { if (o !== m) o.open = false; }); }));
    document.addEventListener("click", e => { if (!e.target.closest("details.menu")) menus.forEach(m => { m.open = false; }); });
    document.addEventListener("keydown", e => { if (e.key === "Escape") menus.forEach(m => { if (m.open) { m.open = false; m.querySelector("summary").focus(); } }); });
    document.querySelectorAll("[data-check-all]").forEach(box => box.addEventListener("change", () => {
      document.querySelectorAll(`input[name="${box.dataset.checkAll}"]`).forEach(c => { c.checked = box.checked; });
    }));
  });
})();
