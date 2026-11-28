/* Hypervisors pages: confirmation dialog for control actions, live task progress, console pop-outs. */
(function () {
  "use strict";
  const dlg = document.getElementById("hv-confirm");

  function ask(form) {
    const kind = form.dataset.confirm, expect = form.dataset.expect || "";
    if (!dlg || typeof dlg.showModal !== "function") return;
    document.getElementById("hv-confirm-title").textContent = form.dataset.title || "Are you sure?";
    document.getElementById("hv-confirm-help").textContent = form.dataset.help || "";
    const typed = document.getElementById("hv-confirm-typed"), input = document.getElementById("hv-confirm-input");
    const ok = document.getElementById("hv-confirm-ok");
    typed.hidden = kind !== "typed";
    document.getElementById("hv-confirm-expect").textContent = expect;
    input.value = "";
    ok.className = "btn pri" + (kind === "typed" ? " danger" : "");
    ok.disabled = kind === "typed";
    input.oninput = function () { ok.disabled = input.value.trim() !== expect; };
    dlg.onclose = function () {
      if (dlg.returnValue !== "ok") return;
      if (kind === "typed" && input.value.trim() !== expect) return;
      form.querySelector("[name=confirm]").value = "yes";
      form.querySelector("[name=confirm_text]").value = input.value.trim();
      form.dataset.confirmed = "1";
      if (form.requestSubmit) form.requestSubmit(); else form.submit();
    };
    dlg.returnValue = "";
    dlg.showModal();
    if (kind === "typed") input.focus(); else ok.focus();
  }

  document.addEventListener("submit", function (ev) {
    const form = ev.target;
    if (!(form instanceof HTMLFormElement) || !form.dataset.confirm) return;
    if (ev.submitter && ev.submitter.hasAttribute("formaction")) return;  // e.g. a read-only "Validate" button
    if (form.dataset.confirmed === "1") {
      delete form.dataset.confirmed;
      form.querySelectorAll("button[type=submit]").forEach(function (b) { b.disabled = true; });
      return;
    }
    ev.preventDefault();
    ask(form);
  }, true);

  // forms without a confirmation still get their button disabled, so a double click doesn't run an action twice
  document.addEventListener("submit", function (ev) {
    const form = ev.target;
    if (form instanceof HTMLFormElement && form.action.indexOf("/action") > 0 && !ev.defaultPrevented) {
      setTimeout(function () { form.querySelectorAll("button[type=submit]").forEach(function (b) { b.disabled = true; }); }, 0);
    }
  });

  // live task progress
  document.querySelectorAll("[data-task]").forEach(function (box) {
    const upid = box.dataset.task, iid = box.dataset.iid;
    const state = box.querySelector(".hv-task-state"), pre = box.querySelector(".hv-log");
    let n = 0;
    function tick() {
      n++;
      fetch("/ui/hypervisors/" + iid + "/task?upid=" + encodeURIComponent(upid), { credentials: "same-origin" })
        .then(function (r) { return r.json(); })
        .then(function (t) {
          if (t.error) { state.textContent = "unknown"; pre.textContent = t.error; return; }
          pre.textContent = (t.log || []).join("\n") || "(no output yet)";
          pre.scrollTop = pre.scrollHeight;
          if (t.status === "stopped") {
            const ok = t.exitstatus === "OK";
            state.textContent = ok ? "finished" : (t.exitstatus || "stopped");
            state.className = "hv-task-state tag " + (ok ? "okc" : "bad");
            if (ok && !box.dataset.reloaded) {
              box.dataset.reloaded = "1";
              const reload = document.createElement("a");
              reload.className = "btn sm"; reload.textContent = "Refresh page"; reload.style.marginLeft = "8px";
              reload.href = location.pathname + location.search.replace(/[?&]task=[^&]*/, "").replace(/^&/, "?");
              state.after(reload);
            }
            return;
          }
          state.textContent = "running";
          setTimeout(tick, n < 30 ? 2000 : 5000);
        })
        .catch(function () { if (n < 200) setTimeout(tick, 5000); });
    }
    tick();
  });

  // task rows on the Tasks page: click to show the log
  document.querySelectorAll("[data-task-row]").forEach(function (row) {
    row.addEventListener("click", function () {
      const pre = document.getElementById("task-" + row.dataset.idx);
      if (!pre) return;
      pre.closest("tr").hidden = !pre.closest("tr").hidden;
      if (pre.dataset.loaded) return;
      pre.dataset.loaded = "1";
      fetch("/ui/hypervisors/" + row.dataset.iid + "/task?upid=" + encodeURIComponent(row.dataset.taskRow), { credentials: "same-origin" })
        .then(function (r) { return r.json(); })
        .then(function (t) { pre.textContent = t.error || (t.log || []).join("\n") || "(no output)"; });
    });
  });

  document.querySelectorAll("a[data-popout]").forEach(function (a) {
    a.addEventListener("click", function (ev) {
      ev.preventDefault();
      window.open(a.href, "pve-" + (a.dataset.popout || "console"), "width=1000,height=640,noopener=no");
    });
  });

  document.querySelectorAll("input[data-filter]").forEach(function (q) {
    q.addEventListener("input", function () {
      const t = q.value.trim().toLowerCase();
      document.querySelectorAll("#" + q.dataset.filter + " tbody tr[data-q]").forEach(function (r) { r.hidden = t && !r.dataset.q.includes(t); });
    });
  });
})();
