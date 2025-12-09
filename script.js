(function () {
  // Wrap everything so we never fail silently
  try {

    // ---------- Helpers ----------
    const $  = (sel) => document.querySelector(sel);
    const $$ = (sel) => Array.from(document.querySelectorAll(sel));
    const getText = (el) => (el?.textContent || "").trim();

    function bust() { return `v=${Date.now()}`; }

    async function tryFetchJSON(url) {
      const r = await fetch(url, { cache: "no-store" });
      if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
      const j = await r.json();
      if (!Array.isArray(j)) throw new Error("JSON not an array");
      return j;
    }

    // ---------- Load updates ----------
    async function loadUpdates() {
      const BASE = location.origin + location.pathname.replace(/\/[^\/]*$/, "/");

      const candidates = [
        `${BASE}updates.json?${bust()}`,
        `${location.origin}/MS-Updates/updates.json?${bust()}`,
        `${location.origin}/updates.json?${bust()}`
      ];

      let updates = [];
      let sourceNote = "";

      // 1) updates.json (auto-updated)
      for (const url of candidates) {
        try {
          const list = await tryFetchJSON(url);
          if (list.length) {
            updates = list;
            sourceNote = `updates.json (${url.replace(/\?.*$/, "")})`;
            break;
          }
        } catch (_) {}
      }

      // 2) If updates.json failed, fallback-updates.json (your old static list)
      if (!updates.length) {
        const fbCandidates = [
          `${BASE}fallback-updates.json?${bust()}`,
          `${location.origin}/MS-Updates/fallback-updates.json?${bust()}`,
          `${location.origin}/fallback-updates.json?${bust()}`
        ];
        for (const url of fbCandidates) {
          try {
            const list = await tryFetchJSON(url);
            if (list.length) {
              updates = list;
              sourceNote = `fallback-updates.json (${url.replace(/\?.*$/, "")})`;
              break;
            }
          } catch (_) {}
        }
      }

      // 3) Merge server-updates.json if present
      const serverCandidates = [
        `${BASE}server-updates.json?${bust()}`,
        `${location.origin}/MS-Updates/server-updates.json?${bust()}`,
        `${location.origin}/server-updates.json?${bust()}`
      ];
      for (const url of serverCandidates) {
        try {
          const list = await tryFetchJSON(url);
          if (list.length) updates.push(...list);
          if (!sourceNote) sourceNote = "server-updates.json only";
          break;
        } catch (_) {}
      }

      // 4) Merge manual extras from localStorage
      try {
        const extra = JSON.parse(localStorage.getItem("extraUpdates") || "[]");
        if (Array.isArray(extra) && extra.length) updates.push(...extra);
      } catch (_) {}

      return { updates, sourceNote: sourceNote || "none (no JSON found)" };
    }

    // ---------- Date / rendering ----------
    const coverageEl = $("#coverage");
    const genEl = $("#generatedAt");
    const tbody = $("#updatesTable tbody");

    const today = new Date();
    const start = new Date(today);
    start.setDate(start.getDate() - 90);

    function fmtDate(d) {
      return d.toLocaleString(undefined, { month: "short", day: "2-digit", year: "numeric" });
    }
    function fmtDateISO(iso) {
      const d = new Date(iso + "T00:00:00");
      return d.toLocaleString(undefined, { month: "short", day: "2-digit", year: "numeric" });
    }
    function rowHTML(u) {
      return `<tr>
        <td data-col="date">${fmtDateISO(u.date)}</td>
        <td data-col="kb"><a href="${u.link}" target="_blank" rel="noopener">${u.kb}</a></td>
        <td data-col="product">${u.product}</td>
        <td data-col="class">${u.classification}</td>
        <td data-col="details">${u.details}</td>
        <td data-col="issues">${u.known_issues}</td>
        <td data-col="sev"><span class="badge">${u.severity}</span></td>
      </tr>`;
    }

    // Add data-source line under coverage
    const sourceEl = document.createElement("div");
    sourceEl.className = "sub muted";
    sourceEl.style.marginTop = "4px";
    coverageEl.insertAdjacentElement("afterend", sourceEl);

    // ---------- Sort / filter UI (your original behavior) ----------
    let osAsc = true;

    function sortByOS() {
      const rows = $$("#updatesTable tbody tr");
      rows.sort((a, b) => {
        const ap = getText(a.querySelector('td[data-col="product"]')).toLowerCase();
        const bp = getText(b.querySelector('td[data-col="product"]')).toLowerCase();
        if (ap < bp) return osAsc ? -1 : 1;
        if (ap > bp) return osAsc ? 1 : -1;

        const ad = Date.parse(getText(a.querySelector('td[data-col="date"]')));
        const bd = Date.parse(getText(b.querySelector('td[data-col="date"]')));
        return bd - ad;
      });
      tbody.innerHTML = "";
      rows.forEach(r => tbody.appendChild(r));
      $("#btnSortOS").textContent = osAsc ? "Sort by OS (Z→A)" : "Sort by OS (A→Z)";
      osAsc = !osAsc;
      applyCombinedFilter();
    }

    function resetSort() {
      tbody.innerHTML = window.__updates.map(rowHTML).join("");
      osAsc = true;
      $("#btnSortOS").textContent = "Sort by OS (A→Z)";
      buildChips();
      applyCombinedFilter();
    }

    const panel = document.createElement("div");
    panel.id = "filterPanel";
    panel.className = "filterpanel";
    const chips = document.createElement("div");
    chips.id = "chips";
    chips.className = "chips";
    const controls = document.createElement("div");
    controls.style.cssText = "margin-top:8px; display:flex; gap:8px; align-items:center;";
    const btnAll = document.createElement("button");
    btnAll.className = "btn"; btnAll.id = "btnSelectAll"; btnAll.textContent = "Select all";
    const btnClr = document.createElement("button");
    btnClr.className = "btn"; btnClr.id = "btnClear"; btnClr.textContent = "Clear";
    const note = document.createElement("span");
    note.className = "muted"; note.id = "activeFilterNote";
    controls.append(btnAll, btnClr, note);

    document.querySelector("header").append(panel);
    panel.append(chips, controls);

    function uniqueProducts() {
      const set = new Set();
      $$('#updatesTable td[data-col="product"]').forEach(td => set.add(getText(td)));
      return Array.from(set).sort((a, b) => a.localeCompare(b));
    }

    function buildChips() {
      chips.innerHTML = "";
      uniqueProducts().forEach(p => {
        const id = "chk_" + p.replace(/[^a-z0-9]+/gi, "_");
        const lab = document.createElement("label");
        lab.className = "chip";
        const input = document.createElement("input");
        input.type = "checkbox";
        input.checked = true;
        input.dataset.os = p;
        input.id = id;
        const span = document.createElement("span");
        span.textContent = p;
        lab.appendChild(input);
        lab.appendChild(span);
        chips.appendChild(lab);
        input.addEventListener("change", applyCombinedFilter);
      });
    }

    function activeOSList() {
      return Array.from(chips.querySelectorAll('input[type="checkbox"]'))
        .filter(cb => cb.checked).map(cb => cb.dataset.os);
    }
    function allOSList() {
      return Array.from(chips.querySelectorAll('input[type="checkbox"]'))
        .map(cb => cb.dataset.os);
    }

    const searchInput = $("#searchInput");
    const matchCount = $("#matchCount");

    function applyCombinedFilter() {
      const term = (searchInput?.value || "").toLowerCase().trim();
      const active = activeOSList();
      const all = allOSList();
      let shown = 0;

      $$("#updatesTable tbody tr").forEach(tr => {
        const product = getText(tr.querySelector('td[data-col="product"]'));
        const text = tr.innerText.toLowerCase();
        const matchOS = active.length === 0 ? false : active.includes(product);
        const matchSearch = term === "" ? true : text.includes(term);
        const visible = matchOS && matchSearch;
        tr.style.display = visible ? "" : "none";
        if (visible) shown++;
      });

      note.textContent = active.length === all.length || active.length === 0
        ? ""
        : ("Active OS filters: " + active.join(", "));

      matchCount.textContent = term ? `${shown} match${shown === 1 ? "" : "es"}` : "";
    }

    function toEmailSafe(text, maxLen) {
      const enc = encodeURIComponent(text);
      return enc.length > maxLen ? enc.slice(0, maxLen) + "%0A%0A%5Btruncated%5D" : enc;
    }

    function draftEmail() {
      const lines = [];
      lines.push("Windows Updates & Patches — Last 90 Days");
      lines.push(`Coverage: ${fmtDate(start)} to ${fmtDate(today)}`);
      lines.push("");

      $$("#updatesTable tbody tr").forEach(tr => {
        if (tr.style.display === "none") return;
        const date = getText(tr.querySelector('td[data-col="date"]'));
        const kb = getText(tr.querySelector('td[data-col="kb"]'));
        const kbLink = tr.querySelector('td[data-col="kb"] a')?.href || "";
        const product = getText(tr.querySelector('td[data-col="product"]'));
        const cls = getText(tr.querySelector('td[data-col="class"]'));
        const sev = getText(tr.querySelector('td[data-col="sev"]'));
        const issues = getText(tr.querySelector('td[data-col="issues"]'));

        lines.push(`• ${date} — ${kb} — ${product} — ${sev} — ${cls}\n  ${kbLink}\n  Issues: ${issues}`);
      });

      lines.push("\n(Attach the HTML report if needed)");

      const mailto = "mailto:?subject=" +
        encodeURIComponent("Windows updates (last 90 days)") +
        "&body=" + toEmailSafe(lines.join("\n"), 1800);

      window.location.href = mailto;
    }

    $("#btnSortOS").addEventListener("click", sortByOS);
    $("#btnResetSort").addEventListener("click", resetSort);
    $("#btnFilterOS").addEventListener("click", () => {
      panel.style.display = (panel.style.display === "none" || panel.style.display === "") ? "block" : "none";
    });
    $("#btnPrint").addEventListener("click", () => window.print());
    $("#btnEmail").addEventListener("click", draftEmail);

    $("#btnSearch").addEventListener("click", applyCombinedFilter);
    $("#btnClearSearch").addEventListener("click", () => { searchInput.value = ""; applyCombinedFilter(); });
    searchInput.addEventListener("keyup", (e) => { if (e.key === "Enter") applyCombinedFilter(); });

    btnAll.addEventListener("click", () => {
      chips.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = true);
      applyCombinedFilter();
    });
    btnClr.addEventListener("click", () => {
      chips.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
      applyCombinedFilter();
    });

    // ---------- Boot ----------
    (async function init() {
      coverageEl.textContent = "Coverage window: (loading…)";

      const { updates, sourceNote } = await loadUpdates();
      sourceEl.textContent = `Data source: ${sourceNote}`;

      window.__updates = updates
        .filter(u => u?.date && u?.kb)
        .sort((a, b) => a.date < b.date ? 1 : -1);

      coverageEl.textContent = `Coverage window: ${fmtDate(start)} → ${fmtDate(today)}`;
      genEl.textContent = `Generated at: ${new Date().toLocaleString()}`;

      tbody.innerHTML = window.__updates.map(rowHTML).join("");
      buildChips();
      applyCombinedFilter();
    })();

  } catch (err) {
    console.error("script.js fatal error:", err);
    const coverageEl = document.getElementById("coverage");
    if (coverageEl) coverageEl.textContent = "Coverage window: ERROR loading script.js (see console)";
  }
})();
