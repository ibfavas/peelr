/* Peelr 3.0 UI — scan → prioritize → inspect → export.
 * Performance notes: results re-render only when the job's completion count,
 * the active filters, or dismissal state change (renderToken). Progress ticks
 * update the bar and per-file rows in place. Finding lists are paginated and
 * file cards use CSS content-visibility so minified mega-files stay smooth.
 */
"use strict";

const GROUPS = [
  { id: "all",        label: "All",          cats: null },
  { id: "secrets",    label: "Secrets",      cats: ["api_keys", "credentials"] },
  { id: "xss",        label: "XSS & sinks",  cats: ["xss"] },
  { id: "endpoints",  label: "Endpoints",    cats: ["endpoints"] },
  { id: "parameters", label: "Parameters",   cats: ["parameters"] },
  { id: "paths",      label: "Paths",        cats: ["paths"] },
  { id: "emails",     label: "Emails",       cats: ["emails"] },
  { id: "comments",   label: "Comments",     cats: ["comments"] },
];

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const FINDINGS_PER_PAGE = 60;

const state = {
  jobId: null,
  job: null,
  pollTimer: null,
  renderToken: "",
  group: "all",
  severity: "all",
  search: "",
  dismissed: new Set(),
  showDismissed: false,
  expanded: new Set(),   // finding ids
  pagesShown: {},        // result id -> number of pages
  findingById: {},       // finding id -> finding object (rebuilt per render)
  historyView: null,     // history record when inspecting one
};

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

/* ---------------- scan lifecycle ---------------- */

$("scan").addEventListener("click", startScan);
$("clear").addEventListener("click", () => {
  $("urls").value = "";
  $("file").value = "";
  $("file-name").textContent = "";
  hideScanError();
});
$("file").addEventListener("change", (e) => {
  $("file-name").textContent = e.target.files.length ? e.target.files[0].name : "";
});

function showScanError(msg) {
  const el = $("scan-error");
  el.textContent = msg;
  el.classList.remove("hidden");
}
function hideScanError() { $("scan-error").classList.add("hidden"); }

async function startScan() {
  const urls = $("urls").value.trim();
  const file = $("file").files[0];
  if (!urls && !file) {
    showScanError("Paste some URLs or upload a list first.");
    return;
  }
  hideScanError();
  resetResults();

  const form = new FormData();
  if (urls) form.append("urls", urls);
  if (file) form.append("file", file);

  const btn = $("scan");
  btn.disabled = true;
  btn.textContent = "Scanning…";
  try {
    const res = await fetch("/api/jobs", { method: "POST", body: form });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Scan failed to start");
    state.jobId = data.job_id;
    $("progress-card").classList.remove("hidden");
    $("results-section").classList.remove("hidden");
    pollJob();
    state.pollTimer = setInterval(pollJob, 1500);
  } catch (err) {
    showScanError(err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "Scan";
  }
}

function resetResults() {
  stopPolling();
  state.job = null;
  state.jobId = null;
  state.historyView = null;
  state.renderToken = "";
  state.group = "all";
  state.severity = "all";
  state.search = "";
  state.dismissed = new Set();
  state.showDismissed = false;
  state.expanded = new Set();

  state.pagesShown = {};
  $("cat-tabs").innerHTML = "";
  $("stats").innerHTML = "";
  $("files").innerHTML = "";
  $("sev-filter").value = "all";
  $("search").value = "";
  $("dismiss-bar").classList.add("hidden");
  $("results-section").classList.add("hidden");
  $("progress-card").classList.add("hidden");
}

function stopPolling() {
  if (state.pollTimer) {
    clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
}

async function pollJob() {
  if (!state.jobId) return;
  try {
    const res = await fetch("/api/jobs/" + encodeURIComponent(state.jobId));
    if (!res.ok) throw new Error("job lost");
    state.job = await res.json();
    updateProgress();
    maybeRenderResults();
    if (state.job.status === "completed") stopPolling();
  } catch (err) {
    stopPolling();
    showScanError("Lost contact with the scan. Refresh to try again.");
  }
}

function updateProgress() {
  const job = state.job;
  const pct = job.total ? Math.round((job.completed / job.total) * 100) : 0;
  $("bar").style.width = pct + "%";
  const pill = $("job-status");
  pill.textContent = job.status;
  pill.className = "pill" + (job.status === "running" ? " running" : job.status === "completed" ? " completed" : "");
  $("progress-text").textContent = `${job.completed} of ${job.total} files analyzed`;

  const box = $("file-status");
  const html = job.results.map((r) => {
    const name = esc(r.name || r.id);
    let status;
    if (r.status === "completed") status = '<span class="dot-ok">✓ done</span>';
    else if (r.status === "failed") status = '<span class="dot-err">✗ failed</span>';
    else status = '<span class="spin"></span>';
    return `<div class="file-row"><span class="fname">${name}</span><span class="fstat">${status}</span></div>`;
  }).join("");
  if (box.dataset.html !== html) {
    box.innerHTML = html;
    box.dataset.html = html;
  }
}

/* ---------------- rendering ---------------- */

function allFindings() {
  if (state.historyView) {
    const rec = state.historyView;
    return [{ id: "history", name: rec.name, origin: rec.origin, kind: rec.kind,
              status: "completed", findings: rec.findings || [], summary: {} }];
  }
  return (state.job && state.job.results) || [];
}

function sevPasses(f) {
  if (state.severity === "all") return true;
  const rank = SEV_RANK[f.severity] ?? 0;
  if (state.severity === "critical") return rank >= 4;
  if (state.severity === "high") return rank >= 3;
  if (state.severity === "medium") return rank >= 2;
  return true;
}

function filterFindings(list) {
  const grp = GROUPS.find((g) => g.id === state.group);
  const q = state.search.trim().toLowerCase();
  return list.filter((f) => {
    if (grp.cats && !grp.cats.includes(f.category)) return false;
    if (!sevPasses(f)) return false;
    if (!state.showDismissed && state.dismissed.has(f.id)) return false;
    if (q) {
      const hay = ((f.title || "") + " " + (f.value || "") + " " + (f.note || "")).toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

function maybeRenderResults() {
  // Works for both live jobs and the read-only history view.
  const srcId = state.historyView
    ? "history:" + (state.historyView.source_id || state.historyView.name)
    : state.jobId;
  if (!srcId) return;
  const completed = state.job ? state.job.completed : 0;
  const total = state.job ? state.job.total : 0;
  const token = [srcId, completed, total, state.group, state.severity,
                 state.search, state.showDismissed, state.dismissed.size].join("|");
  if (token === state.renderToken) return;
  state.renderToken = token;
  renderResults();
}

function renderResults() {
  const results = allFindings();
  const done = results.filter((r) => r.status === "completed" || r.status === "failed");
  const totalFindings = done.reduce((n, r) => n + (r.findings ? r.findings.length : 0), 0);

  // id -> finding lookup for surgical expand/collapse
  state.findingById = {};
  for (const r of done) for (const f of r.findings || []) state.findingById[f.id] = f;

  // stats
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let secrets = 0;
  for (const r of done) {
    for (const f of r.findings || []) {
      if (counts[f.severity] !== undefined) counts[f.severity]++;
      if (f.category === "api_keys" || f.category === "credentials") secrets++;
    }
  }
  const maxSev = SEV_ORDER.find((s) => counts[s] > 0) || "minimal";
  $("stats").innerHTML =
    stat("Files", done.length) +
    stat("Findings", totalFindings) +
    stat("Secrets", secrets, "secrets") +
    stat("Critical", counts.critical, "critical") +
    stat("High", counts.high, "high") +
    `<div class="stat"><div class="num"><span class="risk-badge risk-${maxSev}">${maxSev === "minimal" ? "clean" : maxSev}</span></div><div class="lbl">Top risk</div></div>`;

  // category tabs with counts
  const byCat = {};
  for (const r of done) for (const f of r.findings || []) byCat[f.category] = (byCat[f.category] || 0) + 1;
  $("cat-tabs").innerHTML = GROUPS.map((g) => {
    const n = g.cats ? g.cats.reduce((s, c) => s + (byCat[c] || 0), 0) : totalFindings;
    const active = state.group === g.id ? " active" : "";
    return `<button class="tab${active}" role="tab" data-group="${g.id}">${esc(g.label)}<span class="count">${n}</span></button>`;
  }).join("");
  document.querySelectorAll("#cat-tabs .tab").forEach((t) =>
    t.addEventListener("click", () => {
      state.group = t.dataset.group;
      maybeRenderResults();
    })
  );

  // dismiss bar
  if (state.dismissed.size) {
    $("dismiss-bar").classList.remove("hidden");
    $("dismiss-count").textContent = `${state.dismissed.size} dismissed`;
    $("toggle-dismissed").textContent = state.showDismissed ? "Hide dismissed" : "Show dismissed";
  } else {
    $("dismiss-bar").classList.add("hidden");
  }

  // file groups
  const filesEl = $("files");
  const cards = [];
  let anyVisible = false;
  const sorted = [...done].sort((a, b) => fileRiskRank(b) - fileRiskRank(a));
  for (const r of sorted) {
    const visible = filterFindings(r.findings || []);
    const dismissedHere = (r.findings || []).filter((f) => state.dismissed.has(f.id)).length;
    if (!visible.length && !dismissedHere) {
      if (state.search || state.group !== "all" || state.severity !== "all") continue;
    }
    anyVisible = anyVisible || visible.length > 0;
    cards.push(fileCard(r, visible, dismissedHere));
  }
  filesEl.innerHTML = cards.join("");
  $("no-match").classList.toggle("hidden", anyVisible);

  // wire up interactions
  document.querySelectorAll(".file-head").forEach((h) =>
    h.addEventListener("click", () => {
      const card = h.closest(".file-card");
      card.classList.toggle("closed");
    })
  );
  document.querySelectorAll(".finding").forEach((el) => {
    const row = el.querySelector(".finding-row");
    if (row) wireFinding(el, row.dataset.fid);
  });
  document.querySelectorAll(".show-more").forEach((b) =>
    b.addEventListener("click", () => {
      const rid = b.dataset.rid;
      state.pagesShown[rid] = (state.pagesShown[rid] || 1) + 1;
      state.renderToken = ""; // force re-render
      maybeRenderResults();
    })
  );
}

function stat(label, n, cls) {
  return `<div class="stat${cls ? " " + cls : ""}"><div class="num">${n}</div><div class="lbl">${esc(label)}</div></div>`;
}

function fileRiskRank(r) {
  let best = -1;
  for (const f of r.findings || []) best = Math.max(best, SEV_RANK[f.severity] ?? 0);
  return best;
}

function fileCard(r, visible, dismissedCount) {
  const rid = r.id;
  const maxSev = SEV_ORDER.find((s) => (r.findings || []).some((f) => f.severity === s)) || "minimal";
  const isMin = r.minified ? '<span class="tag">minified bundle</span>' : "";
  const trunc = r.summary && r.summary.truncated
    ? Object.entries(r.summary.truncated).map(([c, n]) => `${n} more ${c}`).join(", ")
    : "";
  const n = visible.length;
  const shown = Math.min(n, (state.pagesShown[rid] || 1) * FINDINGS_PER_PAGE);
  const items = visible.slice(0, shown).map(findingHTML).join("");
  const more = n > shown
    ? `<button class="show-more" data-rid="${esc(rid)}">Show ${n - shown} more findings…</button>` : "";
  const truncNote = trunc ? `<div class="trunc-note">Capped at ${n} shown — ${esc(trunc)} not shown.</div>` : "";
  const emptyNote = !n && !dismissedCount
    ? `<div class="file-error" style="color:var(--muted)">No findings in this file. Clean scan.</div>` : "";
  const dismissedNote = dismissedCount && !state.showDismissed
    ? `<div class="trunc-note">${dismissedCount} dismissed finding${dismissedCount > 1 ? "s" : ""} hidden.</div>` : "";
  const errNote = r.status === "failed"
    ? `<div class="file-error">Failed: ${esc(r.error || "unknown error")}</div>` : "";

  return `<div class="file-card" data-rid="${esc(rid)}">
    <button class="file-head" type="button">
      <span class="risk-badge risk-${maxSev}">${maxSev === "minimal" ? "clean" : maxSev}</span>
      <span class="file-name">${esc(r.name)}</span>
      ${isMin}
      <span class="file-meta">${n} finding${n === 1 ? "" : "s"}</span>
      <span class="chev">▾</span>
    </button>
    <div class="file-body">${errNote}${items}${emptyNote}${dismissedNote}${truncNote}${more}</div>
  </div>`;
}

function findingHTML(f) {
  const fid = esc(f.id);
  const open = state.expanded.has(f.id);
  const dismissed = state.dismissed.has(f.id);
  const sev = esc(f.severity || "info");
  const conf = esc(f.confidence || "");
  const confCls = conf === "high" ? "conf-high" : conf === "low" ? "conf-low" : "";
  const val = esc(f.value || "");
  const detail = open ? `
    <div class="f-detail">
      ${f.context ? `<div class="f-context">${esc(f.context)}</div>` : ""}
      ${f.snippet ? `<pre class="f-code">${esc(f.snippet)}</pre>` : ""}
      ${f.note ? `<div class="f-note">${esc(f.note)}</div>` : ""}
      <div class="f-actions">
        <button class="btn ghost small-btn copy-btn" data-value="${esc(f.value || "")}" type="button">Copy value</button>
        <button class="btn ghost small-btn dismiss-btn" data-fid="${fid}" type="button">${dismissed ? "Restore" : "Dismiss"}</button>
      </div>
    </div>` : "";
  return `<div class="finding${dismissed ? " is-dismissed" : ""}" style="${dismissed && !state.showDismissed ? "display:none" : ""}">
    <button class="finding-row" data-fid="${fid}" type="button">
      <span class="sev-dot sev-${sev}"></span>
      <span class="f-main">
        <span class="f-title">${esc(f.title || f.type)} ${conf ? `<span class="conf ${confCls}">${conf}</span>` : ""}</span>
        ${val ? `<span class="f-value">${val}</span>` : ""}
      </span>
      <span class="f-meta">L${f.line}${f.column ? ":" + f.column : ""}</span>
    </button>
    ${detail}
  </div>`;
}

function toggleFinding(fid) {
  const f = state.findingById[fid];
  if (!f) return;
  if (state.expanded.has(fid)) state.expanded.delete(fid);
  else state.expanded.add(fid);
  // surgical update: rebuild only this finding's node so scroll position
  // and pagination state survive expand/collapse.
  const row = document.querySelector(`.finding-row[data-fid="${CSS.escape(fid)}"]`);
  if (!row) return;
  const wrapper = row.closest(".finding");
  const tmp = document.createElement("div");
  tmp.innerHTML = findingHTML(f);
  const fresh = tmp.firstElementChild;
  wrapper.replaceWith(fresh);
  wireFinding(fresh, fid);
}

function wireFinding(root, fid) {
  const row = root.querySelector(".finding-row");
  if (row) row.addEventListener("click", () => toggleFinding(fid));
  const copy = root.querySelector(".copy-btn");
  if (copy) copy.addEventListener("click", (e) => {
    e.stopPropagation();
    navigator.clipboard.writeText(copy.dataset.value).catch(() => {});
    copy.textContent = "Copied ✓";
    setTimeout(() => (copy.textContent = "Copy value"), 1200);
  });
  const dis = root.querySelector(".dismiss-btn");
  if (dis) dis.addEventListener("click", (e) => {
    e.stopPropagation();
    toggleDismiss(fid);
  });
}

function toggleDismiss(fid) {
  if (state.dismissed.has(fid)) state.dismissed.delete(fid);
  else state.dismissed.add(fid);
  state.renderToken = "";
  maybeRenderResults();
}

/* ---------------- filters ---------------- */

$("sev-filter").addEventListener("change", (e) => {
  state.severity = e.target.value;
  maybeRenderResults();
});

let searchTimer = null;
$("search").addEventListener("input", (e) => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    state.search = e.target.value;
    maybeRenderResults();
  }, 150);
});

$("toggle-dismissed").addEventListener("click", () => {
  state.showDismissed = !state.showDismissed;
  maybeRenderResults();
});
$("restore-dismissed").addEventListener("click", () => {
  state.dismissed = new Set();
  state.showDismissed = false;
  maybeRenderResults();
});

/* ---------------- export ---------------- */

$("export-json").addEventListener("click", () => exportResults("json"));
$("export-csv").addEventListener("click", () => exportResults("csv"));

function exportResults(format) {
  if (!state.jobId) return;
  const a = document.createElement("a");
  a.href = `/api/jobs/${encodeURIComponent(state.jobId)}/export?format=${format}`;
  a.download = `peelr-${state.jobId}.${format}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
}

/* ---------------- history ---------------- */

$("history-btn").addEventListener("click", openHistory);
$("history-close").addEventListener("click", closeHistory);
$("history-overlay").addEventListener("click", (e) => {
  if (e.target === $("history-overlay")) closeHistory();
});

async function openHistory() {
  $("history-overlay").classList.remove("hidden");
  const list = $("history-list");
  list.innerHTML = '<p class="muted small">Loading…</p>';
  try {
    const res = await fetch("/api/history");
    const records = await res.json();
    if (!records.length) {
      list.innerHTML = '<p class="muted small">No scans saved yet.</p>';
      return;
    }
    list.innerHTML = records.map((rec) => {
      const n = (rec.findings || []).length;
      const top = ["critical", "high", "medium", "low", "info"].find((s) =>
        (rec.findings || []).some((f) => f.severity === s));
      return `
      <div class="history-item" data-id="${esc(rec.id || rec.source_id)}">
        <div class="h-name">${esc(rec.name)}</div>
        <div class="h-meta">${esc(rec.scanned_at || "")} · ${n} finding${n === 1 ? "" : "s"}${top ? ` · top: ${top}` : ""}</div>
      </div>`;
    }).join("");
    document.querySelectorAll(".history-item").forEach((el) =>
      el.addEventListener("click", () => viewHistory(el.dataset.id, records))
    );
  } catch (err) {
    list.innerHTML = '<p class="muted small">Could not load history.</p>';
  }
}

function viewHistory(id, records) {
  const rec = records.find((r) => (r.id || r.source_id) === id);
  if (!rec) return;
  stopPolling();
  state.historyView = rec;
  state.jobId = null;
  state.job = null;
  state.renderToken = "";
  state.group = "all";
  state.severity = "all";
  state.search = "";
  state.dismissed = new Set();
  state.showDismissed = false;
  state.expanded = new Set();

  state.pagesShown = {};
  $("sev-filter").value = "all";
  $("search").value = "";
  $("progress-card").classList.add("hidden");
  $("results-section").classList.remove("hidden");
  closeHistory();
  maybeRenderResults();
}

function closeHistory() { $("history-overlay").classList.add("hidden"); }
