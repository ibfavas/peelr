const VERSION = "v1.1.0";

const CATS = {
  api_keys: { icon: "🔑", label: "API Keys & Tokens", hint: "Stripe, AWS, Google, GitHub, JWT…" },
  credentials: { icon: "🔒", label: "Credentials", hint: "Passwords, Basic Auth, DB strings, private keys" },
  xss: { icon: "⚡", label: "XSS Sinks", hint: "innerHTML, eval, document.write, dangerouslySetInnerHTML…" },
  dom_sinks: { icon: "🕳️", label: "DOM Sinks", hint: "document.domain, postMessage, srcdoc, script.src…" },
  prototype_pollution: { icon: "☣️", label: "Prototype Pollution", hint: "__proto__ writes, Object.assign taint, lodash merge…" },
  graphql: { icon: "◈", label: "GraphQL", hint: "/graphql endpoints, queries, mutations, introspection" },
  endpoints: { icon: "🌐", label: "Endpoints & APIs", hint: "fetch(), axios, XHR, jQuery AJAX calls, API paths" },
  emails: { icon: "✉️", label: "Email Addresses", hint: "" },
  paths: { icon: "📂", label: "File Paths", hint: "Unix/Windows paths, S3 bucket references" },
  comments: { icon: "💬", label: "Dev Comments", hint: "TODO, FIXME, security-related, credential-related comments" },
};

const SIDEBAR_ORDER = [
  "api_keys",
  "credentials",
  "xss",
  "dom_sinks",
  "prototype_pollution",
  "graphql",
  "endpoints",
  "emails",
  "paths",
  "comments",
];

const STATS = [
  { id: "total", label: "Total Findings", hint: "all files combined", className: "num-total" },
  { id: "critical", label: "🔴 Critical", hint: "report immediately", className: "num-crit" },
  { id: "high", label: "🟠 High", hint: "verify & report", className: "num-high" },
  { id: "medium", label: "🟡 Medium", hint: "worth reviewing", className: "num-med" },
  { id: "low", label: "🟢 Low / Info", hint: "context dependent", className: "num-low" },
  { id: "files", label: "Files Scanned", hint: "JS files processed", className: "num-files" },
];

const SEVERITY_FILTERS = [
  { value: "critical", label: "🔴 Critical" },
  { value: "high", label: "🟠 High" },
  { value: "medium", label: "🟡 Medium" },
  { value: "low", label: "🟢 Low" },
  { value: "info", label: "ℹ Info" },
];

const LEGEND_ITEMS = [
  { color: "var(--red)", text: "Severity = impact if exploited" },
  { color: "var(--green)", text: "Confidence HIGH = low false positive" },
  { color: "var(--yellow)", text: "Confidence LOW = verify manually" },
];

const results = [];
const F = {
  sev: new Set(SEVERITY_FILTERS.map((item) => item.value)),
  cat: null,
  q: "",
};

document.addEventListener("DOMContentLoaded", () => {
  renderShell();
  initTheme();
  bindShellEvents();
});

function renderShell() {
  document.getElementById("app").innerHTML = `
    <div class="app">
      <header class="header">
        <a class="logo" href="/">
          <div class="logo-icon">🧅</div>
          <div>
            <div class="logo-name">Peelr</div>
            <div class="logo-sub">JavaScript Security Scanner</div>
          </div>
        </a>
        <div class="header-gap"></div>
        <div class="header-end">
          <div class="server-pill">
            <div class="server-dot"></div>
            Go · ${VERSION}
          </div>
          <button class="theme-btn" id="theme-btn" title="Switch dark / light mode">🌙</button>
        </div>
      </header>
      <aside class="sidebar">
        <div class="sb-group">
          <div class="sb-group-label">Scanner</div>
          <button class="sb-btn active" id="nav-scanner" data-nav="scanner">
            <span class="sb-icon">🔍</span> Scan Files
          </button>
        </div>
        <div class="sb-divider"></div>
        <div class="sb-group">
          <div class="sb-group-label">Filter by Category</div>
          ${SIDEBAR_ORDER.map(renderSidebarButton).join("")}
        </div>
        <div class="sb-divider"></div>
        <div class="sb-group">
          <div class="sb-group-label">Actions</div>
          <button class="sb-btn" data-action="export">
            <span class="sb-icon">⬇</span> Export as JSON
          </button>
          <button class="sb-btn" data-action="clear">
            <span class="sb-icon">🗑</span> Clear Results
          </button>
        </div>
      </aside>
      <main class="main">
        <div class="scan-panel">
          <div class="scan-heading">Scan JavaScript Files</div>
          <div class="scan-subtext">
            Paste a <code>.js</code> URL to scan for API keys, hardcoded credentials, XSS sinks, prototype pollution gadgets, GraphQL endpoints, and more.
            Each finding shows a <strong>severity</strong> (impact) and <strong>confidence</strong> (likelihood of being a real issue).
          </div>
          <div class="tabs">
            <button class="tab-btn active" data-tab-target="single">Single URL</button>
            <button class="tab-btn" data-tab-target="batch">Batch (up to 50 URLs)</button>
          </div>
          <div class="tab-pane active" id="pane-single">
            <div class="input-row">
              <input class="url-input" id="inp-single" type="url" placeholder="https://target.com/assets/app.min.js  — press Enter to scan">
              <label class="diff-label" title="Compare findings with the last scan of this URL to see what changed">
                <input type="checkbox" id="diff-mode"> Show diff
              </label>
              <button class="btn btn-primary" id="btn-single">Analyze →</button>
            </div>
          </div>
          <div class="tab-pane" id="pane-batch">
            <textarea class="url-textarea" id="inp-batch" placeholder="One URL per line:&#10;https://target.com/chunk.abc123.js&#10;https://target.com/vendor.js&#10;https://cdn.example.com/app.js"></textarea>
            <div class="input-row">
              <button class="btn btn-primary" id="btn-batch">Analyze All →</button>
              <button class="btn btn-ghost" id="btn-clear-batch">Clear</button>
            </div>
          </div>
          <div class="prog-wrap" id="prog-wrap">
            <div class="prog-track"><div class="prog-fill" id="prog-fill"></div></div>
          </div>
          <div class="prog-text" id="prog-text"></div>
        </div>
        <div class="stats-bar">
          ${STATS.map(renderStatCell).join("")}
        </div>
        <div class="results-area">
          <div class="filter-bar" id="filter-bar" style="display:none">
            <span class="filter-label">Show severity:</span>
            <div class="filter-sep"></div>
            ${SEVERITY_FILTERS.map(renderSeverityChip).join("")}
            <input class="search-input" id="search-input" placeholder="🔎 Search findings…">
          </div>
          <div class="legend-bar" id="legend-bar" style="display:none">
            <span style="font-weight:600;color:var(--text-muted)">Reading results:</span>
            ${LEGEND_ITEMS.map(renderLegendItem).join("")}
          </div>
          <div class="empty-state" id="empty-state">
            <div class="empty-icon">🧅</div>
            <div class="empty-title">Ready to scan</div>
            <div class="empty-body">
              Paste any <code>.js</code> URL above and press <strong>Enter</strong> or click <strong>Analyze →</strong>.<br><br>
              Peelr will check for API keys, hardcoded passwords, XSS sinks, prototype pollution gadgets, GraphQL endpoints, and more.<br><br>
              Each finding shows its <strong>severity</strong> (how bad if real) and <strong>confidence</strong> (how likely it's a real issue, not a false positive).
            </div>
          </div>
          <div id="results-container"></div>
        </div>
      </main>
    </div>
  `;
}

function renderSidebarButton(cat) {
  const meta = CATS[cat];
  const title = meta.hint ? ` title="${x(meta.hint)}"` : "";
  return `
    <button class="sb-btn" id="nav-${cat}" data-cat="${cat}"${title}>
      <span class="sb-icon">${meta.icon}</span> ${meta.label}
      <span class="sb-badge" id="cnt-${cat}">0</span>
    </button>
  `;
}

function renderStatCell(item) {
  return `
    <div class="stat-cell">
      <div class="stat-label">${item.label}</div>
      <div class="stat-num ${item.className}" id="s-${item.id}">0</div>
      <div class="stat-hint">${item.hint}</div>
    </div>
  `;
}

function renderSeverityChip(item) {
  return `<button class="sev-chip on" data-sev="${item.value}">${item.label}</button>`;
}

function renderLegendItem(item) {
  const dot = item.color ? `<span class="legend-dot" style="background:${item.color}"></span>` : "";
  return `<span class="legend-item">${dot}${item.text}</span>`;
}

function bindShellEvents() {
  document.getElementById("theme-btn").addEventListener("click", toggleTheme);
  document.getElementById("btn-single").addEventListener("click", runSingle);
  document.getElementById("btn-batch").addEventListener("click", runBatch);
  document.getElementById("btn-clear-batch").addEventListener("click", clearAll);
  document.getElementById("inp-single").addEventListener("keydown", (event) => {
    if (event.key === "Enter") runSingle();
  });
  document.getElementById("search-input").addEventListener("input", (event) => {
    F.q = event.target.value;
    render();
  });

  document.querySelectorAll("[data-tab-target]").forEach((btn) => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tabTarget, btn));
  });

  document.querySelectorAll(".sev-chip").forEach((btn) => {
    btn.addEventListener("click", () => toggleSev(btn));
  });

  document.querySelectorAll("[data-cat]").forEach((btn) => {
    btn.addEventListener("click", () => filterCat(btn.dataset.cat, btn));
  });

  document.querySelector('[data-action="export"]').addEventListener("click", exportJSON);
  document.querySelector('[data-action="clear"]').addEventListener("click", clearAll);
}

function initTheme() {
  const saved = localStorage.getItem("peelr-theme") || "dark";
  document.documentElement.setAttribute("data-theme", saved);
  syncThemeButton(saved);
}

function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme");
  const next = current === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  localStorage.setItem("peelr-theme", next);
  syncThemeButton(next);
}

function syncThemeButton(theme) {
  const btn = document.getElementById("theme-btn");
  if (btn) btn.textContent = theme === "dark" ? "🌙" : "☀️";
}

function switchTab(name, btn) {
  document.querySelectorAll(".tab-btn").forEach((item) => item.classList.remove("active"));
  document.querySelectorAll(".tab-pane").forEach((pane) => pane.classList.remove("active"));
  btn.classList.add("active");
  document.getElementById(`pane-${name}`).classList.add("active");
}

async function runSingle() {
  const url = document.getElementById("inp-single").value.trim();
  if (!url) {
    toast("Please paste a JavaScript URL.", "err");
    return;
  }

  const diff = document.getElementById("diff-mode").checked;
  setLoading(true, diff ? "Scanning and comparing with previous scan…" : "Fetching and scanning…");

  try {
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, diff }),
    });
    const data = await res.json();
    if (data.error) {
      toast(`Error: ${data.error}`, "err");
      return;
    }
    if (diff && data.diff) {
      renderDiff(data.diff, url);
    } else {
      addResult(data);
      const findings = (data.findings || []).length;
      toast(`Scan complete: ${findings} finding${findings !== 1 ? "s" : ""}`, "ok");
    }
  } catch (error) {
    toast(`Network error: ${error.message}`, "err");
  } finally {
    setLoading(false);
  }
}

async function runBatch() {
  const raw = document.getElementById("inp-batch").value.trim();
  if (!raw) {
    toast("Please enter at least one URL.", "err");
    return;
  }

  const urls = raw.split("\n").map((line) => line.trim()).filter(Boolean);
  if (urls.length > 50) {
    toast("Maximum 50 URLs per batch.", "err");
    return;
  }

  setLoading(true, `Scanning ${urls.length} file${urls.length > 1 ? "s" : ""} concurrently…`);
  setProgress(15);

  try {
    const res = await fetch("/api/analyze/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ urls }),
    });
    setProgress(80);
    const data = await res.json();
    if (data.error) {
      toast(`Error: ${data.error}`, "err");
      return;
    }
    (data.results || []).forEach((result) => addResult(result));
    setProgress(100);
    toast(`Batch complete: ${data.succeeded}/${data.total} files succeeded · ${data.duration}`, "ok");
  } catch (error) {
    toast(`Network error: ${error.message}`, "err");
  } finally {
    setLoading(false);
  }
}

function addResult(result) {
  results.push(result);
  updateStats();
  updateSidebarCounts();
  render();
  document.getElementById("filter-bar").style.display = "";
  document.getElementById("legend-bar").style.display = "";
  document.getElementById("empty-state").style.display = "none";
}

function render() {
  const container = document.getElementById("results-container");
  container.innerHTML = "";
  const q = F.q.toLowerCase();
  const sorted = results.slice().sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));

  sorted.forEach((result) => {
    const idx = results.indexOf(result);
    const filtered = (result.findings || []).filter((finding) => {
      if (!F.sev.has(finding.severity)) return false;
      if (F.cat && finding.category !== F.cat) return false;
      if (q && !finding.value.toLowerCase().includes(q) && !finding.type.toLowerCase().includes(q)) return false;
      return true;
    });

    container.appendChild(buildFileCard(result, filtered, idx));
  });
}

function buildFileCard(result, filtered, idx) {
  const card = document.createElement("div");
  card.className = "file-card";

  const isErr = !!result.error;
  const riskLabel = result.risk_label || "minimal";
  const riskScore = result.risk_score || 0;

  card.innerHTML = `
    <div class="file-header" title="Click to expand / collapse">
      <div class="file-status ${isErr ? "st-err" : "st-ok"}" title="${isErr ? "Fetch failed" : "Fetched successfully"}"></div>
      <div class="file-url">${x(result.url)}</div>
      <div class="file-badges">
        <span class="risk-badge risk-${riskLabel}" title="Risk score ${riskScore}/100">
          Risk: ${riskLabel.toUpperCase()} (${riskScore})
        </span>
        <span class="meta-badge mb-findings">${filtered.length} finding${filtered.length !== 1 ? "s" : ""}</span>
        <span class="meta-badge mb-lines">${result.line_count || 0} lines</span>
      </div>
      <div class="collapse-chevron">▾</div>
    </div>
  `;

  const body = document.createElement("div");
  body.className = "file-body";

  if (isErr) {
    body.innerHTML = `<div style="padding:14px 16px;font-size:12px;color:var(--red);font-family:'JetBrains Mono',monospace">⚠ Fetch failed: ${x(result.error)}</div>`;
  } else {
    const byCat = {};
    filtered.forEach((finding) => {
      (byCat[finding.category] = byCat[finding.category] || []).push(finding);
    });

    Object.entries(byCat).forEach(([cat, items]) => {
      body.appendChild(buildCategoryGroup(cat, items, idx));
    });

    if (!filtered.length) {
      body.innerHTML = `<div style="padding:14px 16px;font-size:12px;color:var(--text-dim)">No findings match the current filters.</div>`;
    }
  }

  card.appendChild(body);
  card.querySelector(".file-header").addEventListener("click", () => card.classList.toggle("closed"));
  return card;
}

function buildCategoryGroup(cat, items, idx) {
  const meta = CATS[cat] || { icon: "•", label: cat };
  const group = document.createElement("div");
  group.className = "cat-group";
  group.innerHTML = `
    <div class="cat-header">
      <span class="cat-emoji">${meta.icon}</span>
      <span class="cat-title">${meta.label}</span>
      <span class="cat-count-badge">${items.length} found</span>
      <span class="cat-chev">▾</span>
    </div>
    <div class="cat-body">
      ${items.map((finding, itemIndex) => buildFindingRow(finding, idx, cat, itemIndex)).join("")}
    </div>
  `;

  group.querySelector(".cat-header").addEventListener("click", () => {
    group.classList.toggle("closed");
  });

  group.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", (event) => {
      event.stopPropagation();
      copyText(btn.dataset.copy);
    });
  });

  group.querySelectorAll("[data-toggle-ctx]").forEach((btn) => {
    btn.addEventListener("click", (event) => {
      event.stopPropagation();
      toggleCtx(btn.dataset.toggleCtx);
    });
  });

  group.querySelectorAll(".finding-value[data-copy]").forEach((value) => {
    value.addEventListener("click", (event) => {
      event.stopPropagation();
      copyText(value.dataset.copy);
    });
  });

  return group;
}

function buildFindingRow(finding, idx, cat, itemIndex) {
  const ctxId = `ctx-${idx}-${cat}-${itemIndex}`;
  const confidence = finding.confidence || "low";
  const safeCopy = attrEscape(finding.value);
  return `
    <div class="finding-row">
      <div>
        <span class="sev-badge sev-${finding.severity}" title="Severity: how bad this could be if it's a real issue">${finding.severity}</span>
      </div>
      <div>
        <span class="conf-badge conf-${confidence}" title="Confidence: how likely this is a real finding vs noise">${confidence}</span>
      </div>
      <div class="finding-type" title="Pattern that matched">${x(finding.type)}</div>
      <div class="finding-value" data-copy="${safeCopy}" title="Click to copy">${x(finding.value)}</div>
      <div class="finding-actions">
        <button class="act-btn" data-toggle-ctx="${ctxId}" title="Show the line of code where this was found">Line</button>
        <button class="act-btn" data-copy="${safeCopy}" title="Copy value to clipboard">Copy</button>
      </div>
      ${finding.note ? `<div class="finding-note">${x(finding.note)}</div>` : ""}
      <div class="code-context" id="${ctxId}">
        <span class="line-num">Line ${finding.line}:</span>${x(finding.context)}
      </div>
    </div>
  `;
}

function renderDiff(diff, url) {
  document.getElementById("empty-state").style.display = "none";
  document.getElementById("filter-bar").style.display = "";
  document.getElementById("legend-bar").style.display = "";

  const newCount = (diff.new || []).length;
  const goneCount = (diff.gone || []).length;
  const card = document.createElement("div");
  card.className = "diff-card";

  card.innerHTML = `
    <div class="diff-header">
      <div class="file-status st-ok"></div>
      <div class="file-url">${x(url)}</div>
      <div class="file-badges">
        <span class="meta-badge" style="background:var(--green-bg);color:var(--green)">Δ Diff Result</span>
        ${newCount ? `<span class="meta-badge mb-findings">+${newCount} new</span>` : ""}
        ${goneCount ? `<span class="meta-badge mb-lines">−${goneCount} gone</span>` : ""}
      </div>
      <div class="collapse-chevron">▾</div>
    </div>
  `;

  const body = document.createElement("div");
  body.className = "diff-body";

  if (diff.is_first_scan) {
    body.innerHTML = `
      <div style="padding:16px;font-size:13px;color:var(--text-muted)">
        This is the first scan of this URL — Peelr has saved it as the baseline.
        Run again with "Show diff" to see what changes next time.
      </div>
    `;
  } else {
    let html = `<div class="diff-meta">Compared with scan from ${x(diff.previous_scan)} · ${diff.unchanged} findings unchanged</div>`;

    if (newCount) {
      html += `<div class="diff-section-title new-section">⬆ New findings since last scan — investigate these</div>`;
      html += (diff.new || []).map((finding) => renderDiffRow(finding, "new")).join("");
    }

    if (goneCount) {
      html += `<div class="diff-section-title gone-section">⬇ Removed since last scan — possibly fixed or rotated</div>`;
      html += (diff.gone || []).map((finding) => renderDiffRow(finding, "gone")).join("");
    }

    if (!newCount && !goneCount) {
      html += `<div class="no-changes">✓ No changes detected since the last scan.</div>`;
    }

    body.innerHTML = html;
  }

  card.appendChild(body);
  card.querySelector(".diff-header").addEventListener("click", () => {
    body.style.display = body.style.display === "none" ? "" : "none";
  });
  body.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", (event) => {
      event.stopPropagation();
      copyText(btn.dataset.copy);
    });
  });
  document.getElementById("results-container").prepend(card);
  toast(`Diff complete: ${newCount} new, ${goneCount} gone`, "ok");
}

function renderDiffRow(finding, kind) {
  const confidence = finding.confidence || "low";
  const safeCopy = attrEscape(finding.value);
  const style = kind === "new" ? ` style="background:rgba(63,185,80,0.04)"` : ` style="opacity:0.45"`;
  const valueStyle = kind === "gone" ? ` style="text-decoration:line-through"` : "";
  const action = kind === "new"
    ? `<div class="finding-actions"><button class="act-btn" data-copy="${safeCopy}">Copy</button></div>`
    : "<div></div>";

  return `
    <div class="finding-row"${style}>
      <div><span class="sev-badge sev-${finding.severity}">${finding.severity}</span></div>
      <div><span class="conf-badge conf-${confidence}">${confidence}</span></div>
      <div class="finding-type">${x(finding.type)}</div>
      <div class="finding-value"${valueStyle}>${x(finding.value)}</div>
      ${action}
    </div>
  `;
}

function updateStats() {
  let total = 0;
  let critical = 0;
  let high = 0;
  let medium = 0;
  let low = 0;

  results.forEach((result) => {
    (result.findings || []).forEach((finding) => {
      total++;
      if (finding.severity === "critical") critical++;
      else if (finding.severity === "high") high++;
      else if (finding.severity === "medium") medium++;
      else low++;
    });
  });

  $t("s-total", total);
  $t("s-critical", critical);
  $t("s-high", high);
  $t("s-medium", medium);
  $t("s-low", low);
  $t("s-files", results.length);
}

function updateSidebarCounts() {
  const counts = {};
  results.forEach((result) => {
    (result.findings || []).forEach((finding) => {
      counts[finding.category] = (counts[finding.category] || 0) + 1;
    });
  });

  Object.keys(CATS).forEach((cat) => {
    const el = document.getElementById(`cnt-${cat}`);
    if (el) el.textContent = counts[cat] || 0;
  });
}

function toggleSev(btn) {
  const severity = btn.dataset.sev;
  if (F.sev.has(severity)) {
    F.sev.delete(severity);
    btn.classList.remove("on");
  } else {
    F.sev.add(severity);
    btn.classList.add("on");
  }
  render();
}

function filterCat(cat, el) {
  F.cat = F.cat === cat ? null : cat;
  document.querySelectorAll(".sidebar .sb-btn").forEach((btn) => btn.classList.remove("active"));
  if (F.cat) el.classList.add("active");
  else document.getElementById("nav-scanner").classList.add("active");
  render();
}

function toggleCtx(id) {
  document.getElementById(id)?.classList.toggle("open");
}

function copyText(value) {
  navigator.clipboard.writeText(value).then(() => {
    toast("Copied to clipboard.", "ok");
  });
}

function exportJSON() {
  if (!results.length) {
    toast("No results to export yet.", "err");
    return;
  }

  const blob = new Blob([JSON.stringify(results, null, 2)], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `peelr-${new Date().toISOString().slice(0, 10)}.json`;
  link.click();
  toast("Exported as JSON.", "ok");
}

function clearAll() {
  results.length = 0;
  document.getElementById("results-container").innerHTML = "";
  document.getElementById("empty-state").style.display = "";
  document.getElementById("filter-bar").style.display = "none";
  document.getElementById("legend-bar").style.display = "none";
  STATS.forEach((item) => $t(`s-${item.id}`, 0));
  Object.keys(CATS).forEach((cat) => $t(`cnt-${cat}`, 0));
  F.cat = null;
  F.q = "";
  F.sev = new Set(SEVERITY_FILTERS.map((item) => item.value));
  document.getElementById("search-input").value = "";
  document.querySelectorAll(".sev-chip").forEach((btn) => btn.classList.add("on"));
  document.querySelectorAll(".sidebar .sb-btn").forEach((btn) => btn.classList.remove("active"));
  document.getElementById("nav-scanner").classList.add("active");
}

function setProgress(percent) {
  document.getElementById("prog-fill").style.width = `${percent}%`;
  document.getElementById("prog-wrap").classList.toggle("on", percent > 0 && percent < 100);
}

function setLoading(on, label = "") {
  document.querySelectorAll(".btn").forEach((btn) => {
    btn.disabled = on;
  });
  const text = document.getElementById("prog-text");
  text.textContent = label;
  text.classList.toggle("on", on);
  if (on) setProgress(25);
  else {
    setProgress(100);
    setTimeout(() => setProgress(0), 500);
  }
}

function toast(msg, type = "info") {
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = msg;
  document.getElementById("toasts").appendChild(el);
  setTimeout(() => el.remove(), 3800);
}

function $t(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function x(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function attrEscape(value) {
  return String(value).replace(/&/g, "&amp;").replace(/"/g, "&quot;");
}
