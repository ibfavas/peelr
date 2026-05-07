const VERSION = "2.0.0";

const CATEGORY_LABELS = {
  api_keys: "API Keys",
  credentials: "Credentials",
  emails: "Emails",
  xss: "XSS",
  endpoints: "API Endpoints",
  parameters: "Parameters",
  paths: "Paths",
  comments: "Comments",
};

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

const state = {
  job: null,
  polling: null,
  renderToken: "",
  expandedResults: new Set(),
  visibleResultLimit: 18,
  queryTimer: null,
  filters: {
    category: "api_keys",
    severity: "high",
    query: "",
    includeLowSignal: false,
  },
};

window.addEventListener("DOMContentLoaded", boot);

function boot() {
  const app = document.getElementById("app");
  if (!app) return;

  try {
    app.innerHTML = buildMarkup();
    bindEvents();
  } catch (error) {
    app.innerHTML = `
      <div style="padding:24px;color:#fff;font-family:monospace">
        <h2>Peelr UI failed to load</h2>
        <pre>${escapeHtml(String(error && error.stack ? error.stack : error))}</pre>
      </div>
    `;
  }
}

function buildMarkup() {
  return `
    <div class="app-shell">
      <section class="hero-window">
        <div class="hero-bar">
          <div class="hero-dots"><span></span><span></span><span></span></div>
          <div class="hero-title">peelr://${VERSION}</div>
        </div>
        <div class="hero-body">
          <div class="brand-panel">
            <pre class="ascii">    ____            __
   / __ \\___  ___  / /____
  / /_/ / _ \\/ _ \\/ / ___/
 / ____/  __/  __/ / /
/_/    \\___/\\___/_/_/</pre>
            <div class="hero-copy">
              <h1>JavaScript Recon Console</h1>
              <p>Paste JavaScript URLs directly or upload a JavaScript URL list for focused analysis without domain discovery overhead.</p>
            </div>
          </div>

          <div class="fastfetch-panel">
            ${fastfetchRow("engine", "go stdlib")}
            ${fastfetchRow("input", "javascript urls only")}
            ${fastfetchRow("upload", "txt, csv, list")}
            ${fastfetchRow("focus", "secrets, xss, endpoints, params")}
            ${fastfetchRow("output", "live grouped results with show code")}
            ${fastfetchRow("theme", "cyberpunk terminal")}
          </div>
        </div>

      </section>

      <section class="control-window">
        <div class="window-head">
          <div>
            <h2>Scan JavaScript URLs</h2>
            <p>Provide one or more direct JavaScript URLs. Peelr fetches each file and analyzes the result.</p>
          </div>
          <div class="head-badge">dark console ui</div>
        </div>

        <div class="command-strip">
          <span class="prompt">guest@peelr:~$</span>
          <span>analyze js-urls --fetch</span>
        </div>

        <div class="mode-panel" id="pane-js">
          <div class="field-grid">
            <label class="input-block wide">
              <span>JavaScript URLs</span>
              <textarea id="js-urls-input" placeholder="https://target.com/app.js&#10;https://cdn.target.com/vendor.min.js"></textarea>
              <small>Paste direct JavaScript URLs. Peelr will fetch and analyze each file.</small>
            </label>
            <div class="input-block">
              <span>Upload JS URL list</span>
              ${uploadBox("js-upload-btn", "js-files", "js-upload-name", "Choose list")}
              <small>Accepts one JavaScript URL per line.</small>
            </div>
          </div>
        </div>

        <div class="actions-row">
          <button id="run-btn" class="run-btn">Run Analysis</button>
          <div id="run-meta" class="run-meta">idle</div>
        </div>
      </section>

      <section class="status-window">
        <div class="stats-row">
          ${statCard("sources", "0", "js files queued")}
          ${statCard("processed", "0", "finished scans")}
          ${statCard("findings", "0", "total matches")}
          ${statCard("high risk", "0", "critical or high")}
        </div>

        <div class="runtime-card">
          <div class="window-head compact">
            <h2>Runtime</h2>
            <div id="job-status" class="status-pill idle">waiting</div>
          </div>
          <div class="runtime-log">
            <div><span class="prompt">log&gt;</span> scheduler ready</div>
            <div id="job-summary">No analysis has been started.</div>
          </div>
          <div class="progress-track"><div id="progress-fill" class="progress-fill"></div></div>
        </div>
      </section>

      <section class="results-window">
        <div class="window-head">
          <div>
            <h2>Analysis Results</h2>
            <p>High-signal findings are prioritized by default. Low and info items stay available without flooding the browser.</p>
          </div>
          <div class="results-controls">
            <label class="search-block">
              <span>Search</span>
              <input id="filter-query" type="text" placeholder="token, innerHTML, /api, email">
            </label>
            <button id="low-signal-toggle" class="chip-btn secondary-chip" type="button">Include Lower-Signal</button>
          </div>
        </div>

        <div class="filter-stack">
          <div class="button-group wrap">${categoryButtons()}</div>
          <div class="button-group wrap">${severityButtons()}</div>
        </div>

        <div id="results" class="results-list">
          <div class="empty-state">
            <div class="empty-title">Ready</div>
            <p>Run a scan and the JavaScript URL analysis will appear here.</p>
          </div>
        </div>
      </section>
    </div>
  `;
}

function categoryButtons() {
  return Object.keys(CATEGORY_LABELS).map((key) => {
    const active = key === "api_keys" ? "active" : "";
    return `<button class="chip-btn ${active}" data-category="${key}">${CATEGORY_LABELS[key]}</button>`;
  }).join("");
}

function severityButtons() {
  return SEVERITIES.map((severity) => {
    const active = severity === "high" ? "active" : "";
    return `<button class="chip-btn ${active}" data-severity="${severity}">${capitalize(severity)}</button>`;
  }).join("");
}

function fastfetchRow(label, value) {
  return `<div class="fastfetch-row"><span>${label}</span><strong>${value}</strong></div>`;
}

function featureCard(label, value) {
  return `<div class="feature-card"><div class="feature-title">${label}</div><div class="feature-text">${value}</div></div>`;
}

function statCard(label, value, hint) {
  return `<div class="stat-card"><span>${label}</span><strong data-stat="${label}">${value}</strong><small>${hint}</small></div>`;
}

function uploadBox(buttonId, inputId, nameId, buttonLabel) {
  return `
    <div class="upload-box">
      <input id="${inputId}" class="hidden-file" type="file" multiple accept=".txt,.csv,.list">
      <button id="${buttonId}" type="button" class="upload-btn">${buttonLabel}</button>
      <div id="${nameId}" class="upload-name">No file selected</div>
    </div>
  `;
}

function bindEvents() {
  document.querySelectorAll("[data-category]").forEach((btn) => {
    btn.addEventListener("click", () => setCategory(btn.dataset.category));
  });
  document.querySelectorAll("[data-severity]").forEach((btn) => {
    btn.addEventListener("click", () => setSeverity(btn.dataset.severity));
  });
  byId("filter-query").addEventListener("input", (event) => {
    clearTimeout(state.queryTimer);
    state.queryTimer = setTimeout(() => {
      state.filters.query = event.target.value.trim().toLowerCase();
      renderResults();
    }, 120);
  });
  byId("low-signal-toggle").addEventListener("click", toggleLowSignal);
  byId("run-btn").addEventListener("click", startJob);
  bindUploadPicker("js-upload-btn", "js-files", "js-upload-name");
  byId("results").addEventListener("click", handleResultsClick);
}

function bindUploadPicker(buttonId, inputId, nameId) {
  const button = byId(buttonId);
  const input = byId(inputId);
  const name = byId(nameId);
  if (!button || !input || !name) return;
  button.addEventListener("click", () => input.click());
  input.addEventListener("change", () => {
    name.textContent = input.files.length
      ? Array.from(input.files).map((file) => file.name).join(", ")
      : "No file selected";
  });
}

function setCategory(category) {
  state.filters.category = category;
  document.querySelectorAll("[data-category]").forEach((btn) => btn.classList.toggle("active", btn.dataset.category === category));
  renderResults();
}

function setSeverity(severity) {
  state.filters.severity = severity;
  document.querySelectorAll("[data-severity]").forEach((btn) => btn.classList.toggle("active", btn.dataset.severity === severity));
  renderResults();
}

function toggleLowSignal() {
  state.filters.includeLowSignal = !state.filters.includeLowSignal;
  byId("low-signal-toggle").classList.toggle("active", state.filters.includeLowSignal);
  byId("low-signal-toggle").textContent = state.filters.includeLowSignal ? "Hide Lower-Signal" : "Include Lower-Signal";
  renderResults();
}

async function startJob() {
  const formData = new FormData();
  formData.append("mode", "js");
  formData.append("urls", byId("js-urls-input").value);
  for (const file of byId("js-files").files) {
    formData.append("uploads", file);
  }

  setRunState("submitting");
  try {
    const response = await fetch("/api/jobs", { method: "POST", body: formData });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "unable to create job");
    }
    state.job = null;
    state.expandedResults.clear();
    state.visibleResultLimit = 18;
    state.renderToken = "";
    pollJob(payload.job_id);
  } catch (error) {
    setRunState(error.message, true);
  }
}

function pollJob(jobID) {
  clearInterval(state.polling);
  fetchJob(jobID);
  state.polling = setInterval(() => fetchJob(jobID), 1200);
}

async function fetchJob(jobID) {
  try {
    const response = await fetch(`/api/jobs/${jobID}`);
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "unable to load job");
    }
    state.job = payload;
    renderJob();
    renderResults();
    if (payload.status === "completed") {
      clearInterval(state.polling);
      state.polling = null;
      setRunState(`completed ${payload.completed}/${payload.total}`);
    }
  } catch (error) {
    clearInterval(state.polling);
    state.polling = null;
    setRunState(error.message, true);
  }
}

function renderJob() {
  if (!state.job) return;
  const job = state.job;
  const findings = job.results.reduce((sum, result) => sum + ((result.findings || []).length), 0);
  const highRisk = job.results.filter((result) => ["critical", "high"].includes(result.summary && result.summary.risk_label)).length;
  const progress = job.total ? Math.round((job.completed / job.total) * 100) : 0;

  updateStat("sources", String(job.total));
  updateStat("processed", String(job.completed));
  updateStat("findings", String(findings));
  updateStat("high risk", String(highRisk));
  byId("progress-fill").style.width = `${progress}%`;

  const statusEl = byId("job-status");
  statusEl.textContent = job.status;
  statusEl.className = `status-pill ${job.status}`;
  byId("job-summary").textContent = `log> ${job.completed}/${job.total} javascript files processed, ${findings} findings collected`;
}

function renderResults() {
  const root = byId("results");
  if (!state.job || !root) return;

  const completed = (state.job.results || []).filter((result) => result.status === "completed" || result.status === "failed");
  const pendingCount = Math.max(0, (state.job.total || 0) - completed.length);
  const sorted = completed.slice().sort(compareResults);
  const renderable = sorted.filter((result) => shouldRenderResult(result));
  const visible = renderable.slice(0, state.visibleResultLimit);
  const hiddenResults = Math.max(0, renderable.length - visible.length);

  const token = JSON.stringify({
    status: state.job.status,
    completed: state.job.completed,
    total: state.job.total,
    filters: state.filters,
    visibleResultLimit: state.visibleResultLimit,
    expanded: Array.from(state.expandedResults).sort(),
    results: completed.map((result) => ({
      id: result.id,
      error: result.error,
      status: result.status,
      risk: result.summary && result.summary.risk_label,
      findings: (result.findings || []).length,
    })),
  });
  if (token === state.renderToken) return;
  state.renderToken = token;

  const cards = visible.map((result) => renderResultCard(result)).join("");
  const pending = pendingCount > 0 ? `<div class="pending-summary">${pendingCount} files are still being fetched or analyzed.</div>` : "";
  const more = hiddenResults > 0 ? `<button class="more-results-btn" data-expand-results="true">Show ${hiddenResults} more files</button>` : "";
  root.innerHTML = cards || pending || `<div class="empty-state"><div class="empty-title">No Matches</div><p>The current filters hide all findings or the analyzed JavaScript was clean.</p></div>`;
  if (cards) {
    root.insertAdjacentHTML("beforeend", `${pending}${more}`);
  }
}

function shouldRenderResult(result) {
  if (result.error) return true;
  if (state.job && state.job.status !== "completed") return true;
  return filterFindings(result.findings || []).length > 0;
}

function renderResultCard(result) {
  const filtered = filterFindings(result.findings || []);
  const findings = state.expandedResults.has(result.id) ? filtered : filtered.slice(0, 24);
  const hiddenCount = filtered.length - findings.length;
  if (state.job && state.job.status === "completed" && filtered.length === 0 && !result.error) return "";

  return `
    <article class="result-card">
      <div class="result-head">
        <div>
          <div class="result-name">${escapeHtml(result.name || result.origin || "source")}</div>
          <div class="result-origin">${escapeHtml(result.origin || result.kind || "")}</div>
        </div>
        <div class="risk-badge ${(result.summary && result.summary.risk_label) || "minimal"}">${(result.summary && result.summary.risk_label) || result.status}</div>
      </div>
      <div class="result-meta">
        <span>${result.line_count || 0} lines</span>
        <span>${(result.findings || []).length} findings</span>
        <span>${filtered.length} visible</span>
        <span>${(result.summary && result.summary.network_requests) || 0} requests</span>
        <span>${(result.summary && result.summary.sensitive_params) || 0} sensitive params</span>
      </div>
      ${result.error ? `<div class="error-box">${escapeHtml(result.error)}</div>` : renderFindingList(result.id, findings, hiddenCount, result.status)}
    </article>
  `;
}

function renderFindingList(resultID, findings, hiddenCount, status) {
  if (!findings.length) {
    return `<div class="pending-box">${status === "completed" ? "No findings match the current filters." : "Waiting for analysis output..."}</div>`;
  }

  const rows = findings.map((finding) => `
    <div class="finding ${finding.severity}">
      <div class="finding-head">
        <div>
          <div class="finding-title">${escapeHtml(finding.title)}</div>
          <div class="finding-sub">${escapeHtml(CATEGORY_LABELS[finding.category] || finding.category)} · line ${finding.line} · ${escapeHtml(finding.confidence)}</div>
        </div>
        <span class="sev-tag ${finding.severity}">${finding.severity}</span>
      </div>
      <div class="finding-value">${escapeHtml(finding.value || finding.context || "")}</div>
      ${renderFindingContext(finding)}
      ${finding.note ? `<div class="finding-note">${escapeHtml(finding.note)}</div>` : ""}
      <details class="snippet">
        <summary>Show Code</summary>
        <pre>${escapeHtml(trimSnippet(finding.snippet || ""))}</pre>
      </details>
    </div>
  `).join("");

  if (hiddenCount <= 0) return rows;
  return `${rows}<button class="more-btn" data-expand-result="${escapeHtml(resultID)}">Show ${hiddenCount} more findings</button>`;
}

function filterFindings(findings) {
  return findings
    .filter((finding) => {
      if (!state.filters.includeLowSignal && !state.filters.query) {
        if (finding.severity === "low" || finding.severity === "info") return false;
      }
      if (state.filters.category && finding.category !== state.filters.category) return false;
      if (state.filters.severity && finding.severity !== state.filters.severity) return false;
      if (!state.filters.query) return true;
      const haystack = `${finding.title} ${finding.value} ${finding.context} ${finding.note || ""}`.toLowerCase();
      return haystack.includes(state.filters.query);
    })
    .sort(compareFindings);
}

function compareResults(a, b) {
  const riskOrder = { critical: 5, high: 4, medium: 3, low: 2, minimal: 1 };
  const aRisk = riskOrder[(a.summary && a.summary.risk_label) || "minimal"] || 0;
  const bRisk = riskOrder[(b.summary && b.summary.risk_label) || "minimal"] || 0;
  if (aRisk !== bRisk) return bRisk - aRisk;
  return ((b.findings || []).length - (a.findings || []).length);
}

function compareFindings(a, b) {
  const severityOrder = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  const aSeverity = severityOrder[a.severity] || 0;
  const bSeverity = severityOrder[b.severity] || 0;
  if (aSeverity !== bSeverity) return bSeverity - aSeverity;
  if (a.confidence !== b.confidence) {
    const confidenceOrder = { high: 3, medium: 2, low: 1 };
    return (confidenceOrder[b.confidence] || 0) - (confidenceOrder[a.confidence] || 0);
  }
  return a.line - b.line;
}

function handleResultsClick(event) {
  const expandResultsButton = event.target.closest("[data-expand-results]");
  if (expandResultsButton) {
    state.visibleResultLimit += 18;
    renderResults();
    return;
  }
  const expandButton = event.target.closest("[data-expand-result]");
  if (!expandButton) return;
  const id = expandButton.getAttribute("data-expand-result");
  if (!id) return;
  state.expandedResults.add(id);
  renderResults();
}

function updateStat(label, value) {
  const node = document.querySelector(`[data-stat="${label}"]`);
  if (node) node.textContent = value;
}

function setRunState(text, isError) {
  const meta = byId("run-meta");
  if (!meta) return;
  meta.textContent = text;
  meta.classList.toggle("error", !!isError);
}

function byId(id) {
  return document.getElementById(id);
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function capitalize(value) {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function renderFindingContext(finding) {
  if (!finding.context || finding.context === finding.value) return "";
  return `<div class="finding-context">${escapeHtml(finding.context)}</div>`;
}

function trimSnippet(snippet) {
  const lines = String(snippet).split("\n");
  if (lines.length <= 18) return snippet;
  return `${lines.slice(0, 18).join("\n")}\n...`;
}
