const state = {
  findings: [],
  filtered: [],
  selectedId: null,
  statFilter: "",
  pollStatus: null,
};


const el = {
  cards: document.getElementById("cards"),
  stats: document.getElementById("stats"),
  search: document.getElementById("search"),
  category: document.getElementById("category"),
  ecosystem: document.getElementById("ecosystem"),
  triageState: document.getElementById("triage-state"),
  sortBy: document.getElementById("sort-by"),
  confidence: document.getElementById("confidence"),
  confidenceValue: document.getElementById("confidence-value"),
  epssMin: document.getElementById("epss-min"),
  epssMinValue: document.getElementById("epss-min-value"),
  evidenceMin: document.getElementById("evidence-min"),
  evidenceMinValue: document.getElementById("evidence-min-value"),
  hasKev: document.getElementById("has-kev"),
  hasFix: document.getElementById("has-fix"),
  hasRegional: document.getElementById("has-regional"),
  hasVendorCorroboration: document.getElementById("has-vendor-corroboration"),
  hasDistroContext: document.getElementById("has-distro-context"),
  inScope: document.getElementById("in-scope"),
  hasContradiction: document.getElementById("has-contradiction"),
  hasAtlas: document.getElementById("has-atlas"),
  hasAttack: document.getElementById("has-attack"),
  highMitre: document.getElementById("high-mitre"),
  resetFilters: document.getElementById("reset-filters"),
  refresh: document.getElementById("refresh"),
  exportCsv: document.getElementById("export-csv"),
  detailTitle: document.getElementById("detail-title"),
  detailMeta: document.getElementById("detail-meta"),
  detailContent: document.getElementById("detail-content"),
  vendorPanel: document.getElementById("vendor-panel"),
  vendorSummary: document.getElementById("vendor-summary"),
  triageEditState: document.getElementById("triage-edit-state"),
  triageEditNote: document.getElementById("triage-edit-note"),
  triageSave: document.getElementById("triage-save"),
  mitrePanel: document.getElementById("mitre-panel"),
  mitreSummary: document.getElementById("mitre-summary"),
  atlasList: document.getElementById("atlas-list"),
  attackList: document.getElementById("attack-list"),
  viewRadar: document.getElementById("view-radar"),
  viewDocs: document.getElementById("view-docs"),
  viewTabs: document.querySelectorAll(".view-tab"),
  docLinks: document.querySelectorAll(".doc-link"),
  docTitle: document.getElementById("doc-title"),
  docBody: document.getElementById("doc-body"),
  pollEnabled: document.getElementById("poll-enabled"),
  pollInterval: document.getElementById("poll-interval"),
  pollIntervalValue: document.getElementById("poll-interval-value"),
  pollSave: document.getElementById("poll-save"),
  pollRunNow: document.getElementById("poll-run-now"),
  pollSummary: document.getElementById("poll-summary"),
  pollSources: document.getElementById("poll-sources"),
};

function fmt(n) {
  return Number(n || 0).toFixed(2);
}

function parseDate(value) {
  const t = Date.parse(value || "");
  return Number.isNaN(t) ? 0 : t;
}

function hasHighMitre(f) {
  const all = [...(f.atlas_matches || []), ...(f.attack_matches || [])];
  return all.some((m) => m.confidence === "high");
}

function techniquePreview(matches) {
  if (!matches || !matches.length) return "none";
  return matches
    .slice(0, 2)
    .map((m) => m.technique_id)
    .join(", ");
}

function textPreview(items) {
  if (!items || !items.length) return "none";
  return items.slice(0, 2).join(", ");
}


function normalizedSources(f) {
  return new Set((f.regional_sources || []).map((s) => String(s).toLowerCase()));
}

function hasMsrcSignal(f) {
  const src = normalizedSources(f);
  return src.has("msrc");
}

function hasRedHatSignal(f) {
  const src = normalizedSources(f);
  return src.has("red hat security data api");
}

function hasDebianSignal(f) {
  const src = normalizedSources(f);
  return src.has("debian security tracker");
}

function hasVendorCorroboration(f) {
  return hasMsrcSignal(f) || hasRedHatSignal(f) || hasDebianSignal(f);
}

function hasDistroContext(f) {
  return hasDebianSignal(f);
}

function vendorCorroborationSummary(f) {
  const lines = [];
  const sourceLines = [];
  sourceLines.push(`MSRC: ${hasMsrcSignal(f) ? "yes" : "no"}`);
  sourceLines.push(`Red Hat: ${hasRedHatSignal(f) ? "yes" : "no"}`);
  sourceLines.push(`Debian: ${hasDebianSignal(f) ? "yes" : "no"}`);
  lines.push(sourceLines.join(" | "));

  const vendorSources = (f.regional_sources || []).filter((s) => {
    const x = String(s).toLowerCase();
    return x === "msrc" || x === "red hat security data api" || x === "debian security tracker";
  });
  lines.push(`Matched sources: ${vendorSources.length ? vendorSources.join(", ") : "none"}`);
  lines.push(`Packages (preview): ${textPreview(f.packages)}`);
  lines.push(`Fix context (preview): ${textPreview(f.fixed_versions)}`);
  return lines.join("\n");
}
function resetDetailPanel(message) {
  el.detailTitle.textContent = "Select a CVE";
  el.detailMeta.textContent = "";
  el.triageEditState.value = "new";
  el.triageEditNote.value = "";
  el.mitrePanel.classList.add("hidden");
  if (el.vendorSummary) {
    el.vendorSummary.textContent = "Select a finding to view vendor and distro corroboration details.";
  }
  el.detailContent.textContent = message;
}

function sortFindings(list) {
  const mode = el.sortBy.value;
  const sorted = [...list];
  if (mode === "published") {
    sorted.sort((a, b) => parseDate(b.published) - parseDate(a.published));
  } else if (mode === "confidence") {
    sorted.sort((a, b) => Number(b.confidence || 0) - Number(a.confidence || 0));
  } else if (mode === "epss") {
    sorted.sort((a, b) => Number(b.epss_score || 0) - Number(a.epss_score || 0));
  } else {
    sorted.sort((a, b) => Number(b.priority_score || 0) - Number(a.priority_score || 0));
  }
  return sorted;
}

async function loadFindings() {
  const res = await fetch("/api/findings", { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to load findings");
  state.findings = await res.json();
  populateCategoryOptions();
  populateEcosystemOptions();
  applyFilters();
  renderStats();
}

function populateCategoryOptions() {
  const categories = new Set();
  for (const f of state.findings) {
    for (const c of f.categories || []) categories.add(c);
  }
  const existing = el.category.value;
  el.category.innerHTML = '<option value="">All</option>';
  Array.from(categories)
    .sort()
    .forEach((c) => {
      const option = document.createElement("option");
      option.value = c;
      option.textContent = c;
      el.category.appendChild(option);
    });
  el.category.value = existing;
}

function populateEcosystemOptions() {
  const ecosystems = new Set();
  for (const f of state.findings) {
    for (const e of f.ecosystems || []) ecosystems.add(e);
  }
  const existing = el.ecosystem.value;
  el.ecosystem.innerHTML = '<option value="">All</option>';
  Array.from(ecosystems)
    .sort()
    .forEach((e) => {
      const option = document.createElement("option");
      option.value = e;
      option.textContent = e;
      el.ecosystem.appendChild(option);
    });
  el.ecosystem.value = existing;
}

function applyFilters() {
  const q = el.search.value.trim().toLowerCase();
  const minConfidence = Number(el.confidence.value);
  const minEpss = Number(el.epssMin.value);
  const minEvidence = Number(el.evidenceMin.value);
  const category = el.category.value;
  const ecosystem = el.ecosystem.value;
  const triageState = el.triageState.value;
  const mustHaveKev = el.hasKev.checked;
  const mustHaveFix = el.hasFix.checked;
  const mustHaveRegional = el.hasRegional.checked;
  const mustHaveVendorCorroboration = el.hasVendorCorroboration.checked;
  const mustHaveDistroContext = el.hasDistroContext.checked;
  const mustBeInScope = el.inScope.checked;
  const mustHaveContradiction = el.hasContradiction.checked;
  const mustHaveAtlas = el.hasAtlas.checked;
  const mustHaveAttack = el.hasAttack.checked;
  const mustBeHighMitre = el.highMitre.checked;
  const statFilter = state.statFilter;

  const filtered = state.findings.filter((f) => {
    const confidenceOk = Number(f.confidence || 0) >= minConfidence;
    const epssOk = Number(f.epss_score || 0) >= minEpss;
    const evidenceOk = Number(f.evidence_score || 0) >= minEvidence;
    const categoryOk = !category || (f.categories || []).includes(category);
    const ecosystemOk = !ecosystem || (f.ecosystems || []).includes(ecosystem);
    const triageOk = !triageState || String(f.triage_state || "new") === triageState;
    const kevOk = !mustHaveKev || Boolean(f.kev_status);
    const fixOk = !mustHaveFix || Boolean(f.has_fix);
    const regionalOk = !mustHaveRegional || Number(f.regional_signal_count || 0) > 0;
    const vendorCorroborationOk = !mustHaveVendorCorroboration || hasVendorCorroboration(f);
    const distroContextOk = !mustHaveDistroContext || hasDistroContext(f);
    const inScopeOk = !mustBeInScope || Boolean(f.asset_in_scope);
    const contradictionOk = !mustHaveContradiction || (f.contradiction_flags || []).length > 0;
    const atlasOk = !mustHaveAtlas || (f.atlas_matches || []).length > 0;
    const attackOk = !mustHaveAttack || (f.attack_matches || []).length > 0;
    const highMitreOk = !mustBeHighMitre || hasHighMitre(f);
    const statOk =
      !statFilter ||
      (statFilter === "high" && Number(f.confidence || 0) >= 0.75) ||
      (statFilter === "atlas" && (f.atlas_matches || []).length > 0) ||
      (statFilter === "attack" && (f.attack_matches || []).length > 0) ||
      (statFilter === "kev" && Boolean(f.kev_status)) ||
      (statFilter === "fix" && Boolean(f.has_fix)) ||
      (statFilter === "regional" && Number(f.regional_signal_count || 0) > 0) ||
      (statFilter === "scope" && Boolean(f.asset_in_scope));

    const blob = [
      f.cve_id,
      ...(f.matched_keywords || []),
      ...(f.cwes || []),
      ...(f.categories || []),
      ...(f.ecosystems || []),
      ...(f.packages || []),
      ...(f.fixed_versions || []),
      ...(f.atlas_matches || []).map((m) => m.technique_id),
      ...(f.attack_matches || []).map((m) => m.technique_id),
      f.summary,
      f.correlation_summary,
      f.priority_reason,
      f.evidence_reason,
      f.asset_scope_reason,
      f.triage_state,
      f.triage_note,
      f.change_type,
      f.change_reason,
      ...(f.regional_sources || []),
    ]
      .join(" ")
      .toLowerCase();

    const queryOk = !q || blob.includes(q);
    return (
      confidenceOk &&
      epssOk &&
      evidenceOk &&
      categoryOk &&
      ecosystemOk &&
      triageOk &&
      kevOk &&
      fixOk &&
      regionalOk &&
      vendorCorroborationOk &&
      distroContextOk &&
      inScopeOk &&
      contradictionOk &&
      atlasOk &&
      attackOk &&
      highMitreOk &&
      statOk &&
      queryOk
    );
  });

  state.filtered = sortFindings(filtered);

  if (!state.filtered.length) {
    state.selectedId = null;
    resetDetailPanel(
      state.findings.length
        ? "No findings match current filters."
        : "No findings loaded yet. Use Poll Now to fetch data."
    );
    renderCards();
    return;
  }

  const selectedVisible = state.filtered.find((f) => f.cve_id === state.selectedId);
  if (!selectedVisible) {
    void selectFinding(state.filtered[0]);
    return;
  }

  renderCards();
}

function renderStats() {
  const total = state.findings.length;
  const high = state.findings.filter((f) => Number(f.confidence || 0) >= 0.75).length;
  const kevLinked = state.findings.filter((f) => Boolean(f.kev_status)).length;
  const fixLinked = state.findings.filter((f) => Boolean(f.has_fix)).length;
  const regionalLinked = state.findings.filter((f) => Number(f.regional_signal_count || 0) > 0).length;
  const scopeLinked = state.findings.filter((f) => Boolean(f.asset_in_scope)).length;
  const atlasLinked = state.findings.filter((f) => (f.atlas_matches || []).length > 0).length;
  const attackLinked = state.findings.filter((f) => (f.attack_matches || []).length > 0).length;
  el.stats.innerHTML = `
    <button class="stat stat-button ${state.statFilter === "" ? "active" : ""}" data-stat-filter="all">Findings: ${total}</button>
    <button class="stat stat-button ${state.statFilter === "high" ? "active" : ""}" data-stat-filter="high">High-confidence: ${high}</button>
    <button class="stat stat-button ${state.statFilter === "regional" ? "active" : ""}" data-stat-filter="regional">Regional intel: ${regionalLinked}</button>
    <button class="stat stat-button ${state.statFilter === "kev" ? "active" : ""}" data-stat-filter="kev">KEV linked: ${kevLinked}</button>
    <button class="stat stat-button ${state.statFilter === "fix" ? "active" : ""}" data-stat-filter="fix">Fix available: ${fixLinked}</button>
    <button class="stat stat-button ${state.statFilter === "scope" ? "active" : ""}" data-stat-filter="scope">In scope: ${scopeLinked}</button>
    <button class="stat stat-button ${state.statFilter === "atlas" ? "active" : ""}" data-stat-filter="atlas">ATLAS linked: ${atlasLinked}</button>
    <button class="stat stat-button ${state.statFilter === "attack" ? "active" : ""}" data-stat-filter="attack">ATT&CK linked: ${attackLinked}</button>
  `;
}

function renderCards() {
  if (!state.filtered.length) {
    el.cards.innerHTML = state.findings.length
      ? "<p>No findings match filters.</p>"
      : "<p>No findings loaded yet. Use Poll Now to fetch data.</p>";
    return;
  }

  el.cards.innerHTML = "";
  state.filtered.forEach((f, i) => {
    const card = document.createElement("div");
    card.className = "card" + (state.selectedId === f.cve_id ? " active" : "");
    card.style.animationDelay = `${Math.min(i * 25, 320)}ms`;
    card.innerHTML = `
      <h3>${f.cve_id}</h3>
      <p>${f.summary || "No summary"}</p>
      <div class="badges">
        <span class="badge">priority ${fmt(f.priority_score)}</span>
        <span class="badge">evidence ${fmt(f.evidence_score)}</span>
        <span class="badge">change ${f.change_type || "new"}</span>
        <span class="badge">confidence ${fmt(f.confidence)}</span>
        <span class="badge">EPSS ${fmt(f.epss_score)}</span>
        <span class="badge">KEV ${f.kev_status ? "yes" : "no"}</span>
        <span class="badge">fix ${f.has_fix ? "yes" : "no"}</span>
        <span class="badge">scope ${f.asset_in_scope ? "yes" : "no"}</span>
        <span class="badge">regional ${Number(f.regional_signal_count || 0)}</span>
        ${hasMsrcSignal(f) ? `<span class="badge badge-vendor">MSRC</span>` : ""}
        ${hasRedHatSignal(f) ? `<span class="badge badge-vendor">Red Hat</span>` : ""}
        ${hasDebianSignal(f) ? `<span class="badge badge-distro">Debian</span>` : ""}
      </div>
      <p class="tech-line">Ecosystems: ${textPreview(f.ecosystems)}</p>
      <p class="tech-line">Fixes: ${textPreview(f.fixed_versions)}</p>
      <p class="tech-line">Triage: ${f.triage_state || "new"}</p>
      <p class="tech-line">ATLAS: ${techniquePreview(f.atlas_matches)}</p>
      <p class="tech-line">ATT&CK: ${techniquePreview(f.attack_matches)}</p>
    `;
    card.addEventListener("click", () => selectFinding(f));
    el.cards.appendChild(card);
  });
}

function renderMitreList(target, matches) {
  target.innerHTML = "";
  if (!matches || !matches.length) {
    target.innerHTML = "<li>None</li>";
    return;
  }

  for (const m of matches) {
    const li = document.createElement("li");
    li.textContent = `${m.technique_id} ${m.technique_name} (${m.confidence})`;
    target.appendChild(li);
  }
}

function renderMitrePanel(f) {
  const hasData = (f.atlas_matches || []).length > 0 || (f.attack_matches || []).length > 0;
  el.mitrePanel.classList.toggle("hidden", !hasData);
  if (!hasData) return;

  el.mitreSummary.textContent = f.correlation_summary || "No MITRE correlation summary available.";
  renderMitreList(el.atlasList, f.atlas_matches || []);
  renderMitreList(el.attackList, f.attack_matches || []);
}

function getSelectedFinding() {
  return state.findings.find((f) => f.cve_id === state.selectedId) || null;
}

async function saveTriage() {
  const selected = getSelectedFinding();
  if (!selected) return;

  const payload = {
    state: el.triageEditState.value,
    note: el.triageEditNote.value,
  };

  const res = await fetch(`/api/triage/${encodeURIComponent(selected.cve_id)}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    throw new Error("Failed to save triage");
  }

  await loadFindings();
  const updated = state.findings.find((f) => f.cve_id === selected.cve_id);
  if (updated) {
    await selectFinding(updated);
  }
}

async function selectFinding(f) {
  state.selectedId = f.cve_id;
  renderCards();

  el.detailTitle.textContent = f.cve_id;
  el.detailMeta.textContent =
    `Published: ${f.published || "N/A"} | Priority: ${fmt(f.priority_score)} | ` +
    `Evidence: ${fmt(f.evidence_score)} | Change: ${f.change_type || "new"} | ` +
    `EPSS: ${fmt(f.epss_score)} | KEV: ${f.kev_status ? "Yes" : "No"} | ` +
    `Fix: ${f.has_fix ? "Yes" : "No"} | Scope: ${f.asset_in_scope ? "Yes" : "No"} | ` +
    `Vendor corroboration: ${hasVendorCorroboration(f) ? "Yes" : "No"} | Distro context: ${hasDistroContext(f) ? "Yes" : "No"}`;

  el.triageEditState.value = f.triage_state || "new";
  el.triageEditNote.value = f.triage_note || "";

  renderMitrePanel(f);
  if (el.vendorSummary) {
    el.vendorSummary.textContent = vendorCorroborationSummary(f);
  }
  el.detailContent.textContent = "Loading report...";

  try {
    const res = await fetch(`/api/report/${encodeURIComponent(f.cve_id)}`, {
      cache: "no-store",
    });
    if (res.ok) {
      el.detailContent.textContent = await res.text();
    } else {
      el.detailContent.textContent = "Report not generated yet.";
    }
  } catch {
    el.detailContent.textContent = "Failed to load report.";
  }
}

function switchView(view) {
  const radar = view === "radar";
  el.viewRadar.classList.toggle("hidden", !radar);
  el.viewDocs.classList.toggle("hidden", radar);

  el.viewTabs.forEach((button) => {
    button.classList.toggle("active", button.dataset.view === view);
  });
}

async function loadDoc(docId, title) {
  el.docTitle.textContent = title;
  el.docBody.textContent = "Loading documentation...";

  try {
    const res = await fetch(`/api/docs/${encodeURIComponent(docId)}`, { cache: "no-store" });
    if (!res.ok) {
      el.docBody.textContent = "Documentation not available.";
      return;
    }
    el.docBody.textContent = await res.text();
  } catch {
    el.docBody.textContent = "Failed to load documentation.";
  }
}


function formatAgo(isoString) {
  if (!isoString) return "never";
  const t = Date.parse(isoString);
  if (Number.isNaN(t)) return "unknown";
  const diffSec = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  return `${Math.floor(diffSec / 86400)}d ago`;
}

function statusClass(status) {
  if (status === "ok") return "poll-source__status-ok";
  if (status === "error") return "poll-source__status-error";
  if (status === "running") return "poll-source__status-running";
  return "";
}

function renderPollStatus() {
  const status = state.pollStatus;
  if (!status) {
    el.pollSummary.textContent = "Poll status unavailable.";
    el.pollSources.innerHTML = "";
    return;
  }

  el.pollEnabled.checked = Boolean(status.enabled);
  el.pollInterval.value = String(status.interval_minutes || 30);
  el.pollIntervalValue.textContent = String(status.interval_minutes || 30);

  const active = status.is_polling ? "polling now" : status.enabled ? "auto-poll enabled" : "auto-poll disabled";
  const nextRun = status.next_run_in_seconds == null ? "n/a" : `${status.next_run_in_seconds}s`;
  const lastRun = status.last_cycle_completed ? formatAgo(status.last_cycle_completed) : "never";
  const err = status.last_cycle_error ? ` | error: ${status.last_cycle_error}` : "";
  el.pollSummary.textContent = `Status: ${active} | interval: ${status.interval_minutes}m | next run: ${nextRun} | last run: ${lastRun}${err}`;

  const sources = status.sources || {};
  const names = Object.keys(sources).sort();
  if (!names.length) {
    el.pollSources.innerHTML = "<div class=\"poll-source\">No source telemetry yet.</div>";
    return;
  }

  el.pollSources.innerHTML = "";
  for (const name of names) {
    const s = sources[name] || {};
    const card = document.createElement("div");
    card.className = "poll-source";
    card.innerHTML = `
      <h4>${name}</h4>
      <p class="poll-source__meta ${statusClass(s.status)}">status: ${s.status || "never"}</p>
      <p class="poll-source__meta">last polled: ${formatAgo(s.last_polled)}</p>
      <p class="poll-source__meta">last success: ${formatAgo(s.last_success)}</p>
      <p class="poll-source__meta">duration: ${s.duration_ms == null ? "n/a" : `${s.duration_ms}ms`}</p>
      <p class="poll-source__meta">records: ${Number(s.records || 0)}</p>
      <p class="poll-source__meta">error: ${s.last_error || "none"}</p>
    `;
    el.pollSources.appendChild(card);
  }
}

async function loadPollStatus() {
  const res = await fetch("/api/poll/status", { cache: "no-store" });
  if (!res.ok) {
    throw new Error("Failed to load poll status");
  }
  state.pollStatus = await res.json();
  renderPollStatus();
}

async function savePollConfig() {
  const payload = {
    enabled: el.pollEnabled.checked,
    interval_minutes: Number(el.pollInterval.value),
  };
  const res = await fetch("/api/poll/config", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error("Failed to save poll config");
  }
  state.pollStatus = await res.json();
  renderPollStatus();
}

async function runPollNow() {
  const res = await fetch("/api/poll/run", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });
  if (!res.ok) {
    throw new Error("Failed to trigger poll");
  }
  state.pollStatus = await res.json();
  renderPollStatus();
  setTimeout(async () => {
    try {
      await loadPollStatus();
      await loadFindings();
    } catch {
      // no-op
    }
  }, 3000);
}
function bindEvents() {
  el.search.addEventListener("input", applyFilters);
  el.category.addEventListener("change", applyFilters);
  el.ecosystem.addEventListener("change", applyFilters);
  el.triageState.addEventListener("change", applyFilters);
  el.sortBy.addEventListener("change", applyFilters);

  el.confidence.addEventListener("input", () => {
    el.confidenceValue.textContent = fmt(el.confidence.value);
    applyFilters();
  });

  el.epssMin.addEventListener("input", () => {
    el.epssMinValue.textContent = fmt(el.epssMin.value);
    applyFilters();
  });

  el.evidenceMin.addEventListener("input", () => {
    el.evidenceMinValue.textContent = fmt(el.evidenceMin.value);
    applyFilters();
  });

  el.hasKev.addEventListener("change", applyFilters);
  el.hasFix.addEventListener("change", applyFilters);
  el.hasRegional.addEventListener("change", applyFilters);
  el.hasVendorCorroboration.addEventListener("change", applyFilters);
  el.hasDistroContext.addEventListener("change", applyFilters);
  el.inScope.addEventListener("change", applyFilters);
  el.hasContradiction.addEventListener("change", applyFilters);
  el.hasAtlas.addEventListener("change", applyFilters);
  el.hasAttack.addEventListener("change", applyFilters);
  el.highMitre.addEventListener("change", applyFilters);

  el.refresh.addEventListener("click", async () => {
    await loadFindings();
  });

  el.exportCsv.addEventListener("click", () => {
    window.location.href = "/api/export.csv";
  });

  el.triageSave.addEventListener("click", async () => {
    try {
      await saveTriage();
    } catch {
      alert("Failed to save triage state.");
    }
  });

  el.resetFilters.addEventListener("click", () => {
    el.search.value = "";
    el.category.value = "";
    el.ecosystem.value = "";
    el.triageState.value = "";
    el.sortBy.value = "priority";
    el.confidence.value = "0";
    el.confidenceValue.textContent = fmt(0);
    el.epssMin.value = "0";
    el.epssMinValue.textContent = fmt(0);
    el.evidenceMin.value = "0";
    el.evidenceMinValue.textContent = fmt(0);
    el.hasKev.checked = false;
    el.hasFix.checked = false;
    el.hasRegional.checked = false;
    el.hasVendorCorroboration.checked = false;
    el.hasDistroContext.checked = false;
    el.inScope.checked = false;
    el.hasContradiction.checked = false;
    el.hasAtlas.checked = false;
    el.hasAttack.checked = false;
    el.highMitre.checked = false;
    state.statFilter = "";
    renderStats();
    applyFilters();
  });

  el.stats.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;
    const stat = target.dataset.statFilter;
    if (!stat) return;

    if (stat === "all") {
      state.statFilter = "";
    } else {
      state.statFilter = state.statFilter === stat ? "" : stat;
    }
    renderStats();
    applyFilters();
  });

  el.viewTabs.forEach((button) => {
    button.addEventListener("click", () => {
      switchView(button.dataset.view);
    });
  });

  el.docLinks.forEach((button) => {
    button.addEventListener("click", async () => {
      el.docLinks.forEach((b) => b.classList.remove("active"));
      button.classList.add("active");
      const titleMap = { runbook: "How To Use", overview: "Architecture", analyst: "Analyst Guide", optimize: "Optimization Guide" };
      const title = titleMap[button.dataset.doc] || "Documentation";
      await loadDoc(button.dataset.doc, title);
    });
  });
}

(async function init() {
  bindEvents();
  el.confidenceValue.textContent = fmt(el.confidence.value);
  el.epssMinValue.textContent = fmt(el.epssMin.value);
  el.evidenceMinValue.textContent = fmt(el.evidenceMin.value);
  el.pollIntervalValue.textContent = String(el.pollInterval.value);
  switchView("radar");
  await loadFindings();
  try {
    await loadPollStatus();
  } catch {
    el.pollSummary.textContent = "Poll status unavailable.";
  }
  setInterval(async () => {
    try {
      await loadPollStatus();
    } catch {
      // no-op
    }
  }, 15000);
  await loadDoc("runbook", "How To Use");
})();




