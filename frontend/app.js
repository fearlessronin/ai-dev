const state = {
  findings: [],
  filtered: [],
  selectedId: null,
};

const el = {
  cards: document.getElementById("cards"),
  stats: document.getElementById("stats"),
  search: document.getElementById("search"),
  category: document.getElementById("category"),
  confidence: document.getElementById("confidence"),
  confidenceValue: document.getElementById("confidence-value"),
  hasAtlas: document.getElementById("has-atlas"),
  hasAttack: document.getElementById("has-attack"),
  highMitre: document.getElementById("high-mitre"),
  refresh: document.getElementById("refresh"),
  detailTitle: document.getElementById("detail-title"),
  detailMeta: document.getElementById("detail-meta"),
  detailContent: document.getElementById("detail-content"),
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
};

function fmt(n) {
  return Number(n || 0).toFixed(2);
}

function hasHighMitre(f) {
  const all = [...(f.atlas_matches || []), ...(f.attack_matches || [])];
  return all.some((m) => m.confidence === "high");
}

async function loadFindings() {
  const res = await fetch("/api/findings", { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to load findings");
  state.findings = await res.json();
  populateCategoryOptions();
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

function applyFilters() {
  const q = el.search.value.trim().toLowerCase();
  const minConfidence = Number(el.confidence.value);
  const category = el.category.value;
  const mustHaveAtlas = el.hasAtlas.checked;
  const mustHaveAttack = el.hasAttack.checked;
  const mustBeHighMitre = el.highMitre.checked;

  state.filtered = state.findings.filter((f) => {
    const confidenceOk = Number(f.confidence || 0) >= minConfidence;
    const categoryOk = !category || (f.categories || []).includes(category);
    const atlasOk = !mustHaveAtlas || (f.atlas_matches || []).length > 0;
    const attackOk = !mustHaveAttack || (f.attack_matches || []).length > 0;
    const highMitreOk = !mustBeHighMitre || hasHighMitre(f);

    const blob = [
      f.cve_id,
      ...(f.matched_keywords || []),
      ...(f.cwes || []),
      ...(f.categories || []),
      ...(f.atlas_matches || []).map((m) => m.technique_id),
      ...(f.attack_matches || []).map((m) => m.technique_id),
      f.summary,
      f.correlation_summary,
    ]
      .join(" ")
      .toLowerCase();

    const queryOk = !q || blob.includes(q);
    return confidenceOk && categoryOk && atlasOk && attackOk && highMitreOk && queryOk;
  });

  renderCards();
}

function renderStats() {
  const total = state.findings.length;
  const high = state.findings.filter((f) => Number(f.confidence || 0) >= 0.75).length;
  const atlasLinked = state.findings.filter((f) => (f.atlas_matches || []).length > 0).length;
  const attackLinked = state.findings.filter((f) => (f.attack_matches || []).length > 0).length;
  el.stats.innerHTML = `
    <span class="stat">Findings: ${total}</span>
    <span class="stat">High-confidence: ${high}</span>
    <span class="stat">ATLAS linked: ${atlasLinked}</span>
    <span class="stat">ATT&CK linked: ${attackLinked}</span>
  `;
}

function renderCards() {
  if (!state.filtered.length) {
    el.cards.innerHTML = "<p>No findings match filters.</p>";
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
        <span class="badge">confidence ${fmt(f.confidence)}</span>
        <span class="badge">ATLAS ${(f.atlas_matches || []).length}</span>
        <span class="badge">ATT&CK ${(f.attack_matches || []).length}</span>
      </div>
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

async function selectFinding(f) {
  state.selectedId = f.cve_id;
  renderCards();

  el.detailTitle.textContent = f.cve_id;
  el.detailMeta.textContent = `Published: ${f.published || "N/A"} | Confidence: ${fmt(
    f.confidence,
  )} | Categories: ${(f.categories || []).join(", ")}`;
  renderMitrePanel(f);
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

function bindEvents() {
  el.search.addEventListener("input", applyFilters);
  el.category.addEventListener("change", applyFilters);
  el.confidence.addEventListener("input", () => {
    el.confidenceValue.textContent = fmt(el.confidence.value);
    applyFilters();
  });
  el.hasAtlas.addEventListener("change", applyFilters);
  el.hasAttack.addEventListener("change", applyFilters);
  el.highMitre.addEventListener("change", applyFilters);
  el.refresh.addEventListener("click", async () => {
    await loadFindings();
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
      const title = button.dataset.doc === "runbook" ? "How To Use" : "Architecture";
      await loadDoc(button.dataset.doc, title);
    });
  });
}

(async function init() {
  bindEvents();
  el.confidenceValue.textContent = fmt(el.confidence.value);
  switchView("radar");
  await loadFindings();
  await loadDoc("runbook", "How To Use");
})();
