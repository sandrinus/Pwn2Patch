// The report panel for one file: score summary, tabs (Findings / Categories / Weaknesses),
// the findings list with filters and grouping, and its buttons.
import { exportBtn, patchAllBtn, resultsEl } from "./dom.js";
import { jumpToLine } from "./editor.js";
import { aiButton, askAI, previewFix, suppress, unsuppress } from "./patches.js";
import {
  changeSummary, filteredFindings, hasSafetyInfo, isRisky, matchesScope, state, suppressedList,
} from "./state.js";
import {
  $, QUALITY_HINT, SEVERITIES, cap, downloadJson, escapeHtml, gradeColor, isSecret, maskSecrets, messageHtml,
  plural, refLink, richText, storage,
} from "./util.js";

// What to do when there's no automatic patch, for rules where the generic text isn't helpful.
const MANUAL_HINT = {
  SEC004: "No safe auto-patch: move it to the environment by hand, then rotate it",
  SEC009: "Credential? Move it to the environment and rotate it. Hash or ID? Suppress it",
};
// Which signal found a secret (optional backend field): name, value, usage or entropy.
const EVIDENCE = { name: "found by name", value: "found by value", usage: "found by usage", entropy: "random-looking" };

// Repo mode replaces the "no report yet" message with the repository overview.
let emptyRenderer = null;
export function setEmptyRenderer(fn) { emptyRenderer = fn; }

export function renderEmpty() {
  exportBtn.hidden = patchAllBtn.hidden = true;
  if (emptyRenderer?.()) return;
  resultsEl.innerHTML = `<div class="empty"><div>
    <strong>No report yet</strong>
    Paste Python code or load a sample, then press <b>Analyze</b>.<br>
    The code is parsed, never executed.
  </div></div>`;
}

function renderDelta() {
  const c = changeSummary();
  if (!c) return "";
  const cls = c.delta > 0 ? "up" : c.delta < 0 ? "down" : "same";
  const arrow = c.delta > 0 ? "▲" : c.delta < 0 ? "▼" : "•";
  const parts = [c.fixed && `${c.fixed} fixed`, c.suppressed && `${c.suppressed} suppressed`, c.added && `${c.added} new`]
    .filter(Boolean).join(" · ");
  return `<div class="delta-detail"><span class="delta ${cls}">${arrow} ${c.delta > 0 ? "+" : ""}${c.delta}</span>
    from ${c.from}${parts ? ` · ${parts}` : ""}</div>`;
}

function updatePatchAllButton() {
  const { report } = state;
  patchAllBtn.hidden = !report?.ok || !report.fixable;
  if (patchAllBtn.hidden) return;
  const safe = report.findings.filter(f => f.patch && !isRisky(f)).length;
  patchAllBtn.textContent = hasSafetyInfo() && safe ? `Patch safe (${safe})` : `Patch all (${report.fixable})`;
  patchAllBtn.title = hasSafetyInfo() ? "Apply every patch that doesn't change behavior; review the rest" : "";
}

export function renderResults() {
  const r = state.report;
  if (!r) return renderEmpty();
  exportBtn.hidden = false;
  updatePatchAllButton();
  const stale = `<div class="stale-banner">The code changed since this report. Press <b>Analyze</b> to update it.</div>`;

  if (!r.ok) {
    const e = r.error;
    resultsEl.innerHTML = stale + `<div class="report"><div class="error-card">
      <span class="gate FAIL">FAIL</span>
      <p><strong>${escapeHtml(e.message)}</strong>${e.line ? ` on line ${e.line}` : ""}.</p>
      <p class="meta">The code has to parse before it can be checked against the policy.</p>
      ${e.line ? `<button class="ghost" data-goto="${e.line}">Go to line ${e.line}</button>` : ""}
    </div></div>`;
    return;
  }

  const s = r.stats;
  const reasons = r.gate.reasons.length
    ? `<ul class="reasons">${r.gate.reasons.map(x => `<li>${escapeHtml(x)}</li>`).join("")}</ul>`
    : `<p class="reasons" style="padding:0">Meets every requirement of the policy.</p>`;
  const suppressedNote = suppressedList().length ? ` · ${suppressedList().length} suppressed` : "";
  const tabs = [["findings", "Findings", r.findings.length], ["overview", "Categories", null],
                ["cwe", "Weaknesses", r.cwe_summary.length]];

  resultsEl.innerHTML = stale + `<div class="report">
    <div class="summary ${changeSummary()?.gateFlipped ? "celebrate" : ""}" style="--ring-color:${gradeColor(r.score)}">
      ${scoreRing(r.score)}
      <div class="verdict">
        <div class="grade-line"><span class="grade">Grade ${r.grade}</span>${gateBadge(r.gate.status)}</div>
        ${reasons}
        ${renderDelta()}
        <div class="stats">${plural(s.lines, "line")} · ${plural(s.functions, "function")} · ${plural(s.classes, "class", "classes")} · ${plural(r.findings.length, "finding")}${suppressedNote}</div>
      </div>
    </div>
    <div class="tabs" role="tablist" aria-label="Report sections">${tabs.map(([id, label, n]) =>
      `<button class="tab" role="tab" id="tab-${id}" data-view="${id}">${label}${n === null ? "" : `<b>${n}</b>`}</button>`).join("")}</div>
    <div id="tab-panel" role="tabpanel"></div>
  </div>`;
  animateRing(resultsEl, r.score);
  renderTab();
}

// Shared with the repo overview.
export const scoreRing = (score, label = "/ 100") => `
  <div class="ring" role="img" aria-label="Score ${score} out of 100">
    <svg viewBox="0 0 120 120"><circle class="track" cx="60" cy="60" r="50"/>
      <circle class="value" cx="60" cy="60" r="50" pathLength="100" stroke-dasharray="0 100"/></svg>
    <div class="ring-label"><strong>${score}</strong><span>${label}</span></div>
  </div>`;
export const gateBadge = status => `<span class="gate ${status}">${status === "PASS" ? "✓ PASS" : "✕ FAIL"}</span>`;
export function animateRing(root, score) {
  requestAnimationFrame(() => requestAnimationFrame(() =>
    root.querySelector(".ring .value")?.setAttribute("stroke-dasharray", `${score} 100`)));
}

export function setView(next) {
  state.view = next;
  storage.set("p2p-view", next);
  renderTab();
}

function renderTab() {
  const panel = $("#tab-panel");
  if (!panel || !state.report?.ok) return;
  resultsEl.querySelectorAll(".tab").forEach(t => {
    const on = t.dataset.view === state.view;
    t.classList.toggle("active", on);
    t.setAttribute("aria-selected", on);
    t.tabIndex = on ? 0 : -1;
  });
  panel.setAttribute("aria-labelledby", `tab-${state.view}`);
  if (state.view === "overview") {
    panel.innerHTML = renderCategories(state.report);
    requestAnimationFrame(() => requestAnimationFrame(() =>
      panel.querySelectorAll(".bar > span").forEach(el => { el.style.width = el.dataset.width + "%"; })));
  } else if (state.view === "cwe") {
    panel.innerHTML = renderCweSection(state.report) || `<div class="none">None of the findings map to a CWE.</div>`;
  } else {
    panel.innerHTML = `<div id="findings-area"></div>`;
    renderFindings();
  }
}

function renderCategories(r) {
  return `<p class="cwe-note">Click a category to see its findings.</p><div class="cats">${
    Object.entries(r.categories).map(([name, c]) => `
    <button class="cat ${state.filters.category === name ? "active" : ""}" data-cat="${name}" title="Show only ${name} findings">
      <span class="cat-name">${name}</span>
      <span class="bar" style="--bar-color:${gradeColor(c.score)}"><span data-width="${c.score}"></span></span>
      <span class="cat-score">${c.score}</span>
      <span class="cat-count">${c.findings} issue${c.findings === 1 ? "" : "s"}</span>
    </button>`).join("")}</div>`;
}

function renderCweSection(r) {
  if (!r.cwe_summary.length) return "";
  const qualityCount = r.cwe_summary.filter(c => c.quality_only).length;
  const rows = r.cwe_summary.map(c => `
    <button class="cwe-row sev-${c.worst_severity} ${state.filters.cwe === c.id ? "active" : ""}" data-cwe="${c.id}"
            title="${escapeHtml(`${c.id}: ${c.name}`)}">
      <span class="dot"></span>
      <span class="cwe-id">${c.id}</span>
      <span class="cwe-short">${escapeHtml(c.short)}</span>
      <span>${c.quality_only ? `<span class="quality-tag" title="${escapeHtml(QUALITY_HINT)}">quality</span>` : ""}</span>
      <span class="cwe-count">×${c.count}</span>
    </button>`).join("");
  return `
    <p class="cwe-note">${plural(r.cwe_summary.length, "distinct CWE")} across ${r.cwe_coverage.mapped} of
      ${plural(r.cwe_coverage.total, "finding")}${qualityCount ? `; ${qualityCount} tagged <span class="quality-tag">quality</span> are code-quality weaknesses, not vulnerabilities` : ""}. Click one to see its findings.</p>
    <div class="cwe-list">${rows}</div>`;
}

function cweTags(f) {
  if (!f.cwe?.length) return "";
  return `<div class="cwe-tags">${f.cwe.map(c => `
    <a class="cwe-pill sev-${f.severity} ${c.quality_only ? "quality" : ""}" href="${escapeHtml(c.url)}" target="_blank"
       rel="noopener" title="${escapeHtml(`${c.id}: ${c.name}`)}"><b>${c.id}</b>${escapeHtml(c.short)}</a>`).join("")}</div>`;
}

export function renderFindings() {
  const area = $("#findings-area");
  const { report, filters } = state;
  if (!area || !report?.ok) return;
  const scoped = report.findings.filter(f => matchesScope(f) && (!filters.fixable || f.patch));
  const counts = Object.fromEntries(SEVERITIES.map(sv => [sv, scoped.filter(f => f.severity === sv).length]));
  const fixableCount = report.findings.filter(f => matchesScope(f) && f.patch).length;
  const shown = filteredFindings();
  const suppressed = suppressedList();

  const active = [filters.cwe && ["cwe", filters.cwe], filters.category && ["category", filters.category]].filter(Boolean);
  const chips = [
    ...active.map(([key, label]) =>
      `<button class="chip active" data-clear="${key}" title="Clear this filter">${escapeHtml(label)} ✕</button>`),
    `<button class="chip ${filters.severity || state.showSuppressed ? "" : "active"}" data-sev="">All <b>${scoped.length}</b></button>`,
    ...SEVERITIES.filter(sv => counts[sv]).map(sv =>
      `<button class="chip sev-${sv} ${filters.severity === sv ? "active" : ""}" data-sev="${sv}">
        <span class="dot"></span>${cap(sv)} <b>${counts[sv]}</b></button>`),
    fixableCount ? `<button class="chip ${filters.fixable ? "active" : ""}" data-fixable title="Only findings with an automatic patch">
        🔧 Fixable <b>${fixableCount}</b></button>` : "",
    suppressed.length ? `<button class="chip ${state.showSuppressed ? "active" : ""}" data-show-suppressed title="Findings hidden by an ignore comment">
        Suppressed <b>${suppressed.length}</b></button>` : "",
  ].join("");
  const seg = `<div class="seg" role="group" aria-label="Group findings by">${["severity", "rule", "line"].map(g =>
    `<button class="${state.groupBy === g ? "active" : ""}" data-group="${g}" aria-pressed="${state.groupBy === g}">${cap(g)}</button>`).join("")}</div>`;
  const notice = report.patches_truncated
    ? `<p class="notice">This file is large, so patches were prepared for the first findings only. Patch some, and the rest will follow.</p>` : "";

  let list;
  if (state.showSuppressed) {
    list = suppressed.map((f, i) => findingCard(f, { suppressedIndex: i })).join("") ||
           `<div class="none">Nothing is suppressed.</div>`;
  } else if (!report.findings.length) {
    list = `<div class="none">No findings. This code meets every rule in the policy.</div>`;
  } else if (!shown.length) {
    list = `<div class="none">No findings match this filter.</div>`;
  } else if (state.groupBy === "rule") {
    const groups = new Map();
    for (const f of shown) groups.set(f.rule_id, [...(groups.get(f.rule_id) || []), f]);
    list = [...groups.values()].map(items => {
      const f = items[0];
      const open = items.length <= 2 || ["critical", "high"].includes(f.severity) || items.some(x => x.line === state.activeLine);
      return `<details class="group sev-${f.severity}" ${open ? "open" : ""}>
        <summary><span class="sev">${f.severity}</span><span class="group-title">${escapeHtml(f.title)}</span>
          <span class="rule-id">${f.rule_id}</span><span class="group-count">×${items.length}</span></summary>
        <div class="findings">${items.map(x => findingCard(x, { compact: true })).join("")}</div>
      </details>`;
    }).join("");
  } else {
    const ordered = state.groupBy === "line" ? [...shown].sort((a, b) => a.line - b.line || (a.col || 0) - (b.col || 0)) : shown;
    list = ordered.map((f, i) => findingCard(f, { open: i === 0 && state.groupBy === "severity" })).join("");
  }
  area.innerHTML = `<div class="findings-toolbar"><div class="chips">${chips}</div>${seg}</div>${notice}<div class="findings">${list}</div>`;
}

// compact: inside a rule group, whose header already shows the severity and title.
function findingCard(f, { open = false, suppressedIndex = null, compact = false } = {}) {
  const i = state.findingIndex.get(f);
  const isSuppressed = suppressedIndex !== null;
  const actions = isSuppressed
    ? `<button class="link-btn" data-unsuppress="${suppressedIndex}">Unsuppress</button>`
    : `${f.patch
        ? `<button class="fix-btn ${isRisky(f) ? "risky" : ""}" data-fix="${i}">${isRisky(f) ? "⚠" : "🔧"} Preview fix</button>
           ${isRisky(f) ? `<span class="risk-tag" title="Applying this patch changes how the code behaves">changes behavior</span>` : ""}`
        : `<span class="manual">${MANUAL_HINT[f.rule_id] || (f.category === "security" ? "No safe auto-patch: needs a human" : "Manual fix")}</span>${aiButton(f)}`}
       ${EVIDENCE[f.evidence] ? `<span class="evidence-tag">${EVIDENCE[f.evidence]}</span>` : ""}
       <button class="link-btn" data-suppress="${i}" title="Add a # pwn2patch: ignore[${f.rule_id}] comment to line ${f.line}">Suppress</button>`;
  return `
    <article class="finding sev-${f.severity} ${isSuppressed ? "suppressed" : ""} ${f.line === state.activeLine ? "is-active" : ""}" data-line="${f.line}">
      <button class="finding-head" data-goto="${f.line}" title="Show line ${f.line} in the editor">
        ${compact ? `<span class="finding-title compact">${richText(f.message)}</span>`
                  : `<span class="sev">${f.severity}</span>
        <span class="finding-title">${escapeHtml(f.title)}<span class="rule-id">${f.rule_id}</span></span>`}
        ${isSuppressed ? "" : pointsTag(f)}
        <span class="loc">line ${f.line}</span>
      </button>
      <div class="finding-body ${compact ? "compact" : ""}">
        ${compact ? "" : `<p class="msg">${messageHtml(f.message)}</p>`}
        <div class="finding-actions">${actions}</div>
        ${cweTags(f)}
        ${snippetHtml(f, suppressedIndex)}
        ${f.why || f.fix ? `<details ${open && ["critical", "high"].includes(f.severity) ? "open" : ""}>
          <summary>Why it matters &amp; how to fix</summary>
          ${f.why ? `<p><b>Why:</b> ${richText(f.why)}</p>` : ""}
          ${typeof f.fix === "string" ? `<p><b>Fix:</b> ${richText(f.fix)}</p>` : ""}
          ${(f.cwe || []).map(c => `<p><b>${c.id}:</b> ${escapeHtml(c.name)}
            ${c.quality_only ? `<span class="quality-tag" title="${escapeHtml(QUALITY_HINT)}">quality</span>` : ""}</p>`).join("")}
          ${f.ref ? `<p>${refLink(f.ref)}</p>` : ""}
        </details>` : ""}
      </div>
    </article>`;
}

function snippetHtml(f, suppressedIndex = null) {
  if (!f.snippet) return "";
  if (!isSecret(f)) return `<code class="snippet">${escapeHtml(f.snippet)}</code>`;
  const ref = suppressedIndex !== null ? `s${suppressedIndex}` : state.findingIndex.get(f);
  return `<div class="secret-snippet"><code class="snippet">${escapeHtml(maskSecrets(f.snippet))}</code>
    <button class="link-btn" data-reveal="${ref}" title="Show the full value">Show</button></div>`;
}

// What fixing this finding is worth. Prefers the server's gain_if_fixed (correct under any
// scoring model); falls back to the raw penalty for older backends.
function pointsTag(f) {
  const p = f.points;
  if (!p) return "";
  if (!p.counted) return `<span class="pts uncounted" title="Only the first ${state.perRuleCap} findings of each rule lower the score">not scored</span>`;
  if (typeof p.gain_if_fixed === "number") {
    if (p.gain_if_fixed > 0) {
      return `<span class="pts gain" title="Fixing this raises the overall score by about ${p.gain_if_fixed}">+${p.gain_if_fixed}</span>`;
    }
    const why = p.category_clamped ? `${cap(f.category)} is already at 0, so fixing this alone won't raise the score yet.`
                                   : "Fixing this alone doesn't change the score.";
    return `<span class="pts uncounted" title="${why}">+0</span>`;
  }
  return `<span class="pts" title="Costs ${p.category} points in ${f.category}">−${p.category}</span>`;
}

export function markActiveFindings(line, scroll) {
  let first = null;
  resultsEl.querySelectorAll(".finding").forEach(el => {
    const on = Number(el.dataset.line) === line;
    el.classList.toggle("is-active", on);
    if (on && !first) first = el;
  });
  first?.closest("details.group")?.setAttribute("open", "");
  if (scroll && first) first.scrollIntoView({ block: "nearest", behavior: "smooth" });
}

function onReportClick(e) {
  const t = e.target;
  if (t.closest(".repo-overview")) return;              // handled by repo.js
  const findings = state.report?.findings || [];
  const { filters } = state;
  const fixBtn = t.closest("[data-fix]");
  if (fixBtn) return previewFix(findings[Number(fixBtn.dataset.fix)]);
  const aiBtn = t.closest("[data-ai]");
  if (aiBtn) return askAI(findings[Number(aiBtn.dataset.ai)], aiBtn);
  const sup = t.closest("[data-suppress]");
  if (sup) return suppress(findings[Number(sup.dataset.suppress)]);
  const unsup = t.closest("[data-unsuppress]");
  if (unsup) return unsuppress(suppressedList()[Number(unsup.dataset.unsuppress)]);
  const reveal = t.closest("[data-reveal]");
  if (reveal) {
    const key = reveal.dataset.reveal;
    const f = key.startsWith("s") ? suppressedList()[Number(key.slice(1))] : findings[Number(key)];
    const code = reveal.previousElementSibling, shown = reveal.textContent === "Hide";
    code.textContent = shown ? maskSecrets(f.snippet) : f.snippet;
    reveal.textContent = shown ? "Show" : "Hide";
    return;
  }
  const tab = t.closest("[data-view]");
  if (tab) return setView(tab.dataset.view);
  const group = t.closest("[data-group]");
  if (group) {
    state.groupBy = group.dataset.group;
    storage.set("p2p-group", state.groupBy);
    return renderFindings();
  }
  if (t.closest("[data-show-suppressed]")) { state.showSuppressed = !state.showSuppressed; return renderFindings(); }
  if (t.closest("[data-fixable]")) {
    filters.fixable = !filters.fixable;
    filters.severity = null;
    state.showSuppressed = false;
    return renderFindings();
  }
  const goto = t.closest("[data-goto]");
  if (goto) {
    jumpToLine(Number(goto.dataset.goto));
    if (goto.classList.contains("line-link")) markActiveFindings(Number(goto.dataset.goto), true);
    return;
  }
  const cat = t.closest(".cat");
  if (cat) {
    filters.category = filters.category === cat.dataset.cat ? null : cat.dataset.cat;
    filters.severity = null;
    return setView("findings");
  }
  const cweRow = t.closest(".cwe-row");
  if (cweRow) {
    filters.cwe = filters.cwe === cweRow.dataset.cwe ? null : cweRow.dataset.cwe;
    filters.severity = null;
    return setView("findings");
  }
  const clear = t.closest("[data-clear]");
  if (clear) { filters[clear.dataset.clear] = null; return renderFindings(); }
  const chip = t.closest(".chip");
  if (chip) {
    filters.severity = chip.dataset.sev || null;
    state.showSuppressed = false;
    renderFindings();
  }
}

export function initReport({ exportName }) {
  resultsEl.addEventListener("click", onReportClick);
  // Arrow keys move between tabs (WAI-ARIA tabs pattern).
  resultsEl.addEventListener("keydown", e => {
    const tab = e.target.closest(".tab");
    if (!tab || !["ArrowLeft", "ArrowRight"].includes(e.key)) return;
    const tabs = [...resultsEl.querySelectorAll(".tab")];
    const next = tabs[(tabs.indexOf(tab) + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
    setView(next.dataset.view);
    $(`#tab-${next.dataset.view}`)?.focus();
  });
  exportBtn.addEventListener("click", () => {
    const { report } = state;
    if (!report) return;
    // Secret values are masked in the export too: reports get attached and shared.
    const maskFinding = f => isSecret(f) ? { ...f, snippet: maskSecrets(f.snippet) } : f;
    const exported = report.ok ? { ...report, findings: report.findings.map(maskFinding),
      ...(Array.isArray(report.suppressed) ? { suppressed: report.suppressed.map(maskFinding) } : {}) } : report;
    downloadJson(exported, exportName());
  });
}
