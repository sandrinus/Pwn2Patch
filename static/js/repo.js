// Repository mode: scan a public Git repo, browse its Python files in a tree, and open any
// file in the editor with the full single-file report (patches, AI drafts, suppressions...).
//
// Files are view-only: the editor holds a copy, so patches and edits stay in the browser and
// are discarded when another file is opened. The URL hash (#repo=...&file=...) records what's
// open, so a reload, a shared link or the back button returns to the same file.
import { codeEl, editorTitle, overviewBtn, repoPanel, reportTitle, resultsEl } from "./dom.js";
import { clearReport, runAnalysis } from "./analysis.js";
import { jumpToLine, setCode } from "./editor.js";
import { animateRing, renderEmpty, scoreRing, setEmptyRenderer } from "./report.js";
import { resetFilters, state } from "./state.js";
import {
  $, SEVERITIES, cap, downloadJson, escapeHtml, getJson, gradeColor, plural, postJson, severityRank, toast,
} from "./util.js";

const POLL_MS = 450;
const EXAMPLES = ["pallets/itsdangerous", "pallets/flask", "psf/requests"];

const repo = {
  job: null,            // latest status from GET /api/repo/<id>; has files + summary once done
  link: "",             // the link as typed
  pollTimer: null,
  current: null,        // path of the file open in the editor
  original: "",         // that file's source as scanned, to tell whether it was edited
  loadSeq: 0,
  expanded: new Set(),  // directories open in the tree
  query: "",
  issuesOnly: false,
  sort: "tree",         // "tree" | "worst"
  rule: null,           // only files with this rule
  severity: null,       // only files with a finding at this severity
  showOverview: false,
};

const done = () => repo.job?.state === "done";
const byPath = path => repo.job?.files?.find(f => f.path === path);
const basename = path => path.split("/").pop();
export const currentPath = () => (state.mode === "repo" ? repo.current : null);

// ------------------------------------------------------------ URL hash
function readHash() {
  const params = new URLSearchParams(location.hash.slice(1));
  return { repo: params.get("repo"), file: params.get("file"), line: Number(params.get("line")) || null };
}

function writeHash({ push = false } = {}) {
  const params = new URLSearchParams();
  if (state.mode === "repo" && repo.link) params.set("repo", repo.link);
  if (state.mode === "repo" && repo.current) params.set("file", repo.current);
  const hash = params.toString() ? `#${params}` : "";
  if (hash === location.hash || (!hash && !location.hash)) return;
  const url = `${location.pathname}${location.search}${hash}`;
  push ? history.pushState(null, "", url) : history.replaceState(null, "", url);
}

// ------------------------------------------------------------ scanning
export async function startScan(link, { push = true, openAfter = null } = {}) {
  link = link.trim();
  if (!link) return toast("Paste a link to a public Git repository.");
  clearTimeout(repo.pollTimer);
  repo.link = link;
  $("#repo-url").value = link;
  repo.job = { state: "starting", message: "Starting…", progress: { done: 0, total: 0 } };
  closeFile();
  renderPanel();
  writeHash({ push });
  try {
    repo.job = await postJson("/api/repo", { url: link });
    renderPanel();
    poll(repo.job.id, openAfter);
  } catch (err) {
    repo.job = { state: "error", error: err.message };
    renderPanel();
  }
}

function poll(id, openAfter) {
  clearTimeout(repo.pollTimer);
  if (repo.job?.id !== id) return;
  if (repo.job.state === "done") return scanFinished(openAfter);
  if (repo.job.state === "error") return renderPanel();
  repo.pollTimer = setTimeout(async () => {
    try {
      const status = await getJson(`/api/repo/${encodeURIComponent(id)}`);
      if (repo.job?.id !== id) return;          // a newer scan replaced this one
      repo.job = status;
    } catch (err) {
      repo.job = { ...repo.job, state: "error", error: err.message };
    }
    renderPanel();
    poll(id, openAfter);
  }, POLL_MS);
}

function scanFinished(openAfter) {
  const files = repo.job.files;
  repo.expanded = new Set();
  // Small repos open fully; big ones show their top level.
  for (const f of files) {
    const parts = f.path.split("/").slice(0, -1);
    for (let i = 1; i <= parts.length; i++) {
      if (files.length <= 60 || i === 1) repo.expanded.add(parts.slice(0, i).join("/"));
    }
  }
  repo.query = "";
  repo.rule = repo.severity = null;
  renderPanel();
  if (openAfter && byPath(openAfter.file)) openFile(openAfter.file, { line: openAfter.line, push: false });
  else showOverview();
}

// ------------------------------------------------------------ files
export async function openFile(path, { line = null, push = true } = {}) {
  if (!done() || !byPath(path)) return;
  if (repo.current && repo.current !== path && codeEl.value !== repo.original) {
    toast(`Discarded your edits to ${basename(repo.current)} (repository files are view-only)`);
  }
  const seq = ++repo.loadSeq;
  repo.current = path;
  repo.showOverview = false;
  writeHash({ push });
  updateTitles();
  highlightActiveRow();
  resultsEl.innerHTML = `<div class="empty"><div><strong>Loading ${escapeHtml(basename(path))}…</strong></div></div>`;
  try {
    const { code } = await getJson(`/api/repo/${encodeURIComponent(repo.job.id)}/file?path=${encodeURIComponent(path)}`);
    if (seq !== repo.loadSeq) return;
    repo.original = code;
    resetFilters();
    setCode(code);
    updateTitles();
    await runAnalysis();
    if (seq === repo.loadSeq && line) jumpToLine(line, { focus: false });
  } catch (err) {
    if (seq !== repo.loadSeq) return;
    resultsEl.innerHTML = `<div class="error-card"><strong>Couldn't open ${escapeHtml(path)}.</strong> ${escapeHtml(err.message)}</div>`;
  }
}

function closeFile() {
  repo.loadSeq++;
  repo.current = null;
  repo.original = "";
  clearReport();
  setCode("");
  updateTitles();
}

export function showOverview() {
  if (repo.current && codeEl.value !== repo.original) {
    toast(`Discarded your edits to ${basename(repo.current)}`);
  }
  closeFile();
  repo.showOverview = true;
  writeHash();
  renderEmpty();       // the empty renderer below draws the overview
  highlightActiveRow();
}

// The editor toolbar's file name, edited marker and host link; the report panel's title.
function updateTitles() {
  const path = currentPath();
  overviewBtn.hidden = !(state.mode === "repo" && done() && path);
  if (!path) {
    editorTitle.innerHTML = state.mode === "repo" && done()
      ? `<span class="meta">Pick a file from the tree</span>` : "";
    reportTitle.textContent = state.mode === "repo" && done() ? "Repository" : "Report";
    return;
  }
  const dir = path.includes("/") ? path.slice(0, path.lastIndexOf("/") + 1) : "";
  const edited = codeEl.value !== repo.original && repo.original !== "";
  const link = hostFileUrl(path);
  editorTitle.innerHTML = `<span class="file-path" title="${escapeHtml(path)}"><span class="dir">${escapeHtml(dir)}</span>${escapeHtml(basename(path))}</span>
    ${edited ? `<span class="edited-tag" title="Your edits stay in this browser tab and are discarded when you open another file">edited · not saved</span>` : ""}
    ${link ? `<a class="host-link" href="${escapeHtml(link)}" target="_blank" rel="noopener noreferrer">${escapeHtml(hostName())} ↗</a>` : ""}`;
  reportTitle.textContent = basename(path);
}

const hostName = () => ({ "github.com": "GitHub", "gitlab.com": "GitLab", "bitbucket.org": "Bitbucket" })[repo.job?.repo?.host] || "";
function hostFileUrl(path) {
  const r = repo.job?.repo, ref = repo.job?.commit || repo.job?.ref || "HEAD";
  if (!r) return null;
  const p = path.split("/").map(encodeURIComponent).join("/");
  return { "github.com": `${r.url}/blob/${ref}/${p}`, "gitlab.com": `${r.url}/-/blob/${ref}/${p}`,
           "bitbucket.org": `${r.url}/src/${ref}/${p}` }[r.host] || null;
}

// ------------------------------------------------------------ side panel
function renderPanel() {
  const body = $("#repo-body");
  const job = repo.job;
  updateTitles();
  if (!job) {
    body.innerHTML = `<div class="repo-intro">
      <p>Paste a link to a public Git repository. Pwn2Patch downloads only its Python files, checks every one,
        and lets you browse the results file by file.</p>
      <p class="meta">Try one:</p>
      <div class="repo-examples">${EXAMPLES.map(e => `<button class="ghost" data-example="${e}">${e}</button>`).join("")}</div>
      <p class="meta">Public repositories only. Nothing from the repository is ever run.</p>
    </div>`;
    renderEmpty();
    return;
  }
  if (job.state === "error") {
    body.innerHTML = `<div class="error-card repo-error"><strong>Couldn't scan this repository.</strong>
      <p>${escapeHtml(job.error || "Unknown error")}</p>
      <button class="ghost" data-rescan>Try again</button></div>`;
    renderEmpty();
    return;
  }
  if (job.state !== "done") {
    const { done: n, total } = job.progress || {};
    const pct = job.state === "scanning" && total ? Math.round((n / total) * 100) : null;
    body.innerHTML = `<div class="repo-progress" role="status">
      <div class="repo-name">${escapeHtml(job.repo?.name || repo.link)}</div>
      <p>${escapeHtml(job.message || "Working…")}</p>
      <div class="progress ${pct === null ? "indeterminate" : ""}"><span style="width:${pct ?? 30}%"></span></div>
      ${pct !== null ? `<p class="meta">${n} of ${total} files</p>` : ""}
    </div>`;
    renderEmpty();
    return;
  }
  const s = job.summary;
  const commit = job.commit ? job.commit.slice(0, 7) : null;
  body.innerHTML = `
    <div class="repo-head">
      <div class="repo-title">
        <a class="repo-name" href="${escapeHtml(job.repo.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(job.repo.name)}</a>
        <span class="meta">${escapeHtml(job.repo.host)}${job.ref ? ` · ${escapeHtml(job.ref)}` : ""}${commit ? ` · <code>${commit}</code>` : ""}</span>
      </div>
      ${s.score !== null ? `<span class="grade-pill" style="--c:${gradeColor(s.score)}" title="Repository score ${s.score}/100">${s.grade} · ${s.score}</span>` : ""}
    </div>
    <div class="repo-tools">
      <input type="search" id="repo-search" placeholder="Filter files" aria-label="Filter files by path" value="${escapeHtml(repo.query)}">
      <div class="repo-tool-row">
        <label class="toggle"><input type="checkbox" id="repo-issues" ${repo.issuesOnly ? "checked" : ""}> Issues only</label>
        <div class="seg" role="group" aria-label="Sort files">
          <button data-sort="tree" class="${repo.sort === "tree" ? "active" : ""}" aria-pressed="${repo.sort === "tree"}">Tree</button>
          <button data-sort="worst" class="${repo.sort === "worst" ? "active" : ""}" aria-pressed="${repo.sort === "worst"}">Worst first</button>
        </div>
      </div>
      <div class="chips" id="repo-active-filters"></div>
    </div>
    <div class="repo-tree" id="repo-tree" role="tree" aria-label="Python files"></div>
    <div class="repo-foot meta">${plural(s.files_scanned, "file")} scanned${s.files_skipped ? ` · ${s.files_skipped} skipped` : ""}${job.files_over_limit ? ` · ${job.files_over_limit} more not scanned (limit ${job.max_files})` : ""}</div>`;
  renderTree();
  if (!repo.current) renderEmpty();
}

// ------------------------------------------------------------ tree
function fileMatches(f) {
  if (repo.query && !f.path.toLowerCase().includes(repo.query.toLowerCase())) return false;
  if (repo.issuesOnly && f.ok && !f.findings) return false;
  if (repo.rule && !(f.rules || {})[repo.rule]) return false;
  if (repo.severity && !(f.severity_counts || {})[repo.severity]) return false;
  return true;
}

function buildTree(files) {
  const root = { name: "", path: "", dirs: new Map(), files: [], findings: 0, worst: null, failing: 0 };
  for (const f of files) {
    let node = root;
    const parts = f.path.split("/");
    for (const [i, part] of parts.slice(0, -1).entries()) {
      if (!node.dirs.has(part)) {
        node.dirs.set(part, { name: part, path: parts.slice(0, i + 1).join("/"), dirs: new Map(), files: [],
                              findings: 0, worst: null, failing: 0 });
      }
      node = node.dirs.get(part);
    }
    node.files.push(f);
  }
  // Roll counts up so a folder shows its worst file's severity and its total findings.
  (function rollUp(node) {
    for (const d of node.dirs.values()) rollUp(d);
    for (const item of [...node.dirs.values(), ...node.files]) {
      node.findings += item.findings || 0;
      node.failing += item.dirs ? item.failing : (item.gate === "FAIL" ? 1 : 0);
      const worst = item.dirs ? item.worst : (item.ok ? item.worst : "critical");
      if (worst && (!node.worst || severityRank(worst) < severityRank(node.worst))) node.worst = worst;
    }
  })(root);
  return root;
}

const fileTitle = f => f.ok
  ? `${f.path} · score ${f.score} · ${plural(f.findings, "finding")}${f.empty ? " (empty file)" : ""}`
  : `${f.path} · couldn't be parsed: ${f.error}`;

function fileRow(f, depth, { showDir = false } = {}) {
  const dir = showDir && f.path.includes("/") ? f.path.slice(0, f.path.lastIndexOf("/") + 1) : "";
  const sev = f.ok ? f.worst : "critical";
  return `<button class="tree-row file ${f.path === repo.current ? "active" : ""}" role="treeitem" data-file="${escapeHtml(f.path)}"
      style="--depth:${depth}" title="${escapeHtml(fileTitle(f))}" tabindex="-1">
    <span class="dot ${sev ? `sev-${sev}` : "clean"}"></span>
    <span class="tree-name">${dir ? `<span class="dir">${escapeHtml(dir)}</span>` : ""}${escapeHtml(basename(f.path))}</span>
    ${f.ok ? (f.findings ? `<span class="tree-count">${f.findings}</span>` : "") : `<span class="tree-count bad" title="Syntax error">!</span>`}
    ${f.ok ? `<span class="tree-grade" style="color:${gradeColor(f.score)}">${f.grade}</span>` : ""}
  </button>`;
}

function renderTree() {
  const el = $("#repo-tree");
  if (!el || !done()) return;
  const files = repo.job.files.filter(fileMatches);
  const filtering = !!(repo.query || repo.rule || repo.severity);
  let html;
  if (!files.length) {
    html = `<p class="none">No files match.</p>`;
  } else if (repo.sort === "worst") {
    const order = (a, b) => (a.ok - b.ok) || (a.score - b.score) || (b.findings - a.findings) || a.path.localeCompare(b.path);
    html = [...files].sort(order).map(f => fileRow(f, 0, { showDir: true })).join("");
  } else {
    const rows = [];
    (function walk(node, depth) {
      const dirs = [...node.dirs.values()].sort((a, b) => a.name.localeCompare(b.name));
      for (const d of dirs) {
        const open = filtering || repo.expanded.has(d.path);
        rows.push(`<button class="tree-row dir" role="treeitem" aria-expanded="${open}" data-dir="${escapeHtml(d.path)}"
            style="--depth:${depth}" tabindex="-1" title="${escapeHtml(d.path)}/ · ${plural(d.findings, "finding")}">
          <span class="caret">${open ? "▾" : "▸"}</span>
          <span class="dot ${d.worst ? `sev-${d.worst}` : "clean"}"></span>
          <span class="tree-name">${escapeHtml(d.name)}/</span>
          ${d.findings ? `<span class="tree-count">${d.findings}</span>` : ""}
        </button>`);
        if (open) walk(d, depth + 1);
      }
      for (const f of [...node.files].sort((a, b) => a.path.localeCompare(b.path))) rows.push(fileRow(f, depth));
    })(buildTree(files), 0);
    html = rows.join("");
  }
  el.innerHTML = html;
  // Roving tabindex: one tab stop for the whole tree, arrow keys move inside it.
  const focusable = el.querySelector(".tree-row.active") || el.querySelector(".tree-row");
  if (focusable) focusable.tabIndex = 0;

  const chips = [];
  if (repo.rule) chips.push(`<button class="chip active" data-clear-rule title="Show all files">${escapeHtml(repo.rule)} ✕</button>`);
  if (repo.severity) chips.push(`<button class="chip active sev-${repo.severity}" data-clear-sev title="Show all files"><span class="dot"></span>${cap(repo.severity)} ✕</button>`);
  $("#repo-active-filters").innerHTML = chips.join("");
}

function highlightActiveRow() {
  const el = $("#repo-tree");
  if (!el) return;
  el.querySelectorAll(".tree-row").forEach(row => {
    const on = row.dataset.file === repo.current;
    row.classList.toggle("active", on);
    row.tabIndex = on ? 0 : -1;
  });
  el.querySelector(".tree-row.active")?.scrollIntoView({ block: "nearest" });
}

function onTreeKey(e) {
  const row = e.target.closest(".tree-row");
  if (!row) return;
  const rows = [...$("#repo-tree").querySelectorAll(".tree-row")];
  const i = rows.indexOf(row);
  const move = to => { if (!to) return; rows.forEach(r => { r.tabIndex = -1; }); to.tabIndex = 0; to.focus(); };
  if (e.key === "ArrowDown") { e.preventDefault(); move(rows[i + 1]); }
  else if (e.key === "ArrowUp") { e.preventDefault(); move(rows[i - 1]); }
  else if (e.key === "Home") { e.preventDefault(); move(rows[0]); }
  else if (e.key === "End") { e.preventDefault(); move(rows[rows.length - 1]); }
  else if (row.dataset.dir && (e.key === "ArrowRight" || e.key === "ArrowLeft")) {
    e.preventDefault();
    const open = row.getAttribute("aria-expanded") === "true";
    if ((e.key === "ArrowRight") !== open) toggleDir(row.dataset.dir, true);
  }
}

function toggleDir(path, keepFocus = false) {
  repo.expanded.has(path) ? repo.expanded.delete(path) : repo.expanded.add(path);
  renderTree();
  if (keepFocus) {
    const row = $(`#repo-tree [data-dir="${CSS.escape(path)}"]`);
    if (row) { $("#repo-tree").querySelectorAll(".tree-row").forEach(r => { r.tabIndex = -1; }); row.tabIndex = 0; row.focus(); }
  }
}

// ------------------------------------------------------------ overview (report panel)
function renderOverview() {
  const job = repo.job;
  const s = job.summary;
  const files = job.files;
  const failing = files.filter(f => f.gate === "FAIL");
  const worst = [...files].filter(f => !f.ok || f.findings)
    .sort((a, b) => (a.ok - b.ok) || (a.score - b.score) || (b.findings - a.findings)).slice(0, 8);
  const unparsable = files.filter(f => !f.ok);
  const allPass = failing.length === 0;

  resultsEl.innerHTML = `<div class="report repo-overview">
    <div class="summary" style="--ring-color:${s.score !== null ? gradeColor(s.score) : "var(--muted)"}">
      ${s.score !== null ? scoreRing(s.score) : `<div class="ring"><div class="ring-label"><strong>–</strong><span>no code</span></div></div>`}
      <div class="verdict">
        <div class="grade-line">${s.grade ? `<span class="grade">Grade ${s.grade}</span>` : ""}
          <span class="gate ${allPass ? "PASS" : "FAIL"}">${allPass ? "✓ ALL PASS" : `✕ ${failing.length} FAIL`}</span></div>
        <p class="reasons" style="padding:0">${s.files_passing} of ${plural(s.files_scanned, "file")} pass the gate.
          The repository score is the average file score, weighted by lines of code.</p>
        <div class="stats">${plural(s.lines, "line")} · ${plural(s.findings, "finding")}${s.files_unparsable ? ` · ${s.files_unparsable} unparsable` : ""}</div>
      </div>
    </div>
    <div class="chips repo-sev-chips">${SEVERITIES.filter(sev => s.severity_counts[sev]).map(sev => `
      <button class="chip sev-${sev} ${repo.severity === sev ? "active" : ""}" data-tree-sev="${sev}" title="Show files with ${sev} findings">
        <span class="dot"></span>${cap(sev)} <b>${s.severity_counts[sev]}</b></button>`).join("")}
      <button class="ghost repo-export" data-export-repo>Export JSON</button></div>
    ${job.files_over_limit ? `<p class="notice">This repository has more Python files than one scan covers: the first
      ${job.max_files} were scanned and ${job.files_over_limit} were not.</p>` : ""}

    ${worst.length ? `<div class="section-title">Files to look at first</div>
    <div class="repo-list">${worst.map(f => `
      <button class="repo-list-row" data-open-file="${escapeHtml(f.path)}" title="${escapeHtml(fileTitle(f))}">
        <span class="dot ${f.ok ? (f.worst ? `sev-${f.worst}` : "clean") : "sev-critical"}"></span>
        <span class="repo-list-path"><span class="dir">${escapeHtml(f.path.slice(0, f.path.lastIndexOf("/") + 1))}</span>${escapeHtml(basename(f.path))}</span>
        <span class="meta">${f.ok ? plural(f.findings, "finding") : "syntax error"}</span>
        ${f.ok ? `<span class="tree-grade" style="color:${gradeColor(f.score)}">${f.score}</span>` : ""}
      </button>`).join("")}</div>` : `<div class="none">No findings in any file. 🎉</div>`}

    ${s.rules.length ? `<div class="section-title">Most common issues</div>
    <p class="cwe-note">Click one to list the files that have it.</p>
    <div class="repo-list">${s.rules.slice(0, 12).map(r => `
      <button class="repo-list-row sev-${r.severity} ${repo.rule === r.rule_id ? "active" : ""}" data-rule="${r.rule_id}">
        <span class="dot"></span>
        <span class="repo-list-path">${escapeHtml(r.title)} <span class="rule-id">${r.rule_id}</span></span>
        <span class="meta">${plural(r.files, "file")}</span>
        <span class="cwe-count">×${r.count}</span>
      </button>`).join("")}</div>` : ""}

    ${unparsable.length ? `<div class="section-title">Couldn't be parsed</div>
    <div class="repo-list">${unparsable.map(f => `
      <button class="repo-list-row" data-open-file="${escapeHtml(f.path)}">
        <span class="dot sev-critical"></span><span class="repo-list-path">${escapeHtml(f.path)}</span>
        <span class="meta">${escapeHtml(f.error)}</span></button>`).join("")}</div>` : ""}

    ${job.skipped?.length ? `<details class="repo-skipped"><summary>${plural(job.skipped.length, "file")} skipped</summary>
      <ul>${job.skipped.map(f => `<li><code>${escapeHtml(f.path)}</code>: ${escapeHtml(f.reason)}</li>`).join("")}</ul></details>` : ""}
  </div>`;
  if (s.score !== null) animateRing(resultsEl, s.score);
}

function onOverviewClick(e) {
  const t = e.target;
  if (!t.closest(".repo-overview")) return;
  const open = t.closest("[data-open-file]");
  if (open) return openFile(open.dataset.openFile);
  const rule = t.closest("[data-rule]");
  if (rule) {
    repo.rule = repo.rule === rule.dataset.rule ? null : rule.dataset.rule;
    if (repo.rule) repo.sort = "worst";
    renderPanel();
    return renderOverview();
  }
  const sev = t.closest("[data-tree-sev]");
  if (sev) {
    repo.severity = repo.severity === sev.dataset.treeSev ? null : sev.dataset.treeSev;
    renderPanel();
    return renderOverview();
  }
  if (t.closest("[data-export-repo]")) {
    const { files, summary, repo: r, commit, ref, skipped } = repo.job;
    downloadJson({ repo: r, commit, ref, summary, files, skipped }, `pwn2patch-${r.name.replace(/[^\w.-]+/g, "_")}.json`);
  }
}

function onPanelClick(e) {
  const t = e.target;
  const example = t.closest("[data-example]");
  if (example) return startScan(example.dataset.example);
  if (t.closest("[data-rescan]")) return startScan(repo.link);
  const file = t.closest("[data-file]");
  if (file) return openFile(file.dataset.file);
  const dir = t.closest("[data-dir]");
  if (dir) return toggleDir(dir.dataset.dir);
  const sort = t.closest("[data-sort]");
  if (sort) { repo.sort = sort.dataset.sort; return renderPanel(); }
  if (t.closest("[data-clear-rule]")) { repo.rule = null; renderPanel(); return repo.current ? null : renderEmpty(); }
  if (t.closest("[data-clear-sev]")) { repo.severity = null; renderPanel(); return repo.current ? null : renderEmpty(); }
}

// ------------------------------------------------------------ mode
// Called by main.js when switching to or from repository mode.
export function enterRepoMode() {
  repoPanel.hidden = false;
  codeEl.placeholder = "Pick a file from the tree…";
  const hash = readHash();
  if (hash.repo && hash.repo !== repo.link) return startScan(hash.repo, { push: false, openAfter: hash });
  renderPanel();
  if (repo.job?.id && !["done", "error"].includes(repo.job.state)) return poll(repo.job.id, null);   // still scanning
  if (repo.current && done()) return openFile(repo.current, { push: false });
  closeFile();
  renderEmpty();
  writeHash();
}

export function leaveRepoMode() {
  clearTimeout(repo.pollTimer);
  repoPanel.hidden = true;
  codeEl.placeholder = "Paste Python code here…";
  editorTitle.innerHTML = "";
  overviewBtn.hidden = true;
  reportTitle.textContent = "Report";
  // keep repo.job and repo.current so switching back restores the same file
}

export const hashWantsRepo = () => !!readHash().repo;

export function initRepo({ setMode }) {
  setEmptyRenderer(() => {
    if (state.mode !== "repo") return false;
    if (done()) renderOverview();
    else resultsEl.innerHTML = `<div class="empty"><div><strong>No repository yet</strong>
      Paste a link on the left, or pick an example.<br>Only Python files are downloaded, and nothing is run.</div></div>`;
    return true;
  });
  $("#repo-form").addEventListener("submit", e => { e.preventDefault(); startScan($("#repo-url").value); });
  repoPanel.addEventListener("click", onPanelClick);
  repoPanel.addEventListener("keydown", onTreeKey);
  repoPanel.addEventListener("input", e => {
    if (e.target.id === "repo-search") { repo.query = e.target.value; renderTree(); }
  });
  repoPanel.addEventListener("change", e => {
    if (e.target.id === "repo-issues") { repo.issuesOnly = e.target.checked; renderTree(); }
  });
  resultsEl.addEventListener("click", onOverviewClick);
  overviewBtn.addEventListener("click", showOverview);
  document.addEventListener("p2p:code-changed", () => { if (currentPath()) updateTitles(); });

  // Back / forward and edited hashes: follow them.
  window.addEventListener("popstate", () => {
    const hash = readHash();
    if (!hash.repo) {
      if (state.mode === "repo" && repo.link) setMode("paste");   // back to before the scan
      return;
    }
    if (state.mode !== "repo") return setMode("repo");
    if (hash.repo !== repo.link) return startScan(hash.repo, { push: false, openAfter: hash });
    if (hash.file && hash.file !== repo.current) return openFile(hash.file, { push: false, line: hash.line });
    if (!hash.file && repo.current) showOverview();
  });
}
