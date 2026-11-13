// Changing the code: previewing and applying patches (rule-based, Patch all, or drafted by
// Workers AI), suppression comments, and undo.
//
// POST /api/fix accepts { code, include_behavior_changes } and may return `complete: false`
// and a `safety` per applied fix. Older backends ignore the flag and omit both fields.
import { codeEl, diffDialog, patchAllBtn, undoBtn } from "./dom.js";
import { runAnalysis } from "./analysis.js";
import { hideHovercard, setCode, syncScroll } from "./editor.js";
import { renderFindings } from "./report.js";
import { changeSummary, hasSafetyInfo, isFresh, isRisky, secretLines, state, suppressedList } from "./state.js";
import { $, cap, escapeHtml, gradeColor, maskSecrets, plural, postJson, richText, toast } from "./util.js";

// Comment that tells the analyzer to skip a rule on one line. Must match the backend's parser.
const SUPPRESS_RE = /#\s*pwn2patch:\s*ignore(?:\[([^\]]*)\])?/;
const STALE = "The code changed. Re-analyze before patching.";

let pendingPatch = null;      // { code, label } to apply if the user confirms
let includeRisky = false;     // Patch all: also apply fixes that change behavior
let aiBusy = false;

export function applyEdits(source, edits) {
  const lines = source.split("\n");
  [...edits].sort((a, b) => b.start - a.start || b.end - a.end)
    .forEach(e => lines.splice(e.start - 1, e.end - e.start + 1, ...e.lines));
  return lines.join("\n");
}

// ------------------------------------------------------------ diff rendering
const diffLine = (cls, sign, no, text) =>
  `<div class="${cls}"><span class="ln-no">${no ?? ""}</span>${sign} ${escapeHtml(text)}</div>`;

// A patch's edits as hunks against the analyzed code, with 2 lines of context. Secret lines are masked.
function editsToDiff(source, edits, masked = new Set()) {
  const lines = source.split("\n");
  const show = n => masked.has(n) ? maskSecrets(lines[n - 1]) : lines[n - 1];
  return [...edits].sort((a, b) => a.start - b.start).map(e => {
    const from = Math.max(1, e.start - 2), to = Math.min(lines.length, Math.max(e.end, e.start - 1) + 2);
    let html = `<div class="hunk">line ${e.start}</div>`;
    for (let n = from; n < e.start; n++) html += diffLine("", " ", n, show(n));
    for (let n = e.start; n <= e.end; n++) html += diffLine("del", "−", n, show(n));
    for (const text of e.lines) html += diffLine("add", "+", "", text);
    for (let n = Math.max(e.end, e.start - 1) + 1; n <= to; n++) html += diffLine("", " ", n, show(n));
    return html;
  }).join("");
}

function unifiedToHtml(diff, masked = new Set()) {
  let oldNo = 0;
  return diff.split("\n").filter(l => l && !l.startsWith("---") && !l.startsWith("+++")).map(l => {
    if (l.startsWith("@@")) { oldNo = Number(/-(\d+)/.exec(l)?.[1] || 1); return `<div class="hunk">line ${oldNo}</div>`; }
    if (l[0] === "+") return diffLine("add", "+", "", l.slice(1));
    const no = oldNo++, text = masked.has(no) ? maskSecrets(l.slice(1)) : l.slice(1);
    return l[0] === "-" ? diffLine("del", "−", no, text) : diffLine("", " ", no, text);
  }).join("");
}

function openDiffDialog() {
  if (!diffDialog.open) diffDialog.showModal();
  $("#apply-diff").focus();
}

// ------------------------------------------------------------ one finding's patch
// ai: the /api/ai-fix result when the patch was drafted by Workers AI
export function previewFix(f, ai = null) {
  if (!f?.patch || !isFresh()) return toast(STALE);
  const { analyzedCode } = state;
  pendingPatch = { code: applyEdits(analyzedCode, f.patch.edits), label: ai ? "AI patch" : f.patch.title };
  $("#diff-title").textContent = f.patch.title;
  $("#diff-body").innerHTML = `
    <p class="score-preview">${ai ? `<span class="ai-badge" title="${escapeHtml(ai.model)}">✨ Workers AI</span>` : ""}
      <span class="sev sev-${f.severity}" style="width:auto">${f.severity}</span>
      ${escapeHtml(f.title)} · line ${f.line}</p>
    ${isRisky(f) ? `<p class="risk-banner"><b>⚠ This patch changes how the code behaves.</b>
      Check the code that calls it before applying.</p>` : ""}
    ${f.patch.note ? `<p class="fix-note">${richText(f.patch.note)}</p>` : ""}
    ${ai ? `<p class="fix-note">Drafted by <code>${escapeHtml(ai.model)}</code>${ai.attempts > 1 ? ` (${ai.attempts} tries)` : ""}.
      Pwn2Patch re-analyzed the result: it parses, ${escapeHtml(f.rule_id)} is gone, and nothing critical, high or medium was added.
      Review it like any code from a stranger.</p>` : ""}
    ${state.mode === "repo" ? `<p class="meta">Repository files are view-only: the patch changes this copy in your browser, not the repository.</p>` : ""}
    <div class="diff">${editsToDiff(analyzedCode, f.patch.edits, secretLines())}</div>`;
  const gain = ai ? ai.score_after - ai.score_before : f.points?.gain_if_fixed ?? 0;
  $("#diff-meta").textContent = ai ? (gain > 0 ? `Score ${ai.score_before} → ${ai.score_after}` : "Verified, but doesn't change the score")
    : gain > 0 ? `Raises the overall score by about ${gain}`
    : f.points?.category_clamped ? `${cap(f.category)} is already at 0: fix a few more to see the score move`
    : "Doesn't change the score, but it's still worth fixing";
  openDiffDialog();
}

// ------------------------------------------------------------ Workers AI
export function aiButton(f) {
  if (!state.aiStatus.enabled || f.patch || !state.report) return "";
  return `<button class="ai-btn" data-ai="${state.findingIndex.get(f)}"
    title="Ask ${escapeHtml(state.aiStatus.model)} on Cloudflare Workers AI for a patch. Pwn2Patch re-checks it before showing it.">✨ Ask Workers AI</button>`;
}

export async function askAI(f, btn) {
  if (!f || !isFresh()) return toast(STALE);
  if (aiBusy) return;
  aiBusy = true;
  hideHovercard();
  const label = btn?.textContent;
  if (btn) { btn.disabled = true; btn.textContent = "Asking Workers AI…"; }
  const code = state.analyzedCode;
  try {
    const result = await postJson("/api/ai-fix", { code, rule_id: f.rule_id, line: f.line });
    if (code !== codeEl.value) return toast("The code changed while Workers AI was working. Ask again.");
    previewFix({ ...f, patch: result.fix }, result);
  } catch (err) {
    toast(`Workers AI: ${err.message}`);
  } finally {
    aiBusy = false;
    if (btn?.isConnected) { btn.disabled = false; btn.textContent = label; }
  }
}

// ------------------------------------------------------------ Patch all
function appliedListHtml(applied) {
  const group = items => `<ul class="applied-list">${[...items.reduce((m, a) => m.set(a.title, (m.get(a.title) || 0) + 1), new Map())]
    .map(([title, n]) => `<li>${richText(title)}${n > 1 ? ` <b>×${n}</b>` : ""}</li>`).join("")}</ul>`;
  if (!applied.some(a => a.safety)) return group(applied);
  const risky = applied.filter(a => a.safety === "behavior_change"), safe = applied.filter(a => a.safety !== "behavior_change");
  return (safe.length ? `<div class="applied-group">Safe · ${safe.length}</div>${group(safe)}` : "") +
         (risky.length ? `<div class="applied-group" style="color:var(--warn)">⚠ Changes behavior · ${risky.length}</div>${group(risky)}` : "");
}

async function previewPatchAll() {
  if (!isFresh()) return toast(STALE);
  const { report, analyzedCode } = state;
  patchAllBtn.disabled = true;
  try {
    const result = await postJson("/api/fix", { code: analyzedCode, include_behavior_changes: includeRisky });
    if (!result.ok) return toast(result.error?.message || "Could not patch this code.");
    const riskyAvailable = report.findings.filter(isRisky).length;
    if (!result.applied.length && !riskyAvailable) return toast("Nothing left to patch automatically.");
    pendingPatch = result.applied.length ? { code: result.code, label: plural(result.applied.length, "patch", "patches") } : null;
    $("#diff-title").textContent = result.applied.length ? `Patch all: ${plural(result.applied.length, "fix", "fixes")}` : "Patch all";
    $("#diff-body").innerHTML = `
      ${hasSafetyInfo() && riskyAvailable ? `<label class="toggle risky-toggle"><input type="checkbox" id="include-risky" ${includeRisky ? "checked" : ""}>
        Also apply ${plural(riskyAvailable, "fix", "fixes")} that change behavior</label>` : ""}
      ${result.complete === false ? `<p class="notice">Stopped early because there were too many fixes for one run. Apply these, then press Patch all again for the rest.</p>` : ""}
      ${result.applied.length ? `
        <p class="score-preview">Score <b>${result.score_before}</b> → <b style="color:${gradeColor(result.score_after)}">${result.score_after}</b>
          <span class="meta">· fixes are applied one at a time and each result is re-checked</span></p>
        ${appliedListHtml(result.applied)}
        <div class="diff">${unifiedToHtml(result.diff, secretLines())}</div>`
      : `<p class="none">Every remaining patch changes behavior. Tick the box above to review them.</p>`}`;
    $("#diff-meta").textContent = report.findings.length > result.applied.length ? "Some findings will still need a human afterwards" : "";
    $("#apply-diff").disabled = !pendingPatch;
    openDiffDialog();
  } catch (err) {
    toast(`Patch failed: ${err.message}`);
  } finally {
    patchAllBtn.disabled = false;
  }
}

// ------------------------------------------------------------ applying and undo
// Replace the editor's code as one undoable step and re-analyze. Returns the new report.
export async function applyCodeChange(code) {
  state.undoStack.push(codeEl.value);
  undoBtn.hidden = false;
  const scrollTop = codeEl.scrollTop;
  setCode(code, { keepHistory: true });
  codeEl.scrollTop = scrollTop;
  syncScroll();
  return runAnalysis({ quiet: true });
}

async function applyPendingPatch() {
  if (!pendingPatch) return;
  const { code, label } = pendingPatch;
  pendingPatch = null;
  diffDialog.close();
  const data = await applyCodeChange(code);
  const c = changeSummary();
  if (data?.ok && c) toast(`Applied ${label} · ${plural(c.fixed, "issue")} fixed · score ${c.from} → ${data.score}` +
                           (c.gateFlipped ? " · gate now PASSES 🎉" : ""));
}

function undo() {
  if (!state.undoStack.length) return;
  setCode(state.undoStack.pop(), { keepHistory: true });
  undoBtn.hidden = !state.undoStack.length;
  runAnalysis({ quiet: true });
}

// ------------------------------------------------------------ suppression
// Add or remove a `# pwn2patch: ignore[RULE]` comment on the finding's line.
function withSuppression(text, ruleId, add) {
  const m = text.match(SUPPRESS_RE);
  const rules = m?.[1] ? m[1].split(",").map(r => r.trim()).filter(Boolean) : [];
  if (add) {
    if (!m) return `${text.trimEnd()}  # pwn2patch: ignore[${ruleId}]`;
    if (!m[1] || rules.includes(ruleId)) return text;     // a bare ignore already covers every rule
    return text.replace(SUPPRESS_RE, `# pwn2patch: ignore[${[...rules, ruleId].join(", ")}]`);
  }
  if (!m) return text;
  const left = rules.filter(r => r !== ruleId);
  return left.length ? text.replace(SUPPRESS_RE, `# pwn2patch: ignore[${left.join(", ")}]`)
                     : text.replace(/\s*#\s*pwn2patch:\s*ignore(?:\[[^\]]*\])?/, "");
}

function editLine(line, transform) {
  const lines = codeEl.value.split("\n");
  const text = lines[line - 1];
  if (text === undefined) return null;
  // Appending a comment inside an unfinished string or a continued line would break the code.
  if (/"""|'''|\\$/.test(text)) return null;
  const next = transform(text);
  if (next === text) return null;
  lines[line - 1] = next;
  return lines.join("\n");
}

export async function suppress(f) {
  if (!f) return;
  if (!isFresh()) return toast("The code changed. Re-analyze first.");
  const code = editLine(f.line, text => withSuppression(text, f.rule_id, true));
  if (code === null) return toast(`Can't add an ignore comment to line ${f.line}: add it by hand`);
  const data = await applyCodeChange(code);
  if (!data?.ok) return;
  const still = data.findings.some(x => x.rule_id === f.rule_id && x.line === f.line);
  toast(still && !Array.isArray(data.suppressed)
    ? "Ignore comment added. The analyzer doesn't read suppressions yet, so the finding stays for now."
    : `Suppressed ${f.rule_id} on line ${f.line} · Undo to bring it back`);
}

export async function unsuppress(f) {
  if (!f) return;
  const code = editLine(f.line, text => withSuppression(text, f.rule_id, false));
  if (code === null) return toast(`No ignore comment for ${f.rule_id} found on line ${f.line}`);
  await applyCodeChange(code);
  if (!suppressedList().length) state.showSuppressed = false;
  renderFindings();
  toast(`${f.rule_id} on line ${f.line} is reported again`);
}

export function initPatches() {
  patchAllBtn.addEventListener("click", previewPatchAll);
  $("#diff-body").addEventListener("change", e => {
    if (e.target.id !== "include-risky") return;
    includeRisky = e.target.checked;
    previewPatchAll();
  });
  $("#apply-diff").addEventListener("click", applyPendingPatch);
  $("#cancel-diff").addEventListener("click", () => diffDialog.close());
  $("#close-diff").addEventListener("click", () => diffDialog.close());
  diffDialog.addEventListener("click", e => { if (e.target === diffDialog) diffDialog.close(); });
  diffDialog.addEventListener("close", () => { pendingPatch = null; $("#apply-diff").disabled = false; });
  undoBtn.addEventListener("click", undo);
}
