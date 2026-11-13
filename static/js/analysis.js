// Sending the editor's code to /api/analyze, and re-running it live while you type.
import { analyzeBtn, codeEl, liveToggle, resultsEl, resultsPanel } from "./dom.js";
import { jumpToLine, renderEditorDecorations, renderStatus } from "./editor.js";
import { renderResults } from "./report.js";
import { isFresh, state } from "./state.js";
import { escapeHtml, isMac, postJson, storage } from "./util.js";

let requestSeq = 0;     // ignore responses that arrive after a newer request
let liveTimer = null;

export function cancelLive() { clearTimeout(liveTimer); }

export function scheduleLive() {
  cancelLive();
  if (liveToggle.checked) liveTimer = setTimeout(() => runAnalysis({ quiet: true }), 450);
}

// Share of non-blank lines in `b` that also appear in `a`.
function sharedLineRatio(a, b) {
  const old = new Set(a.split("\n").map(l => l.trim()).filter(Boolean));
  const lines = b.split("\n").map(l => l.trim()).filter(Boolean);
  return lines.length ? lines.filter(l => old.has(l)).length / lines.length : 1;
}

// quiet: a live re-run while typing; it shouldn't move the cursor or flash the button.
export async function runAnalysis({ quiet = false } = {}) {
  cancelLive();
  const code = codeEl.value;
  const seq = ++requestSeq;
  if (!quiet) { analyzeBtn.disabled = true; analyzeBtn.firstChild.textContent = "Analyzing… "; }
  try {
    const data = await postJson("/api/analyze", { code });
    if (seq !== requestSeq) return null;           // a newer run is on its way
    // A paste that replaces most of the file is a different file: don't show "46 fixed" for it.
    if (state.newFile || (state.analyzedCode !== null && sharedLineRatio(state.analyzedCode, code) < 0.3)) {
      state.previous = null;
      state.newFile = false;
      if (!quiet || state.activeLine > code.split("\n").length) state.activeLine = null;
    } else if (state.report?.ok && state.analyzedCode !== code) {
      state.previous = { report: state.report, code: state.analyzedCode };
    }
    state.report = data;
    state.analyzedCode = code;
    state.reportVersion++;
    state.findingIndex = new Map((data.ok ? data.findings : []).map((f, i) => [f, i]));
    if (!quiet) state.activeLine = null;
    renderResults();
    renderEditorDecorations(true);
    renderStatus();
    resultsPanel.classList.remove("is-stale");
    if (!quiet && !data.ok && data.error?.line) jumpToLine(data.error.line);
    document.dispatchEvent(new CustomEvent("p2p:analyzed", { detail: data }));
    return data;
  } catch (err) {
    if (seq !== requestSeq) return null;
    resultsEl.innerHTML = `<div class="error-card"><strong>Request failed.</strong> ${escapeHtml(err.message)}<br>
      Is <code>python server.py</code> still running?</div>`;
    return null;
  } finally {
    if (seq === requestSeq) { analyzeBtn.disabled = false; analyzeBtn.firstChild.textContent = "Analyze "; }
  }
}

// Forget the current report (e.g. switching to a repository with no file open yet).
export function clearReport() {
  requestSeq++;
  cancelLive();
  Object.assign(state, { report: null, analyzedCode: null, previous: null, activeLine: null });
  state.findingIndex = new Map();
  state.reportVersion++;
}

export function initAnalysis() {
  analyzeBtn.addEventListener("click", () => runAnalysis());
  document.querySelector("#analyze-kbd").textContent = isMac ? "⌘ ↵" : "Ctrl ↵";
  liveToggle.checked = storage.get("p2p-live") !== "off";
  liveToggle.addEventListener("change", () => {
    storage.set("p2p-live", liveToggle.checked ? "on" : "off");
    if (liveToggle.checked && !isFresh() && codeEl.value.trim()) runAnalysis({ quiet: true });
  });
}
