// Global keyboard shortcuts:
//   Ctrl/⌘+Enter  analyze            F8 / Shift+F8  next / previous issue
//   Ctrl/⌘+.      quick fix          j / k          next / previous issue (outside text fields)
import { codeEl } from "./dom.js";
import { runAnalysis } from "./analysis.js";
import { caretLine, jumpToLine } from "./editor.js";
import { previewFix } from "./patches.js";
import { markActiveFindings, setView } from "./report.js";
import { filteredFindings, findingsOnLine, isFresh, state } from "./state.js";
import { toast } from "./util.js";

// Next / previous finding (by line) among the ones the current filters show.
export function navigateFinding(dir, { focus }) {
  if (!isFresh() || !state.report.ok) return;
  const lines = [...new Set(filteredFindings().map(f => f.line))].sort((a, b) => a - b);
  if (!lines.length) return;
  const from = state.activeLine ?? (document.activeElement === codeEl ? caretLine() : 0);
  const next = dir > 0 ? (lines.find(l => l > from) ?? lines[0])
                       : ([...lines].reverse().find(l => l < from) ?? lines[lines.length - 1]);
  if (state.view !== "findings") setView("findings");
  jumpToLine(next, { focus });
  markActiveFindings(next, true);
}

// Ctrl/⌘+. previews the patch for the caret's line (or the selected finding's line).
function quickFix() {
  const line = document.activeElement === codeEl ? caretLine() : state.activeLine;
  const here = line ? findingsOnLine(line) : [];
  const f = here.find(x => x.patch);
  if (f) previewFix(f);
  else toast(here.length ? "No automatic patch for this line" : "No finding on this line");
}

export function initKeys() {
  document.addEventListener("keydown", e => {
    const mod = e.ctrlKey || e.metaKey;
    const typing = e.target.closest?.("textarea, input, select, [contenteditable]");
    if (e.key === "Enter" && mod) { e.preventDefault(); runAnalysis(); }
    else if (e.key === "F8") { e.preventDefault(); navigateFinding(e.shiftKey ? -1 : 1, { focus: !!typing }); }
    else if (e.key === "." && mod) { e.preventDefault(); quickFix(); }
    else if (!typing && !mod && !e.altKey && !document.querySelector("dialog[open]") &&
             !e.target.closest?.(".repo-tree") && (e.key === "j" || e.key === "k")) {
      e.preventDefault();
      navigateFinding(e.key === "j" ? 1 : -1, { focus: false });
    }
  });
}
