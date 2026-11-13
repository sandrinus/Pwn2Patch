// The code editor: a textarea over a syntax-highlighted <pre>, with a gutter, line bands,
// column underlines, an overview ruler, a hover card and a status bar for the caret's line.
import {
  bandsEl, codeEl, gutterInner, hlEl, hovercard, lineMeta, resultsPanel, ruler, squigglesEl, statusbar, undoBtn,
} from "./dom.js";
import { cancelLive, scheduleLive } from "./analysis.js";
import { aiButton, askAI, previewFix, suppress } from "./patches.js";
import { markActiveFindings } from "./report.js";
import { findingsOnLine, isFresh, isRisky, lineMarks, state } from "./state.js";
import { escapeHtml, isMac, messageHtml } from "./util.js";

export const LINE_H = 20, PAD = 12;
// Above this size, syntax highlighting and live re-analysis switch off to keep typing responsive.
export const LARGE_FILE_CHARS = 60_000;

// ------------------------------------------------------------ syntax highlighting
const KEYWORDS = new Set(("False None True and as assert async await break class continue def del elif else except " +
  "finally for from global if import in is lambda nonlocal not or pass raise return try while with yield match case").split(" "));
const BUILTINS = new Set(("print len range open eval exec compile str int float bool bytes list dict set tuple type " +
  "isinstance getattr setattr hasattr super object self cls input __name__ __import__ Exception BaseException " +
  "ValueError KeyError TypeError OSError RuntimeError").split(" "));
// comment | string (prefixes, triple quotes, unterminated) | decorator | number | identifier
const TOKEN_RE = /(#[^\n]*)|([rRbBuUfF]{0,2}(?:"""[\s\S]*?(?:"""|$)|'''[\s\S]*?(?:'''|$)|"(?:\\.|[^"\\\n])*"?|'(?:\\.|[^'\\\n])*'?))|(@[\w.]+)|(\b\d[\w.]*)|([A-Za-z_]\w*)/g;

export function highlight(text) {
  let html = "", last = 0, prevWord = "";
  for (const m of text.matchAll(TOKEN_RE)) {
    html += escapeHtml(text.slice(last, m.index));
    last = m.index + m[0].length;
    const [tok, com, str, deco, num, word] = m;
    let cls = com ? "com" : str ? "str" : deco ? "deco" : num ? "num" : null;
    if (word) {
      cls = KEYWORDS.has(word) ? "kw" : (prevWord === "def" || prevWord === "class") ? "fn" : BUILTINS.has(word) ? "bi" : null;
      prevWord = word;
    }
    html += cls ? `<span class="tk-${cls}">${escapeHtml(tok)}</span>` : escapeHtml(tok);
  }
  return html + escapeHtml(text.slice(last)) + "\n ";   // trailing line keeps the last empty line's height
}

export const isLarge = () => codeEl.value.length > LARGE_FILE_CHARS;

function renderHighlight() {
  const on = !isLarge();
  codeEl.classList.toggle("highlighted", on);
  hlEl.innerHTML = on ? highlight(codeEl.value) : "";
}

// Width of one monospace character, for placing column underlines.
let charW = 0;
export function measureChar() {
  const probe = Object.assign(document.createElement("span"), { textContent: "x".repeat(100) });
  probe.style.cssText = "position:absolute;visibility:hidden;white-space:pre;font:13px/20px var(--mono)";
  codeEl.parentElement.appendChild(probe);
  charW = probe.getBoundingClientRect().width / 100;
  probe.remove();
}

// The analyzer reports UTF-8 byte columns; convert to a character index.
const utf8 = new TextEncoder();
function charIndex(text, byteCol) {
  let bytes = 0, i = 0;
  for (const ch of text) {
    if (bytes >= byteCol) break;
    bytes += utf8.encode(ch).length;
    i += ch.length;
  }
  return i;
}

// ------------------------------------------------------------ decorations
let gutterKey = "";
export function renderEditorDecorations(force = false) {
  const count = codeEl.value.split("\n").length;
  lineMeta.textContent = `${count} line${count === 1 ? "" : "s"}` + (isLarge() ? " · large file: live off" : "");
  const marks = lineMarks();
  const key = `${count}|${isFresh()}|${state.activeLine}|${state.reportVersion}`;
  if (key !== gutterKey || force) {
    gutterKey = key;
    let html = "";
    for (let i = 1; i <= count; i++) {
      const sev = marks.get(i);
      const cls = ["ln", sev ? `mark sev-${sev}` : "", i === state.activeLine ? "active" : ""].join(" ");
      html += `<div class="${cls}" data-line="${i}">${i}</div>`;
    }
    gutterInner.innerHTML = html;

    let bands = "";
    for (const [line, sev] of marks) bands += `<div class="band sev-${sev}" style="top:${PAD + (line - 1) * LINE_H}px"></div>`;
    if (state.activeLine) bands += `<div class="band active" style="top:${PAD + (state.activeLine - 1) * LINE_H}px"></div>`;
    bandsEl.innerHTML = bands;

    // Underline from the reported column to the end of the line's code.
    let squiggles = "";
    if (isFresh() && state.report.ok && charW) {
      const lines = codeEl.value.split("\n");
      for (const f of state.report.findings) {
        const text = lines[f.line - 1] ?? "";
        const start = Math.min(charIndex(text, Math.max(0, (f.col || 1) - 1)), text.length);
        const firstCode = text.length - text.trimStart().length;
        const from = Math.max(start, firstCode);
        const width = Math.max(1, text.trimEnd().length - from);
        squiggles += `<div class="squiggle sev-${f.severity}" style="top:${PAD + f.line * LINE_H - 3}px;` +
                     `left:${16 + from * charW}px;width:${width * charW}px"></div>`;
      }
    }
    squigglesEl.innerHTML = squiggles;

    // Overview ruler: one tick per marked line, positioned by its share of the file.
    ruler.innerHTML = [...marks].map(([line, sev]) =>
      `<button class="tick sev-${sev}" data-line="${line}" title="Line ${line}" style="top:calc(${((line - 1) / Math.max(count, 1)) * 100}% + 2px)"></button>`).join("");
  }
  syncScroll();
}

export function syncScroll() {
  const y = -codeEl.scrollTop;
  gutterInner.style.transform = `translateY(${y}px)`;
  bandsEl.style.transform = `translateY(${y}px)`;
  squigglesEl.style.transform = `translate(${-codeEl.scrollLeft}px, ${y}px)`;
  hlEl.style.transform = `translate(${-codeEl.scrollLeft}px, ${y}px)`;
}

// ------------------------------------------------------------ navigation and content
// focus: false keeps keyboard focus where it is (j/k navigation from the report).
export function jumpToLine(line, { focus = true } = {}) {
  const lines = codeEl.value.split("\n");
  let offset = 0;
  for (let i = 0; i < line - 1 && i < lines.length; i++) offset += lines[i].length + 1;
  state.activeLine = line;
  if (focus) codeEl.focus({ preventScroll: true });
  codeEl.setSelectionRange(offset, offset);
  codeEl.scrollTop = Math.max(0, PAD + (line - 1) * LINE_H - codeEl.clientHeight / 3);
  codeEl.scrollLeft = 0;
  renderEditorDecorations();
  markActiveFindings(line, false);
  renderStatus();
}

// keepHistory: a patch or undo of the same file, so the score badge and undo stack stay meaningful.
export function setCode(text, { keepHistory = false } = {}) {
  if (!keepHistory) {
    state.previous = null;
    state.undoStack.length = 0;
    undoBtn.hidden = true;
    state.newFile = true;   // don't compare the next report with a different file's
  }
  codeEl.value = text.replace(/\r\n/g, "\n");
  codeEl.scrollTop = 0;
  codeEl.scrollLeft = 0;
  state.activeLine = null;
  onCodeChanged();
}

export function onCodeChanged() {
  if (state.activeLine && state.activeLine > codeEl.value.split("\n").length) state.activeLine = null;
  resultsPanel.classList.toggle("is-stale", !!state.report && !isFresh());
  renderHighlight();
  renderEditorDecorations();
  renderStatus();
  hideHovercard();
  cancelLive();
  if (!isLarge() && codeEl.value.trim() && !isFresh()) scheduleLive();
  document.dispatchEvent(new CustomEvent("p2p:code-changed"));
}

export const caretLine = () => codeEl.value.slice(0, codeEl.selectionStart).split("\n").length;

// ------------------------------------------------------------ status bar
// Findings on the caret's line, so keyboard users get what the hover card shows.
let statusFrame = 0;
export function renderStatus() {
  cancelAnimationFrame(statusFrame);
  statusFrame = requestAnimationFrame(() => {
    const line = document.activeElement === codeEl ? caretLine() : state.activeLine;
    const found = line ? findingsOnLine(line) : [];
    const hint = `<span class="sb-hint"><kbd class="k">F8</kbd> next issue · <kbd class="k">${isMac ? "⌘" : "Ctrl"}+.</kbd> quick fix</span>`;
    if (!found.length) {
      statusbar.innerHTML = `<span>${line ? `Ln ${line}` : ""}</span>${hint}`;
      return;
    }
    const f = found[0], i = state.findingIndex.get(f);
    statusbar.innerHTML = `<span class="sev sev-${f.severity}">${f.severity}</span>
      <span class="sb-msg" title="${escapeHtml(f.message.replace(/`/g, ""))}">${messageHtml(f.message)}${found.length > 1 ? ` <span class="meta">+${found.length - 1} more</span>` : ""}</span>
      ${f.patch ? `<button class="fix-btn ${isRisky(f) ? "risky" : ""}" data-fix="${i}">Preview fix</button>` : aiButton(f)}
      <button class="link-btn" data-suppress="${i}">Suppress</button>`;
  });
}

// ------------------------------------------------------------ hover card
let hoverLine = null, hideTimer = null;
export function hideHovercard() { hovercard.classList.remove("show"); hoverLine = null; }

function onHover(e) {
  const rect = codeEl.getBoundingClientRect();
  const line = Math.floor((e.clientY - rect.top + codeEl.scrollTop - PAD) / LINE_H) + 1;
  const found = findingsOnLine(line);
  if (!found.length) {
    if (!hovercard.matches(":hover")) { clearTimeout(hideTimer); hideTimer = setTimeout(hideHovercard, 150); }
    return;
  }
  clearTimeout(hideTimer);
  if (line !== hoverLine) {
    hoverLine = line;
    hovercard.innerHTML = found.map(f => `
      <div class="hc-item sev-${f.severity}">
        <span class="sev">${f.severity}</span><b>${escapeHtml(f.title)}</b>
        <p>${messageHtml(f.message)}</p>
        ${f.patch ? `<button class="fix-btn ${isRisky(f) ? "risky" : ""}" data-fix="${state.findingIndex.get(f)}">${isRisky(f) ? "⚠ " : ""}Preview fix</button>`
                  : aiButton(f) || `<span class="manual">No auto-patch</span>`}
        <button class="link-btn" data-suppress="${state.findingIndex.get(f)}">Suppress</button>
      </div>`).join("");
    hovercard.classList.add("show");
  }
  const top = rect.top + PAD + line * LINE_H - codeEl.scrollTop + 4;
  const below = top + hovercard.offsetHeight < innerHeight - 8;
  hovercard.style.top = `${below ? top : top - LINE_H - hovercard.offsetHeight - 8}px`;
  hovercard.style.left = `${Math.min(e.clientX + 12, innerWidth - hovercard.offsetWidth - 12)}px`;
}

// Buttons inside the hover card and status bar share one handler.
function onFindingAction(e, { closeCard = false } = {}) {
  const findings = state.report?.findings || [];
  const fix = e.target.closest("[data-fix]"), ai = e.target.closest("[data-ai]");
  const sup = e.target.closest("[data-suppress]"), link = e.target.closest(".line-link");
  if (closeCard && (fix || sup || link)) hideHovercard();
  if (fix) previewFix(findings[Number(fix.dataset.fix)]);
  else if (ai) askAI(findings[Number(ai.dataset.ai)], ai);
  else if (sup) suppress(findings[Number(sup.dataset.suppress)]);
  else if (link) { jumpToLine(Number(link.dataset.goto)); markActiveFindings(Number(link.dataset.goto), true); }
}

// ------------------------------------------------------------ wiring
export function initEditor() {
  codeEl.addEventListener("input", onCodeChanged);
  codeEl.addEventListener("scroll", () => { syncScroll(); hideHovercard(); });
  ["keyup", "click", "focus", "blur"].forEach(type => codeEl.addEventListener(type, renderStatus));
  codeEl.addEventListener("mousemove", onHover);
  codeEl.addEventListener("mouseleave", () => {
    hideTimer = setTimeout(() => { if (!hovercard.matches(":hover")) hideHovercard(); }, 200);
  });
  hovercard.addEventListener("mouseleave", hideHovercard);
  hovercard.addEventListener("click", e => onFindingAction(e, { closeCard: true }));
  statusbar.addEventListener("click", e => onFindingAction(e));

  codeEl.addEventListener("keydown", e => {
    if (e.key === "Tab" && !e.shiftKey && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      const { selectionStart: s, selectionEnd: end } = codeEl;
      codeEl.setRangeText("    ", s, end, "end");
      onCodeChanged();
    } else if (e.key === "Escape") {
      codeEl.blur();
    }
  });

  const jumpAndMark = line => { jumpToLine(line); markActiveFindings(line, true); };
  ruler.addEventListener("click", e => {
    const tick = e.target.closest(".tick");
    if (tick) jumpAndMark(Number(tick.dataset.line));
  });
  gutterInner.addEventListener("click", e => {
    const ln = e.target.closest(".ln.mark");
    if (ln) jumpAndMark(Number(ln.dataset.line));
  });

  measureChar();
  document.fonts?.ready.then(() => { measureChar(); renderEditorDecorations(true); });
  renderEditorDecorations();
}
