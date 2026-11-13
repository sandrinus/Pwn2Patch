// Element references, looked up once. The modules are loaded with `type="module"`,
// which runs after the document is parsed, so every element exists by now.
import { $ } from "./util.js";

export const codeEl = $("#code");
export const gutterInner = $("#gutter-inner");
export const bandsEl = $("#bands");
export const hlEl = $("#hl");
export const squigglesEl = $("#squiggles");
export const ruler = $("#ruler");
export const statusbar = $("#statusbar");
export const hovercard = $("#hovercard");
export const lineMeta = $("#line-meta");
export const liveToggle = $("#live-toggle");
export const analyzeBtn = $("#analyze-btn");
export const undoBtn = $("#undo-btn");

export const resultsEl = $("#results");
export const resultsPanel = $("#results-panel");
export const reportTitle = $("#report-title");
export const patchAllBtn = $("#patch-all-btn");
export const exportBtn = $("#export-btn");
export const overviewBtn = $("#overview-btn");

export const diffDialog = $("#diff-dialog");
export const rulesDialog = $("#rules-dialog");

export const repoPanel = $("#repo-panel");
export const editorTitle = $("#editor-title");
