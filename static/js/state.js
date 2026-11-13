// The app's shared state, plus helpers derived from it.
// Modules read and write `state.x` directly; nothing here touches the DOM except reading the editor.
import { codeEl } from "./dom.js";
import { SEVERITIES, isSecret, storage } from "./util.js";

const pick = (value, allowed, fallback) => allowed.includes(value) ? value : fallback;

export const state = {
  mode: "paste",              // "paste" (one file you type or drop) | "repo" (browse a scanned repository)
  report: null,               // last report from /api/analyze
  analyzedCode: null,         // the code that report describes
  previous: null,             // { report, code } before that, for the "score went up" badge
  reportVersion: 0,
  newFile: false,             // the next report belongs to a different file: don't compare it
  activeLine: null,
  findingIndex: new Map(),    // finding object -> its index in report.findings
  undoStack: [],
  filters: { category: null, severity: null, cwe: null, fixable: false },
  view: pick(storage.get("p2p-view"), ["findings", "overview", "cwe"], "findings"),
  groupBy: pick(storage.get("p2p-group"), ["severity", "rule", "line"], "severity"),
  showSuppressed: false,
  aiStatus: { enabled: false, model: "" },   // from /api/policy
  perRuleCap: 3,                             // from /api/policy
  samples: {},
};

export const isFresh = () => !!state.report && codeEl.value === state.analyzedCode;

export function findingsOnLine(line) {
  return isFresh() && state.report.ok ? state.report.findings.filter(f => f.line === line) : [];
}

// Worst severity per line, used for gutter dots, line bands and the ruler.
export function lineMarks() {
  const marks = new Map();
  if (!isFresh()) return marks;
  const { report } = state;
  if (!report.ok) {
    if (report.error?.line) marks.set(report.error.line, "critical");
    return marks;
  }
  for (const f of report.findings) {
    const prev = marks.get(f.line);
    if (!prev || SEVERITIES.indexOf(f.severity) < SEVERITIES.indexOf(prev)) marks.set(f.line, f.severity);
  }
  return marks;
}

// Optional backend fields (see README "Frontend contract"); each falls back gracefully.
export const isRisky = f => f?.patch?.safety === "behavior_change";
export const hasSafetyInfo = () => !!state.report?.ok && state.report.findings.some(f => f.patch?.safety);
export const suppressedList = () =>
  (state.report?.ok && Array.isArray(state.report.suppressed)) ? state.report.suppressed : [];
export const secretLines = () =>
  new Set(state.report?.ok ? state.report.findings.filter(isSecret).map(f => f.line) : []);

// Category and CWE filters (not severity), shared by the findings list and keyboard navigation.
export const matchesScope = f => (!state.filters.category || f.category === state.filters.category) &&
                                 (!state.filters.cwe || f.cwe?.[0]?.id === state.filters.cwe);
export function filteredFindings() {
  if (!state.report?.ok) return [];
  const { fixable, severity } = state.filters;
  return state.report.findings.filter(f => matchesScope(f) && (!fixable || f.patch) && (!severity || f.severity === severity));
}

// What changed since the previous run: score delta plus fixed / new / suppressed findings.
export function changeSummary() {
  const { previous, report } = state;
  if (!previous || !report?.ok) return null;
  // Compare counts per rule: a finding whose line text changed (say, after a rename) is not "new".
  const counts = list => list.reduce((m, f) => m.set(f.rule_id, (m.get(f.rule_id) || 0) + 1), new Map());
  const before = counts(previous.report.findings), after = counts(report.findings);
  let fixed = 0, added = 0;
  for (const rule of new Set([...before.keys(), ...after.keys()])) {
    const d = (after.get(rule) || 0) - (before.get(rule) || 0);
    if (d > 0) added += d; else fixed -= d;
  }
  // Findings that disappeared because they were suppressed weren't fixed.
  const suppressed = Math.max(0, (report.suppressed?.length || 0) - (previous.report.suppressed?.length || 0));
  fixed = Math.max(0, fixed - suppressed);
  return { delta: report.score - previous.report.score, from: previous.report.score, fixed, added, suppressed,
           gateFlipped: previous.report.gate.status === "FAIL" && report.gate.status === "PASS" };
}

export function resetFilters() {
  Object.assign(state.filters, { category: null, severity: null, cwe: null, fixable: false });
  state.showSuppressed = false;
}
