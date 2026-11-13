// Entry point: wires the modules together and handles the two modes.
//   paste: one file you type, paste, drop or load from the samples
//   repo:  a scanned Git repository, browsed file by file (see repo.js)
import { codeEl } from "./dom.js";
import { clearReport, initAnalysis, runAnalysis } from "./analysis.js";
import { initEditor, setCode } from "./editor.js";
import { initKeys } from "./keys.js";
import { initPatches } from "./patches.js";
import { initPolicy } from "./policy.js";
import { currentPath, enterRepoMode, hashWantsRepo, initRepo, leaveRepoMode } from "./repo.js";
import { initReport, renderEmpty } from "./report.js";
import { resetFilters, state } from "./state.js";
import { $, getJson, storage } from "./util.js";

let pasteBuffer = "";   // paste mode's code, kept while you browse a repository

function setMode(mode, { initial = false } = {}) {
  if (mode === state.mode && !initial) return;
  if (!initial && state.mode === "paste") pasteBuffer = codeEl.value;
  if (!initial && state.mode === "repo") leaveRepoMode();
  state.mode = mode;
  storage.set("p2p-mode", mode);
  document.body.classList.toggle("repo-mode", mode === "repo");
  document.querySelectorAll("[data-mode]").forEach(btn => {
    const on = btn.dataset.mode === mode;
    btn.classList.toggle("active", on);
    btn.setAttribute("aria-pressed", on);
  });
  document.querySelectorAll("[data-paste-only]").forEach(el => { el.hidden = mode !== "paste"; });
  resetFilters();
  if (mode === "repo") {
    enterRepoMode();
    return;
  }
  if (location.hash) history.replaceState(null, "", location.pathname + location.search);
  clearReport();
  setCode(pasteBuffer);
  if (pasteBuffer.trim()) runAnalysis({ quiet: true });
  else renderEmpty();
}

function initTheme() {
  const saved = storage.get("p2p-theme");
  if (saved) document.documentElement.dataset.theme = saved;
  $("#theme-btn").addEventListener("click", () => {
    const root = document.documentElement;
    const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    root.dataset.theme = dark ? "light" : "dark";
    storage.set("p2p-theme", root.dataset.theme);
  });
}

// Samples, "Open file…" and drag-and-drop all load into paste mode.
function loadIntoPasteMode(text) {
  if (state.mode !== "paste") { pasteBuffer = text; setMode("paste"); }
  else setCode(text);
}

function initFiles() {
  document.querySelectorAll("[data-sample]").forEach(btn =>
    btn.addEventListener("click", () => { if (state.samples[btn.dataset.sample]) loadIntoPasteMode(state.samples[btn.dataset.sample]); }));
  const fileInput = $("#file-input");
  $("#open-btn").addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", async () => {
    const file = fileInput.files[0];
    if (file) loadIntoPasteMode(await file.text());
    fileInput.value = "";
  });
  const editorPanel = $(".editor-panel");
  editorPanel.addEventListener("dragover", e => { e.preventDefault(); });
  editorPanel.addEventListener("drop", async e => {
    const file = e.dataTransfer?.files?.[0];
    if (!file) return;
    e.preventDefault();
    loadIntoPasteMode(await file.text());
  });
}

function start() {
  initEditor();
  initAnalysis();
  initReport({ exportName: () => currentPath()
    ? `pwn2patch-${currentPath().replace(/[^\w.-]+/g, "_")}.json` : "pwn2patch-report.json" });
  initPatches();
  initKeys();
  initPolicy();
  initRepo({ setMode });
  initTheme();
  initFiles();
  document.querySelectorAll("[data-mode]").forEach(btn => btn.addEventListener("click", () => setMode(btn.dataset.mode)));

  const mode = hashWantsRepo() ? "repo" : storage.get("p2p-mode") === "repo" ? "repo" : "paste";
  getJson("/api/samples").then(data => {
    state.samples = data;
    // First visit in paste mode: show the messy sample straight away.
    if (state.mode === "paste" && !codeEl.value && !pasteBuffer && data.bad_example) {
      pasteBuffer = data.bad_example;
      setCode(data.bad_example);
      runAnalysis({ quiet: true });
    }
  }).catch(() => {});
  setMode(mode, { initial: true });
}

start();
