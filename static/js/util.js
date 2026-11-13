// Small helpers shared by every module. No DOM state lives here.

export const SEVERITIES = ["critical", "high", "medium", "low", "info"];
export const QUALITY_HINT = "MITRE classifies this as a code-quality weakness: it describes the problem, " +
                            "but MITRE says not to use it to label security vulnerabilities.";
export const isMac = /Mac|iPhone|iPad/.test(navigator.userAgentData?.platform || navigator.platform || "");

export const $ = (sel, el = document) => el.querySelector(sel);

export const escapeHtml = s => String(s ?? "").replace(/[&<>"']/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
export const richText = s => escapeHtml(s).replace(/`([^`]+)`/g, "<code>$1</code>");
export const plural = (n, one, many = one + "s") => `${n} ${n === 1 ? one : many}`;
export const cap = s => s ? s[0].toUpperCase() + s.slice(1) : "";
export const gradeColor = score => score >= 90 ? "var(--good)" : score >= 70 ? "var(--warn)" : "var(--bad)";
export const severityRank = sev => { const i = SEVERITIES.indexOf(sev); return i < 0 ? SEVERITIES.length : i; };

// Messages can point at another line ("built with string formatting on line 19"): make that a link.
export const messageHtml = s => richText(s).replace(/\bon line (\d+)\b/g,
  (_, n) => `on <button class="line-link" data-goto="${n}" title="Show line ${n}">line ${n}</button>`);

export function refLink(ref) {
  if (!ref) return "";
  const cwe = ref.match(/^CWE-(\d+)$/), pep = ref.match(/^PEP (\d+)$/);
  let url = null, label = ref;
  if (cwe) url = `https://cwe.mitre.org/data/definitions/${cwe[1]}.html`;
  else if (pep) url = `https://peps.python.org/pep-${pep[1].padStart(4, "0")}/`;
  else if (/^https?:\/\//.test(ref)) { url = ref; label = "Reference"; }
  return url ? `<a href="${escapeHtml(url)}" target="_blank" rel="noopener">${escapeHtml(label)} ↗</a>` : escapeHtml(ref);
}

// Secret findings quote the secret. Mask string literals so screenshots, demos and exports don't leak it.
export const SECRET_RULES = new Set(["SEC004", "SEC009"]);
export const isSecret = f => SECRET_RULES.has(f?.rule_id);
const maskValue = v => v.length <= 12 ? v.slice(0, 2) + "•••" : v.slice(0, 4) + "•••" + v.slice(-2);
export const maskSecrets = text => String(text ?? "").replace(/(["'])((?:\\.|(?!\1).)*)\1/g,
  (m, q, inner) => inner.length >= 6 ? q + maskValue(inner) + q : m);

// localStorage can throw (private mode, blocked storage): every access is wrapped.
export const storage = {
  get(key) { try { return localStorage.getItem(key); } catch { return null; } },
  set(key, value) { try { localStorage.setItem(key, value); } catch { /* not available */ } },
};

export function toast(message) {
  const el = $("#toast");
  el.textContent = message;
  el.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => el.classList.remove("show"), 3600);
}

async function readJson(res) {
  let data;
  try { data = await res.json(); } catch { data = {}; }
  if (!res.ok) throw new Error(data.error || res.statusText || `HTTP ${res.status}`);
  return data;
}

export async function postJson(url, body) {
  return readJson(await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" },
                                     body: JSON.stringify(body) }));
}

export async function getJson(url) {
  return readJson(await fetch(url));
}

export function downloadJson(data, filename) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: filename });
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
