// The "View policy" dialog, and the settings the rest of the UI reads from /api/policy.
import { rulesDialog } from "./dom.js";
import { renderFindings } from "./report.js";
import { state } from "./state.js";
import { $, QUALITY_HINT, escapeHtml, getJson } from "./util.js";

let policyData = null;
const loadPolicy = () => policyData ??= getJson("/api/policy").catch(err => { policyData = null; throw err; });

async function openPolicy() {
  rulesDialog.showModal();
  try {
    const { policy, rules, cwes } = await loadPolicy();
    const mappedRules = rules.filter(r => r.cwe.length).length;
    const cweCell = r => r.cwe.length ? r.cwe.map(id => {
      const c = cwes[id];
      return `<a href="${escapeHtml(c.url)}" target="_blank" rel="noopener" title="${escapeHtml(c.name)}">${id}</a>` +
             (c.quality_only ? ` <span class="quality-tag" title="${escapeHtml(QUALITY_HINT)}">quality</span>` : "");
    }).join("<br>") : `<span class="meta" title="No CWE entry describes this accurately">none</span>`;
    $("#policy-title").textContent = policy.name;
    const weights = Object.entries(policy.weights).map(([k, v]) => `${k} ${Math.round(v * 100)}%`).join(" · ");
    const limits = policy.limits;
    $("#rules-body").innerHTML = `
      <div class="policy-facts">
        <div class="fact"><b>Gate fails when</b>score &lt; ${policy.gate.min_score}, or any ${policy.gate.fail_on_severity.join(" / ")} finding</div>
        <div class="fact"><b>Category weights</b>${weights}</div>
        <div class="fact"><b>Limits</b>${limits.max_function_lines} lines/function · complexity ${limits.max_complexity} · ${limits.max_params} params · nesting ${limits.max_nesting}</div>
        <div class="fact"><b>Penalty per finding</b>${Object.entries(policy.penalties).map(([k, v]) => `${k} −${v}`).join(" · ")}</div>
        <div class="fact"><b>CWE coverage</b>${mappedRules} of ${rules.length} rules map to a CWE (checked against MITRE CWE 5.0)</div>
      </div>
      <p class="meta">Edit <code>checker/policy.json</code> to change the policy and <code>checker/cwe.py</code> for CWE mappings.</p>
      <table><thead><tr><th>Rule</th><th>Severity</th><th>Category</th><th>Checks for</th><th>CWE</th></tr></thead><tbody>
      ${rules.map(r => `<tr><td><code>${r.id}</code></td><td class="sev-cell sev-${r.severity}">${r.severity}</td>
        <td style="text-transform:capitalize">${r.category}</td><td>${escapeHtml(r.title)}</td><td>${cweCell(r)}</td></tr>`).join("")}
      </tbody></table>`;
  } catch {
    $("#rules-body").textContent = "Could not load the policy. Is the server running?";
  }
}

export function initPolicy() {
  $("#rules-btn").addEventListener("click", openPolicy);
  $("#close-rules").addEventListener("click", () => rulesDialog.close());
  rulesDialog.addEventListener("click", e => { if (e.target === rulesDialog) rulesDialog.close(); });
  loadPolicy().then(d => {
    state.perRuleCap = d.policy.max_counted_per_rule ?? 3;
    state.aiStatus = d.ai || state.aiStatus;
    if (state.aiStatus.enabled && state.report) renderFindings();
  }).catch(() => {});
}
