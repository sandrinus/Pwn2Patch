"""Public entry point: analyze(source) -> JSON-ready report."""
from __future__ import annotations

import ast
import json
from pathlib import Path

from .analyzer import Finding, PythonAnalyzer
from .cwe import CWES
from .rules import RULES, SEVERITIES
from .scoring import score_findings

DEFAULT_POLICY_PATH = Path(__file__).with_name("policy.json")
MAX_SOURCE_CHARS = 200_000


def load_policy(path: str | Path | None = None) -> dict:
    with open(path or DEFAULT_POLICY_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def _error_report(kind: str, message: str, line: int | None = None, col: int | None = None) -> dict:
    return {
        "ok": False,
        "error": {"type": kind, "message": message, "line": line, "col": col},
        "gate": {"status": "FAIL", "reasons": ["The code could not be analyzed"]},
    }


def cwe_ids_for(finding: Finding) -> tuple[str, ...]:
    """The finding's own CWE mapping if the analyzer gave one, otherwise the rule's."""
    return finding.cwe or RULES[finding.rule_id].cwe


def cwe_summary(findings: list[dict]) -> list[dict]:
    """One row per distinct CWE (by each finding's primary CWE), worst severity first."""
    severity_rank = {sev: i for i, sev in enumerate(SEVERITIES)}
    rows: dict[str, dict] = {}
    for f in findings:
        if not f["cwe"]:
            continue
        primary = f["cwe"][0]
        row = rows.setdefault(primary["id"], {**primary, "count": 0, "worst_severity": f["severity"],
                                              "rules": []})
        row["count"] += 1
        if severity_rank[f["severity"]] < severity_rank[row["worst_severity"]]:
            row["worst_severity"] = f["severity"]
        if f["rule_id"] not in row["rules"]:
            row["rules"].append(f["rule_id"])
    return sorted(rows.values(), key=lambda r: (severity_rank[r["worst_severity"]], -r["count"], r["id"]))


def analyze(source: str, policy: dict | None = None) -> dict:
    """Analyze Python source code against a policy. The code is never executed."""
    policy = policy or load_policy()

    if len(source) > MAX_SOURCE_CHARS:
        return _error_report("too_large", f"Input is larger than {MAX_SOURCE_CHARS:,} characters.")
    if not source.strip():
        return _error_report("empty", "There is no code to analyze.")

    analyzer = PythonAnalyzer(source, policy["limits"], set(policy.get("disabled_rules", [])))
    try:
        findings = analyzer.run()
    except SyntaxError as exc:
        return _error_report("syntax", f"Syntax error: {exc.msg}", exc.lineno, exc.offset)
    except (RecursionError, MemoryError, ValueError) as exc:
        return _error_report("parse", f"Could not parse the code: {type(exc).__name__}")

    tree = ast.parse(source)
    stats = {
        "lines": len(source.splitlines()),
        "code_lines": sum(1 for line in source.splitlines() if line.strip() and not line.strip().startswith("#")),
        "functions": sum(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) for n in ast.walk(tree)),
        "classes": sum(isinstance(n, ast.ClassDef) for n in ast.walk(tree)),
    }

    severity_rank = {sev: i for i, sev in enumerate(SEVERITIES)}
    findings_out = []
    for f in findings:
        rule = RULES[f.rule_id]
        findings_out.append({
            "rule_id": f.rule_id,
            "title": rule.title,
            "category": rule.category,
            "severity": rule.severity,
            "line": f.line,
            "col": f.col,
            "message": f.message,
            "snippet": f.snippet,
            "why": rule.why,
            "fix": rule.fix,
            "ref": rule.ref,
            "cwe": [CWES[cwe_id].to_dict() for cwe_id in cwe_ids_for(f)],
        })
    findings_out.sort(key=lambda item: (severity_rank[item["severity"]], item["line"]))

    mapped = sum(1 for f in findings_out if f["cwe"])
    return {
        "ok": True,
        "language": "python",
        "policy": policy.get("name", "custom"),
        "stats": stats,
        **score_findings(findings, policy),
        "cwe_summary": cwe_summary(findings_out),
        "cwe_coverage": {"mapped": mapped, "total": len(findings_out)},
        "findings": findings_out,
    }
