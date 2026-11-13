"""Turn a list of findings into category scores, an overall grade and a pass/fail gate.

Scoring is deterministic: the same code and policy always produce the same score.

  * Every category starts at 100.
  * Each finding subtracts the policy's penalty for its severity.
  * A single rule counts at most `max_counted_per_rule` times, so one noisy
    rule (say, 40 long lines) can't zero out a whole category on its own.
  * The overall score is the weighted average of the category scores.
  * The gate FAILS if the overall score is below `gate.min_score` or if any
    finding has a severity listed in `gate.fail_on_severity`.
"""
from __future__ import annotations

from collections import Counter, defaultdict

from .analyzer import Finding
from .rules import CATEGORIES, RULES, SEVERITIES


def grade_for(score: float) -> str:
    for threshold, grade in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
        if score >= threshold:
            return grade
    return "F"


def score_findings(findings: list[Finding], policy: dict) -> dict:
    penalties = policy["penalties"]
    cap = policy.get("max_counted_per_rule", 3)

    per_rule = Counter(f.rule_id for f in findings)
    penalty_by_category: dict[str, float] = defaultdict(float)
    for rule_id, count in per_rule.items():
        rule = RULES[rule_id]
        penalty_by_category[rule.category] += penalties[rule.severity] * min(count, cap)

    findings_by_category = Counter(RULES[f.rule_id].category for f in findings)
    categories = {
        cat: {
            "score": max(0, round(100 - penalty_by_category[cat])),
            "findings": findings_by_category[cat],
        }
        for cat in CATEGORIES
    }

    weights = policy["weights"]
    total_weight = sum(weights.get(cat, 0) for cat in CATEGORIES) or 1
    overall = round(sum(categories[cat]["score"] * weights.get(cat, 0) for cat in CATEGORIES) / total_weight)

    by_severity = Counter(RULES[f.rule_id].severity for f in findings)
    gate = policy["gate"]
    reasons = []
    if overall < gate["min_score"]:
        reasons.append(f"Score {overall} is below the required {gate['min_score']}")
    for severity in gate.get("fail_on_severity", []):
        if by_severity[severity]:
            plural = "s" if by_severity[severity] > 1 else ""
            reasons.append(f"{by_severity[severity]} {severity}-severity finding{plural}")

    return {
        "score": overall,
        "grade": grade_for(overall),
        "categories": categories,
        "severity_counts": {sev: by_severity[sev] for sev in SEVERITIES},
        "gate": {"status": "FAIL" if reasons else "PASS", "reasons": reasons},
    }
