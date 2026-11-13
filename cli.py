"""Command-line checker. Exits with code 1 when the quality gate fails, so it can run in CI.

    python cli.py samples/bad_example.py
    python cli.py src/                      (checks every .py file in the folder)
    python cli.py app.py --json             (machine-readable report)
    python cli.py app.py --policy strict.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from checker import analyze, load_policy

USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ
COLORS = {
    "critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m",
    "info": "\033[90m", "PASS": "\033[1;32m", "FAIL": "\033[1;31m", "dim": "\033[90m", "bold": "\033[1m",
}


def paint(text: str, key: str) -> str:
    return f"{COLORS[key]}{text}\033[0m" if USE_COLOR else text


def collect_files(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            files.extend(sorted(p for p in path.rglob("*.py") if ".venv" not in p.parts))
        else:
            files.append(path)
    return files


def print_report(path: Path, report: dict) -> None:
    print(paint(str(path), "bold"))
    gate = report["gate"]
    if not report["ok"]:
        err = report["error"]
        where = f" (line {err['line']})" if err.get("line") else ""
        print(f"  {paint('FAIL', 'FAIL')}  {err['message']}{where}\n")
        return

    print(f"  Score {report['score']}/100  Grade {report['grade']}   Gate: {paint(gate['status'], gate['status'])}")
    for reason in gate["reasons"]:
        print(f"    - {reason}")
    cats = "  |  ".join(f"{name} {c['score']}" for name, c in report["categories"].items())
    print(paint(f"  {cats}", "dim"))
    print()
    for f in report["findings"]:
        sev = f["severity"].upper().ljust(8)
        cwe = (f["cwe"][0]["id"] if f["cwe"] else "-").ljust(9)
        print(f"  {paint(sev, f['severity'])}  {f['rule_id']}  {cwe} line {str(f['line']).ljust(4)} {f['message']}")
        if f["severity"] in ("critical", "high"):
            print(paint(f"{'':30}fix: {f['how_to_fix']}", "dim"))
    print()
    print_cwe_summary(report)


def print_cwe_summary(report: dict) -> None:
    rows = report.get("cwe_summary") or []
    if not rows:
        return
    coverage = report["cwe_coverage"]
    print(paint(f"  Weaknesses: {len(rows)} distinct CWEs across "
                f"{coverage['mapped']}/{coverage['total']} findings", "bold"))
    for row in rows:
        tag = paint("  (quality, not a vulnerability)", "dim") if row["quality_only"] else ""
        print(f"    {paint(row['id'].ljust(9), row['worst_severity'])} x{str(row['count']).ljust(3)} {row['short']}{tag}")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(description="Check Python code against a compliance policy.")
    parser.add_argument("paths", nargs="+", help="files or folders to check")
    parser.add_argument("--json", action="store_true", help="print the full report as JSON")
    parser.add_argument("--policy", help="path to a policy JSON file")
    args = parser.parse_args()

    policy = load_policy(args.policy)
    files = collect_files(args.paths)
    if not files:
        print("No Python files found.", file=sys.stderr)
        return 2

    reports = {}
    for path in files:
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            print(f"Could not read {path}: {exc}", file=sys.stderr)
            return 2
        reports[str(path)] = analyze(source, policy)

    if args.json:
        print(json.dumps(reports if len(reports) > 1 else next(iter(reports.values())), indent=2))
    else:
        for path, report in reports.items():
            print_report(Path(path), report)

    failed = [p for p, r in reports.items() if r["gate"]["status"] == "FAIL"]
    if len(files) > 1 and not args.json:
        print(f"{len(files) - len(failed)}/{len(files)} files passed the gate.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
