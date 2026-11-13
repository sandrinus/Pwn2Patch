# Compliance Checker (Hacknight demo)

Paste Python code and get a report: a score out of 100, a grade, a score for each category, and a **PASS/FAIL gate** based on a policy file.
Every finding says *what* is wrong, *why* it matters, *how* to fix it, and links to the CWE or PEP behind it.

The code is **parsed, never executed**. It is turned into an AST and pattern-matched, so it is safe to paste untrusted code.

No dependencies: Python 3.10+ standard library only.

## Run it

```bash
python server.py
```

Then open http://127.0.0.1:8000. Click **Load messy sample**, then **Analyze** (or press Ctrl+Enter).
Click a finding to jump to its line; click a category bar or a severity chip to filter.

Command line / CI (exit code 1 when the gate fails):

```bash
python cli.py samples/bad_example.py
python cli.py path/to/project/ --json
```

Tests:

```bash
python -m unittest
```

## How it works

```
code ──► analyzer.py ──► findings ──► scoring.py ──► score, grade, gate ──► UI / CLI / JSON
          (AST walk)       (rule id,     (policy.json:
                            line, msg)    weights, penalties, gate)
```

| File | What it does |
|---|---|
| `checker/rules.py` | Rule catalog: id, category, severity, why, fix, CWE/PEP reference |
| `checker/analyzer.py` | Walks the AST and reports rule violations with line numbers |
| `checker/scoring.py` | Category scores → weighted overall score → grade → PASS/FAIL gate |
| `checker/policy.json` | The "compliance policy": weights, penalties, limits, gate, disabled rules |
| `checker/engine.py` | `analyze(source) -> dict`: the one function everything else calls |
| `server.py` | Standard-library HTTP server: `POST /api/analyze`, `GET /api/policy`, `GET /api/samples` |
| `cli.py` | Terminal output + exit codes for CI |
| `static/index.html` | The whole UI: editor with line markers, score ring, filters, policy viewer |

### Scoring

* Each category (security, reliability, maintainability, style) starts at 100.
* Each finding subtracts a penalty for its severity (critical 30, high 15, medium 7, low 3, info 1).
  A single rule counts at most 3 times, so one noisy rule can't zero a category.
* Overall = weighted average (security 40%, reliability 25%, maintainability 20%, style 15%).
* **Gate FAILS** if overall < 70 **or** any critical/high finding exists.

It's deterministic: the same code always gets the same score.

### Rules (25)

| Category | Rules |
|---|---|
| Security | eval/exec, shell injection, SQL injection (incl. via variables), hardcoded secrets, pickle/yaml deserialization, `verify=False`, MD5/SHA-1, Flask debug mode |
| Reliability | bare `except`, swallowed exceptions, mutable defaults, `open()` without `with`, `== None` |
| Maintainability | long functions, cyclomatic complexity, too many params, deep nesting, wildcard imports, `global` |
| Style | docstrings, naming, line length, `print` vs logging, TODO/FIXME, type hints |

## Adding a rule

1. Add a `Rule(...)` to `checker/rules.py` (id, title, category, severity, why, fix, ref).
2. Detect it in `checker/analyzer.py`, usually in a `visit_*` method, and call `self.report("ID", node, "message")`.
3. Add a test in `tests/test_checker.py`.

## Ideas for the rest of the night

* **AI explanations**: send the findings (not just the raw code) to an LLM to write a personalized fix or patch. The score stays deterministic.
* **More languages**: run `eslint` / `semgrep` through `subprocess` and map their output into the same `Finding` format.
* **Benchmarks**: run the checker over popular open-source repos and show "your complexity is worse than 80% of Flask's functions".
* **GitHub Action**: `python cli.py .` already exits 1 on FAIL, so it can block PRs today.
