# Pwn2Patch (Hacknight demo)

Paste Python code and get a report: a score out of 100, a grade, a score for each category, and a **PASS/FAIL gate** based on a policy file.
Every finding says *what* is wrong, *why* it matters, *how* to fix it, and links to the CWE or PEP behind it.

The code is **parsed, never executed**. It is turned into an AST and pattern-matched, so it is safe to paste untrusted code.

No dependencies: Python 3.10+ standard library only.

## Run it

```bash
python server.py
```

Then open http://127.0.0.1:8000. The messy sample loads and is analyzed straight away.

* **Live**: the report re-runs as you type (turn off with the *Live* toggle; Ctrl/⌘+Enter runs it by hand).
* **Hover** an underlined line to see what's wrong with it; click a gutter dot or a mark in the right-hand ruler to jump to it.
* **Preview fix** on a finding shows the exact patch as a diff; **Apply** it and the score badge shows what changed.
* **Patch all** applies every safe automatic fix in one go (46 → 74 on the messy sample). **Undo** reverts a patch.
* Click a category bar, a CWE or a severity / *Fixable* chip to filter.

## Patching

`checker/fixes.py` turns findings into line edits: parameterized SQL, argument-list subprocess calls,
secrets read from `os.environ`, `with open(...)`, `is None`, renames that update every use in the file, and so on
(17 of 25 rules). Every fix is checked before it is offered: the patched code must still parse.

Some findings deliberately get **no** automatic fix, because any mechanical change would be wrong or misleading:
a route that lets the user choose the program to run, MD5 on a password (SHA-256 would be just as wrong there; it
needs bcrypt/argon2 and a salt), a hardcoded default parameter (an API change), long or complex functions.
*Patch all* applies fixes one at a time and re-analyzes after each, so they never conflict.

### AI patches with Cloudflare Workers AI

For the findings above that get no mechanical fix, the UI shows **✨ Ask Workers AI**. The rules still decide
*what* is wrong, so the score stays deterministic; a Workers AI model only drafts *how* to fix it, and
Pwn2Patch doesn't trust the draft. `checker/ai_fix.py` accepts it only if:

1. it is one edit of whole statements that covers the reported line (plus optional new `import` lines),
2. the patched code still parses,
3. re-running the analyzer shows the finding gone, and
4. no new critical, high or medium finding appears. New low/info findings (a long line, a missing
   docstring) are allowed and listed in the fix's note.

Before checking, the draft is cleaned up for two mistakes models often make: copying the `NN | ` line
numbers from the prompt, and losing the indentation. If a draft fails, the model gets the analyzer's reasons
(quoting the code, since added imports shift line numbers) and tries again, up to 3 attempts. The server
prints each rejected draft's reason. The code is still never executed, neither yours nor the model's. The
model is told the pasted code is untrusted data, and anything it sends back goes through the same checks
either way.

To turn it on, create a Cloudflare API token with **Workers AI Read + Edit**, then:

```bash
export CLOUDFLARE_ACCOUNT_ID=...
export CLOUDFLARE_API_TOKEN=...
export PWN2PATCH_AI_MODEL=@cf/meta/llama-3.3-70b-instruct-fp8-fast   # optional, this is the default
python server.py
```

The server prints whether AI patching is on. Without the variables, the button is hidden and everything else
works as before. The code is sent to Cloudflare, so don't paste anything you can't share.

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
| `checker/rules.py` | Rule catalog: id, category, severity, why, fix, CWE mapping, PEP reference |
| `checker/cwe.py` | CWE catalog: official MITRE titles, short labels, MITRE's mapping guidance |
| `checker/analyzer.py` | Walks the AST and reports rule violations with line numbers |
| `checker/scoring.py` | Category scores → weighted overall score → grade → PASS/FAIL gate |
| `checker/policy.json` | The "compliance policy": weights, penalties, limits, gate, disabled rules |
| `checker/engine.py` | `analyze(source) -> dict`: the one function everything else calls |
| `checker/ai_fix.py` | Workers AI patches for findings with no mechanical fix, verified by the analyzer |
| `checker/fixes.py` | Automatic patches: line edits per finding, verified to parse; `fix_all` for *Patch all* |
| `server.py` | Standard-library HTTP server: `POST /api/analyze`, `POST /api/fix`, `POST /api/ai-fix`, `GET /api/policy`, `GET /api/samples` |
| `cli.py` | Terminal output + exit codes for CI |
| `static/index.html` | The whole UI: editor with underlines and hover cards, score ring and change badge, fix previews, filters, policy viewer |

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

### CWE mapping

Every finding carries a list of [CWE](https://cwe.mitre.org) entries, most specific first, and the report includes
a `cwe_summary` (one row per weakness, with counts) and `cwe_coverage` (how many findings have a CWE).

* **19 of 25 rules map to a CWE.** All titles were checked against MITRE (CWE 5.0).
  The other 6 rules have no accurate CWE: mutable defaults, `== None`, function length, wildcard imports, `print` and type hints.
  They're left unmapped on purpose, since a forced mapping would be misleading.
* **Context makes it more specific.** A hardcoded *password* maps to CWE-259 (Hard-coded Password), not just
  CWE-798 (Hard-coded Credentials). MD5 used *on a password* maps to CWE-916 (weak password hashing), not just
  CWE-328 (weak hash).
* **Quality vs. vulnerability.** MITRE marks some CWEs as *Prohibited* for vulnerability mapping because they
  describe code quality, not security (CWE-1121 complexity, CWE-1124 nesting, CWE-1064 parameters,
  CWE-1099 naming, CWE-1078 style, CWE-1111 documentation). We still show them, tagged **quality**, so nobody
  mistakes them for vulnerabilities. A test enforces that security rules never use one.

| Rule | CWE | Rule | CWE |
|---|---|---|---|
| SEC001 eval/exec | CWE-95 | REL001 bare except | CWE-396 |
| SEC002 shell injection | CWE-78 | REL003 swallowed exception | CWE-1069, CWE-390 |
| SEC003 SQL injection | CWE-89 | REL004 open() without with | CWE-775 |
| SEC004 hardcoded secret | CWE-798 (CWE-259 for passwords) | MNT002 complexity | CWE-1121 *(quality)* |
| SEC005 deserialization | CWE-502 | MNT003 too many params | CWE-1064 *(quality)* |
| SEC006 verify=False | CWE-295 | MNT004 deep nesting | CWE-1124 *(quality)* |
| SEC007 weak hash | CWE-328 (CWE-916 for passwords) | MNT006 global | CWE-1108 |
| SEC008 debug mode | CWE-489 | STY001 docstring | CWE-1111 *(quality)* |
| STY002 naming | CWE-1099 *(quality)* | STY003 line length | CWE-1078 *(quality)* |
| STY005 TODO/FIXME | CWE-546 | | |

## Adding a rule

1. Add a `Rule(...)` to `checker/rules.py` (id, title, category, severity, why, fix, ref, `cwe=(...)`).
   If it needs a CWE that isn't in `checker/cwe.py` yet, add it there with the exact title from cwe.mitre.org.
2. Detect it in `checker/analyzer.py`, usually in a `visit_*` method, and call `self.report("ID", node, "message")`.
3. Add a test in `tests/test_checker.py`.

## Ideas for the rest of the night

* **AI explanations**: send the findings (not just the raw code) to an LLM to write a personalized fix or patch. The score stays deterministic.
* **More languages**: run `eslint` / `semgrep` through `subprocess` and map their output into the same `Finding` format.
* **Benchmarks**: run the checker over popular open-source repos and show "your complexity is worse than 80% of Flask's functions".
* **GitHub Action**: `python cli.py .` already exits 1 on FAIL, so it can block PRs today.
