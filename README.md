# Pwn2Patch (Hacknight demo)

Paste Python code, or link a public Git repository, and get a report: a score out of 100, a grade, a score for each category, and a **PASS/FAIL gate** based on a policy file.
Every finding says *what* is wrong, *why* it matters, *how* to fix it, and links to the CWE or PEP behind it.

The code is **parsed, never executed**. It is turned into an AST and pattern-matched, so it is safe to paste untrusted code.

No dependencies: Python 3.10+ standard library only. Scanning a repository uses `git` if it's installed
(otherwise github.com links are downloaded as a zip with the standard library).

## Run it

```bash
python server.py
```

Then open http://127.0.0.1:8000. The messy sample loads and is analyzed straight away.

* **Live**: the report re-runs as you type (turn off with the *Live* toggle; Ctrl/⌘+Enter runs it by hand).
  Live analysis and syntax highlighting switch off automatically for files over 60,000 characters.
* **Hover** an underlined line, or put the cursor on it and read the status bar under the editor.
* **Keyboard**: F8 / Shift+F8 jump to the next / previous issue, Ctrl/⌘+. previews the patch for the cursor's line,
  and j / k step through findings when the editor doesn't have focus.
* **Preview fix** shows the exact patch as a diff; **Apply** it and the score badge shows what changed.
  **Patch all** applies every automatic fix in one go (46 → 74 on the messy sample). **Undo** reverts a patch.
* **Suppress** adds a `# pwn2patch: ignore[RULE]` comment to the finding's line.
* The report has three tabs (Findings, Categories, Weaknesses). Findings can be grouped by severity, rule or line
  and filtered by severity, category, CWE or *Fixable*. "on line N" in a message is a link.
* Hardcoded secrets are masked in the report, the patch previews and the JSON export (*Show* reveals one).

## Scan a repository

Switch to **Repository** in the header and paste a link: `https://github.com/owner/repo`, the `owner/repo` shorthand,
a `/tree/<branch>` link, or any public https Git host (GitLab, Bitbucket, ...).

* Only the `.py` files are downloaded: a shallow, blobless `git clone` with a sparse checkout of exactly the files
  that will be scanned. Without git, github.com links fall back to GitHub's zip archive.
* Every Python file is analyzed (up to 1,500 per repository; dependency and build folders such as `venv/`,
  `node_modules/`, `build/` and `site-packages/` are skipped). Pallets' Flask (83 files) takes about a second;
  Django (1,500 of its 2,942 files) about 8 seconds.
* The **file tree** shows each file's grade, finding count and worst severity, rolled up into folders.
  Filter by name, show only files with issues, or sort worst-first. Arrow keys move through the tree.
* The **repository overview** shows the repo score (the average file score, weighted by lines of code), how many
  files pass the gate, severity totals, the files to look at first and the most common issues. Click a rule or a
  severity to list the files that have it. *Export JSON* downloads the whole scan.
* **Click a file** to open it in the editor with the full report: patches, *Patch all*, Workers AI drafts and
  suppressions all work. Repository files are **view-only**: edits and patches change the copy in your browser and are
  discarded when you open another file. *GitHub ↗* opens the same file at the scanned commit.
* The URL records what's open (`#repo=pallets/flask&file=src/flask/app.py`), so reloading, the back button and
  shared links return to the same file.

Safety: only `https://` links to public host names are accepted (no IP addresses, `localhost`, private suffixes or
credentials in the URL). git runs with hooks, submodules, LFS, symlinks, credential helpers and non-https protocols
turned off, under a time limit; zip archives are extracted with path, symlink and size checks. Nothing from the
repository is ever executed or imported. The page is served with a Content-Security-Policy that allows only its own
scripts. Scans are kept in a temporary folder (the last 5) and deleted when the server stops.

## Patching

`checker/fixes.py` turns findings into line edits: parameterized SQL, argument-list subprocess calls,
secrets read from `os.environ`, `with open(...)`, `is None`, renames that update every use in the file, and so on
(17 of 26 rules). Every fix is checked before it is offered: the patched code must still parse.

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

## Frontend contract

The UI reads a few optional fields that the backend is adding. Until they arrive it falls back to today's behavior,
so they can land in any order:

| Field | Meaning | UI without it |
|---|---|---|
| `finding.patch` | `{title, note, edits}`: the automatic patch (`finding.fix` is the rule's advice text) | required today |
| `finding.patch.safety` | `"safe"` or `"behavior_change"` | every patch looks safe; button says *Patch all* |
| `finding.points.gain_if_fixed` | overall points recovered by fixing just this finding | shows the raw penalty |
| `finding.evidence` | which signal found a secret: `name`, `value`, `usage` or `entropy` | no tag |
| `report.suppressed` | findings hidden by an ignore comment (same shape as `findings`) | *Suppress* adds the comment and says the analyzer doesn't read it yet |
| `report.patches_truncated` | `true` when only some findings got a patch prepared | no notice |
| `POST /api/fix` `include_behavior_changes` | request flag; `false` = only safe patches | ignored |
| `/api/fix` response `complete`, `applied[].safety` | `complete: false` when the run stopped at its limit | no notice / no grouping |

Suppression comments look like `# pwn2patch: ignore[SEC004]` or `# pwn2patch: ignore[SEC004, STY003]` at the end of
the finding's line; a bare `# pwn2patch: ignore` covers every rule on that line.

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
| `checker/secret_scan.py` | Secret detection by value: provider key formats, entropy, constant folding |
| `checker/scoring.py` | Category scores → weighted overall score → grade → PASS/FAIL gate |
| `checker/policy.json` | The "compliance policy": weights, penalties, limits, gate, disabled rules |
| `checker/engine.py` | `analyze(source) -> dict`: the one function everything else calls |
| `checker/ai_fix.py` | Workers AI patches for findings with no mechanical fix, verified by the analyzer |
| `checker/fixes.py` | Automatic patches: line edits per finding, verified to parse; `fix_all` for *Patch all* |
| `repos.py` | Repository scans: link validation, sparse `git clone` / GitHub zip fetch, per-file summaries, background jobs |
| `server.py` | Standard-library HTTP server: `POST /api/analyze`, `POST /api/fix`, `POST /api/ai-fix`, `POST /api/repo`, `GET /api/repo/<id>`, `GET /api/repo/<id>/file`, `GET /api/policy`, `GET /api/samples`, `/static/*` |
| `cli.py` | Terminal output + exit codes for CI |
| `static/index.html`, `static/styles.css` | The page's markup and styles |
| `static/js/*.js` | The UI as native ES modules (no build step): `editor` (highlighting, underlines, hover card, status bar), `analysis`, `report` (tabs, findings, filters), `patches` (diffs, Patch all, AI drafts, suppressions, undo), `repo` (tree, overview, URL routing), `keys`, `policy`, `state`, `util`, `main` |

### Scoring

* Each category (security, reliability, maintainability, style) starts at 100.
* Each finding subtracts a penalty for its severity (critical 30, high 15, medium 7, low 3, info 1).
  A single rule counts at most 3 times, so one noisy rule can't zero a category.
* Overall = weighted average (security 40%, reliability 25%, maintainability 20%, style 15%).
* **Gate FAILS** if overall < 70 **or** any critical/high finding exists.

It's deterministic: the same code always gets the same score.

### Rules (26)

| Category | Rules |
|---|---|
| Security | eval/exec, shell injection, SQL injection (incl. via variables), hardcoded secrets (by name, value and usage), possible secrets (random-looking strings), pickle/yaml deserialization, `verify=False`, MD5/SHA-1, Flask debug mode |
| Reliability | bare `except`, swallowed exceptions, mutable defaults, `open()` without `with`, `== None` |
| Maintainability | long functions, cyclomatic complexity, too many params, deep nesting, wildcard imports, `global` |
| Style | docstrings, naming, line length, `print` vs logging, TODO/FIXME, type hints |

### Hardcoded secrets

Renaming `API_KEY` to `x` doesn't make the key any less secret, so a variable's name is only one of three signals:

| Signal | Example it catches | Rule |
|---|---|---|
| **Name**: the variable, argument or dict key sounds secret | `DB_PASSWORD = "..."`, `connect(password="...")` | SEC004 (high) |
| **Value**: the string matches a provider's key format, whatever it's called | `settings_value = "ghp_..."`, `"AKIA..."`, `"sk-..."`, `"postgres://admin:pw@db"`, even split as `"ghp_" + "..."` | SEC004 (high) |
| **Usage**: a hardcoded value flows into a place that takes a credential | `x = "..."` later used in `headers={"X-API-Key": x}`, `f"Bearer {x}"`, `password=x`, `auth=(user, x)`, `smtp.login(user, x)`, `openai.api_key = x`, `jwt.encode(data, x)` | SEC004 (high) |
| **Value**: a long, random-looking string with no other evidence | `x = "k3yZq8vR2kLm9XyT4wPb..."` | SEC009 (medium) |

SEC009 is medium (it costs points but doesn't fail the gate on its own), because hashes and IDs look random too.
The entropy check was tuned against real-shaped keys and look-alikes: 32+ character random keys are caught about
90-100% of the time, while paths, URLs, UUIDs, model names (`all-MiniLM-L6-v2`), CamelCase names and hex digests
assigned to hash-named variables (`expected_sha256 = "e3b0..."`) are not flagged.

**Limit:** a short, human-chosen password that is renamed *and never used* (`x = "SuperSecret123!"`) looks like
any other string, and no static scanner can tell. As soon as it's used as a credential, it's caught.

### CWE mapping

Every finding carries a list of [CWE](https://cwe.mitre.org) entries, most specific first, and the report includes
a `cwe_summary` (one row per weakness, with counts) and `cwe_coverage` (how many findings have a CWE).

* **20 of 26 rules map to a CWE.** All titles were checked against MITRE (CWE 5.0).
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
| STY005 TODO/FIXME | CWE-546 | SEC009 possible secret | CWE-798 |

## Adding a rule

1. Add a `Rule(...)` to `checker/rules.py` (id, title, category, severity, why, fix, ref, `cwe=(...)`).
   If it needs a CWE that isn't in `checker/cwe.py` yet, add it there with the exact title from cwe.mitre.org.
2. Detect it in `checker/analyzer.py`, usually in a `visit_*` method, and call `self.report("ID", node, "message")`.
3. Add a test in `tests/test_checker.py`.

## Ideas for the rest of the night

* **AI explanations**: send the findings (not just the raw code) to an LLM to write a personalized fix or patch. The score stays deterministic.
* **More languages**: run `eslint` / `semgrep` through `subprocess` and map their output into the same `Finding` format.
* **Benchmarks**: the repository scanner makes this easy: show "your complexity is worse than 80% of Flask's functions".
* **Repo patches**: keep edits per file while browsing a repository and download them as one `git apply`-ready patch.
* **GitHub Action**: `python cli.py .` already exits 1 on FAIL, so it can block PRs today.
