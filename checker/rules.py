"""Rule catalog: every check the engine can report, with the "why" and the "fix".

Each rule is metadata only. The detection logic lives in analyzer.py and refers
to rules by id. Keeping them separate means the UI, the CLI and the policy file
can all list and explain rules without importing the analyzer.

`cwe` lists the CWE entries a rule maps to (most specific first; see cwe.py).
A few rules have no CWE because no entry describes them accurately; we leave
those empty rather than force a misleading mapping.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

CATEGORIES = ("security", "reliability", "maintainability", "style")
SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    category: str
    severity: str
    why: str
    fix: str
    ref: str = ""                  # non-CWE reference: a PEP or a URL
    cwe: tuple[str, ...] = ()      # CWE ids, most specific first

    def to_dict(self) -> dict:
        return asdict(self)


_RULES = [
    # ---------------------------------------------------------------- security
    Rule(
        "SEC001", "Use of eval() / exec()", "security", "critical",
        "eval/exec run arbitrary strings as code. If any part of the string comes "
        "from a user, they can run anything on your server.",
        "Parse the data instead: ast.literal_eval for literals, json.loads for JSON, "
        "or a dict of allowed operations.",
        cwe=("CWE-95",),
    ),
    Rule(
        "SEC002", "Shell command injection risk", "security", "critical",
        "os.system / shell=True hand the whole string to a shell, so characters like "
        "; | && in user input start new commands.",
        "Call subprocess.run([...]) with a list of arguments and shell=False.",
        cwe=("CWE-78",),
    ),
    Rule(
        "SEC003", "SQL built with string formatting", "security", "critical",
        "Building SQL with f-strings, + or % lets input change the query itself "
        "(e.g. ' OR 1=1 --).",
        "Use parameterized queries: cursor.execute(\"... WHERE id = ?\", (user_id,)).",
        cwe=("CWE-89",),
    ),
    Rule(
        "SEC004", "Hardcoded secret", "security", "high",
        "Secrets in source code end up in git history, logs and screenshots, and "
        "can't be rotated without a deploy.",
        "Load it at runtime, e.g. os.environ[\"DB_PASSWORD\"], or use a secrets manager.",
        cwe=("CWE-798",),
    ),
    Rule(
        "SEC005", "Unsafe deserialization", "security", "high",
        "pickle / marshal / yaml.load can construct arbitrary objects and run code "
        "while loading untrusted data.",
        "Use json, or yaml.safe_load. Never unpickle data you didn't create.",
        cwe=("CWE-502",),
    ),
    Rule(
        "SEC006", "TLS certificate verification disabled", "security", "high",
        "verify=False accepts any certificate, so anyone on the network can "
        "intercept or modify the traffic.",
        "Remove verify=False. For internal CAs pass verify=\"/path/to/ca.pem\".",
        cwe=("CWE-295",),
    ),
    Rule(
        "SEC007", "Weak hash algorithm", "security", "medium",
        "MD5 and SHA-1 have practical collision attacks and are far too fast for "
        "hashing passwords.",
        "Use hashlib.sha256 for integrity; bcrypt/argon2/hashlib.scrypt for passwords.",
        cwe=("CWE-328",),
    ),
    Rule(
        "SEC008", "Debug mode enabled", "security", "high",
        "Flask/Werkzeug debug mode exposes an interactive console that can run code "
        "on the server.",
        "Drive debug from config: app.run(debug=os.environ.get(\"FLASK_DEBUG\") == \"1\").",
        cwe=("CWE-489",),
    ),
    Rule(
        "SEC009", "Possible hardcoded secret", "security", "medium",
        "This string is long and random-looking, which is what API keys and tokens look like. "
        "Renaming the variable doesn't make a key any less secret. It's medium, not high, because "
        "hashes and IDs can look random too.",
        "If it's a credential, load it from the environment or a secrets manager and rotate it. "
        "If it's a hash, give it a name that says so (e.g. `expected_sha256`).",
        cwe=("CWE-798",),
    ),
    # ------------------------------------------------------------- reliability
    Rule(
        "REL001", "Bare except", "reliability", "medium",
        "`except:` also catches KeyboardInterrupt and SystemExit and hides real bugs.",
        "Catch the specific exceptions you expect, e.g. `except ValueError:`.",
        cwe=("CWE-396",),
    ),
    Rule(
        "REL002", "Mutable default argument", "reliability", "medium",
        "Default values are created once, so a list/dict default is shared between "
        "every call and leaks state.",
        "Default to None and create the object inside: `items = items or []`.",
        "https://docs.python-guide.org/writing/gotchas/",
    ),
    Rule(
        "REL003", "Exception silently swallowed", "reliability", "medium",
        "`except ...: pass` throws the error away, so failures go unnoticed.",
        "Log it (logger.exception(...)), handle it, or let it propagate.",
        cwe=("CWE-1069", "CWE-390"),
    ),
    Rule(
        "REL004", "File opened without a context manager", "reliability", "low",
        "If an exception happens before close(), the file handle leaks.",
        "Use `with open(path) as f:` so the file always closes.",
        cwe=("CWE-775",),
    ),
    Rule(
        "REL005", "Comparison to None with == / !=", "reliability", "low",
        "== can be overridden by classes; identity is what you actually mean.",
        "Use `is None` / `is not None`.",
        "PEP 8",
    ),
    # --------------------------------------------------------- maintainability
    Rule(
        "MNT001", "Function too long", "maintainability", "medium",
        "Long functions do too many things and are hard to test and review.",
        "Split it into smaller functions that each do one job.",
    ),
    Rule(
        "MNT002", "High cyclomatic complexity", "maintainability", "medium",
        "Many branches means many paths to test and more places for bugs to hide.",
        "Use early returns, extract helpers, or replace if/elif chains with a dict.",
        cwe=("CWE-1121",),
    ),
    Rule(
        "MNT003", "Too many parameters", "maintainability", "low",
        "Long parameter lists are easy to call in the wrong order.",
        "Group related parameters into a dataclass or use keyword-only arguments.",
        cwe=("CWE-1064",),
    ),
    Rule(
        "MNT004", "Deeply nested code", "maintainability", "medium",
        "Every nesting level is more state the reader has to hold in their head.",
        "Invert conditions and return early, or extract the inner block into a function.",
        cwe=("CWE-1124",),
    ),
    Rule(
        "MNT005", "Wildcard import", "maintainability", "low",
        "`from x import *` hides where names come from and can silently shadow others.",
        "Import the names you use explicitly.",
        "PEP 8",
    ),
    Rule(
        "MNT006", "Global state modified", "maintainability", "low",
        "`global` makes functions depend on hidden shared state.",
        "Pass values in and return results, or wrap the state in a class.",
        cwe=("CWE-1108",),
    ),
    # ------------------------------------------------------------------ style
    Rule(
        "STY001", "Missing docstring", "style", "low",
        "Public functions and classes are the API other people read first.",
        "Add a one-line docstring saying what it does and returns.",
        "PEP 257",
        cwe=("CWE-1111",),
    ),
    Rule(
        "STY002", "Naming convention", "style", "low",
        "Consistent names make code predictable to read.",
        "Functions and variables: snake_case. Classes: PascalCase.",
        "PEP 8",
        cwe=("CWE-1099",),
    ),
    Rule(
        "STY003", "Line too long", "style", "info",
        "Long lines are hard to read and review side by side.",
        "Wrap the expression or extract a variable.",
        "PEP 8",
        cwe=("CWE-1078",),
    ),
    Rule(
        "STY004", "print() instead of logging", "style", "info",
        "print can't be filtered by level or routed to log storage in production.",
        "Use the logging module: logger = logging.getLogger(__name__).",
    ),
    Rule(
        "STY005", "Leftover TODO / FIXME", "style", "info",
        "Unfinished work markers tend to be forgotten.",
        "Finish it, or move it to an issue tracker and link the issue.",
        cwe=("CWE-546",),
    ),
    Rule(
        "STY006", "Missing type hints", "style", "info",
        "Type hints document intent and let tools catch bugs before runtime.",
        "Annotate the parameters and the return type.",
        "PEP 484",
    ),
]

RULES: dict[str, Rule] = {rule.id: rule for rule in _RULES}
