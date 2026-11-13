"""Automatic patches: the "patch" half of Pwn2Patch.

For findings that have a safe, mechanical fix, `suggest_fix` returns a list of
line edits plus a note explaining what changed and what still needs a human.
Rules where any automatic change would be guesswork (long functions, complexity,
`exec`, a route that runs a user-supplied command...) get no fix on purpose.

Every fix is verified before it is offered: the edits are applied and the result
must still parse. Like the analyzer, nothing here ever executes the code.

Edits use 1-based line numbers and replace lines `start..end` (inclusive) with
`lines`. An insertion is written as `end == start - 1`.
"""
from __future__ import annotations

import ast
import builtins
import difflib
import io
import keyword
import re
import tokenize
from dataclasses import dataclass, field

from .analyzer import OPEN_FUNCS, PASCAL_CASE, SNAKE_CASE, Finding, PythonAnalyzer, dotted_name, snake
from .rules import RULES, SEVERITIES

SQL_PLACEHOLDER = "?"
FIX_ITERATION_LIMIT = 200


@dataclass
class Edit:
    start: int
    end: int
    lines: list[str]

    def to_dict(self) -> dict:
        return {"start": self.start, "end": self.end, "lines": self.lines}


@dataclass
class Fix:
    title: str
    note: str = ""
    edits: list[Edit] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"title": self.title, "note": self.note, "edits": [e.to_dict() for e in self.edits]}


def apply_edits(source: str, edits: list[Edit]) -> str:
    """Apply non-overlapping edits, bottom-up so earlier line numbers stay valid."""
    lines = source.split("\n")
    for edit in sorted(edits, key=lambda e: (e.start, e.end), reverse=True):
        lines[edit.start - 1:edit.end] = edit.lines
    return "\n".join(lines)


def _overlaps(edits: list[Edit]) -> bool:
    spans = sorted((e.start, e.end) for e in edits if e.end >= e.start)
    return any(b_start <= a_end for (_, a_end), (b_start, _) in zip(spans, spans[1:]))


# ------------------------------------------------------------------ context
class FixContext:
    def __init__(self, source: str, tree: ast.Module):
        self.source = source
        self.tree = tree
        self.lines = source.split("\n")
        self.parents: dict[ast.AST, ast.AST] = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                self.parents[child] = node

    def line(self, number: int) -> str:
        return self.lines[number - 1] if 0 < number <= len(self.lines) else ""

    def indent(self, number: int) -> str:
        text = self.line(number)
        return text[:len(text) - len(text.lstrip())]

    def at(self, finding: Finding, *types: type) -> ast.AST | None:
        """The AST node the analyzer reported (same line and byte column)."""
        for node in ast.walk(self.tree):
            if isinstance(node, types) and getattr(node, "lineno", None) == finding.line \
                    and node.col_offset == finding.col - 1:
                return node
        return None

    def char_col(self, number: int, byte_col: int) -> int:
        """AST columns are UTF-8 byte offsets; convert to a str index."""
        return len(self.line(number).encode("utf-8")[:byte_col].decode("utf-8", errors="ignore"))

    def segment(self, node: ast.AST) -> str:
        return ast.get_source_segment(self.source, node) or ast.unparse(node)

    def replace(self, node: ast.AST, text: str) -> Edit:
        """Replace the exact source span of `node` with `text`."""
        first, last = node.lineno, node.end_lineno
        prefix = self.line(first)[:self.char_col(first, node.col_offset)]
        suffix = self.line(last)[self.char_col(last, node.end_col_offset):]
        return Edit(first, last, (prefix + text + suffix).split("\n"))

    def ensure_import(self, module: str) -> list[Edit]:
        """An edit adding `import module` after the existing imports, or [] if it's there."""
        last_line, body = 0, self.tree.body
        for stmt in body:
            if isinstance(stmt, ast.Import) and any(a.name == module and not a.asname for a in stmt.names):
                return []
        for i, stmt in enumerate(body):
            if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                last_line = stmt.end_lineno
            elif i == 0 and isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) \
                    and isinstance(stmt.value.value, str):
                last_line = stmt.end_lineno  # module docstring
            else:
                break
        return [Edit(last_line + 1, last_line, [f"import {module}"])]


def _str_literal(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def _string_parts(node: ast.AST) -> list[str | ast.AST] | None:
    """Split `"a" + x + "b"` or f"a{x}b" into ["a", x, "b"]; None for anything else."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.JoinedStr):
        parts: list[str | ast.AST] = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue) and value.conversion == -1 and value.format_spec is None:
                parts.append(value.value)
            else:
                return None
        return parts
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _string_parts(node.left), _string_parts(node.right)
        if left is None:
            return None
        if right is None:
            if isinstance(node.right, (ast.Name, ast.Attribute, ast.Subscript, ast.Call)):
                right = [node.right]
            else:
                return None
        return left + right
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
        return [node]
    return None


def _call_text(call: ast.Call, func: str | None = None, args: list[ast.AST] | None = None,
               drop: set[str] = frozenset()) -> str:
    new = ast.Call(
        func=ast.parse(func, mode="eval").body if func else call.func,
        args=call.args if args is None else args,
        keywords=[kw for kw in call.keywords if kw.arg not in drop],
    )
    return ast.unparse(new)


# ------------------------------------------------------------------ fixers
def _fix_eval(ctx: FixContext, f: Finding) -> Fix | None:
    call = ctx.at(f, ast.Call)
    if not call or dotted_name(call.func) != "eval":
        return None
    return Fix("Replace eval() with ast.literal_eval()",
               "literal_eval only accepts Python literals (numbers, strings, lists, dicts...). "
               "If you really need arithmetic, write a small parser or use a dict of allowed operations.",
               [ctx.replace(call.func, "ast.literal_eval"), *ctx.ensure_import("ast")])


def _command_list(node: ast.AST) -> list[ast.AST] | None:
    """`"ping -c 1 " + host` -> ['ping', '-c', '1', host], when every variable is a whole argument."""
    parts = _string_parts(node)
    if not parts or not any(not isinstance(p, str) for p in parts):
        return None
    items: list[ast.AST] = []
    for i, part in enumerate(parts):
        if isinstance(part, str):
            items += [ast.Constant(word) for word in part.split()]
        else:
            before = parts[i - 1] if i > 0 else " "
            after = parts[i + 1] if i + 1 < len(parts) else " "
            if not isinstance(before, str) or not isinstance(after, str) \
                    or (before and not before[-1].isspace()) or (after and not after[0].isspace()):
                return None
            items.append(part)
    # The program itself must be fixed text; if the user picks it, a list doesn't make that safe.
    return items if items and isinstance(items[0], ast.Constant) else None


def _fix_shell(ctx: FixContext, f: Finding) -> Fix | None:
    call = ctx.at(f, ast.Call)
    if not call or not call.args:
        return None
    name = dotted_name(call.func)
    argv = _command_list(call.args[0])
    if argv is None and isinstance(call.args[0], (ast.List, ast.Tuple)) and call.args[0].elts \
            and isinstance(call.args[0].elts[0], ast.Constant):
        argv = list(call.args[0].elts)
    if argv is None:
        return None
    arg_list = ast.List(argv)
    if name == "os.system":
        text = f"subprocess.run({ast.unparse(arg_list)}).returncode"
        edits = [ctx.replace(call, text), *ctx.ensure_import("subprocess")]
    elif name.startswith("subprocess."):
        edits = [ctx.replace(call, _call_text(call, args=[arg_list, *call.args[1:]], drop={"shell"}))]
    else:
        return None
    return Fix("Pass the command as a list, without a shell",
               "Each list item is one argument, so shell characters like ; | && in the input "
               "are passed as plain text instead of starting new commands. "
               "Still validate the input (a host name could also be `-f` or similar).", edits)


def _sql_query(parts: list[str | ast.AST]) -> tuple[str, list[ast.AST]] | None:
    text, params = "", []
    for i, part in enumerate(parts):
        if isinstance(part, str):
            text += part
            continue
        nxt = parts[i + 1] if i + 1 < len(parts) else ""
        if not isinstance(nxt, str):
            return None
        if text.endswith(("'", '"')) and nxt.startswith(text[-1]):
            text = text[:-1]
            parts[i + 1] = nxt[1:]
        text += SQL_PLACEHOLDER
        params.append(part)
    return (text, params) if params else None


def _params_text(params: list[ast.AST]) -> str:
    return ast.unparse(ast.Tuple(params)) if len(params) > 1 else f"({ast.unparse(params[0])},)"


SQL_NOTE = ("The value is now sent separately from the query, so the database never treats it as SQL. "
            "`?` is the sqlite3 placeholder; psycopg and MySQL drivers use `%s`.")


def _fix_sql(ctx: FixContext, f: Finding) -> Fix | None:
    call = ctx.at(f, ast.Call)
    if not call or len(call.args) != 1:
        return None
    query = call.args[0]
    if not isinstance(query, ast.Name):
        built = _sql_query(_string_parts(query) or [])
        if not built:
            return None
        text, params = built
        return Fix("Use a parameterized query", SQL_NOTE,
                   [ctx.replace(query, _str_literal(text) + ", " + _params_text(params))])

    # Query built in a variable first: rewrite the assignment and the call together.
    scope = _enclosing_scope(ctx, call)
    assign = None
    for node in ast.walk(scope):
        if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name) and node.target.id == query.id:
            return None
        if isinstance(node, ast.Assign) and node.lineno < call.lineno and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id == query.id:
            if assign is None or node.lineno > assign.lineno:
                assign = node
    if assign is None or assign.end_lineno >= call.lineno:
        return None
    built = _sql_query(_string_parts(assign.value) or [])
    if not built:
        return None
    text, params = built
    return Fix("Use a parameterized query", SQL_NOTE, [
        ctx.replace(assign.value, _str_literal(text)),
        ctx.replace(query, f"{query.id}, {_params_text(params)}"),
    ])


def _enclosing_scope(ctx: FixContext, node: ast.AST) -> ast.AST:
    while node in ctx.parents:
        node = ctx.parents[node]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node
    return ctx.tree


SECRET_NOTE = ("Set `{env}` in the environment (or a .env file that is not committed). "
               "The old value is still in your git history, so rotate it.")


def _fix_secret(ctx: FixContext, f: Finding) -> Fix | None:
    target = ctx.at(f, ast.Name, ast.Attribute)
    value, name = None, None
    if target is not None and isinstance(ctx.parents.get(target), (ast.Assign, ast.AnnAssign)):
        value = ctx.parents[target].value
        name = target.id if isinstance(target, ast.Name) else target.attr
    else:
        const = ctx.at(f, ast.Constant)
        parent = ctx.parents.get(const)
        if isinstance(parent, ast.keyword):
            value, name = const, parent.arg
        elif isinstance(parent, ast.Dict):
            key = parent.keys[parent.values.index(const)]
            value, name = const, key.value
    if value is None or not name:
        return None  # e.g. a parameter default: the fix is an API change, not a mechanical edit
    env = re.sub(r"[^A-Za-z0-9]+", "_", snake(name)).strip("_").upper()  # "X-API-Key" -> X_API_KEY
    return Fix("Read the secret from the environment", SECRET_NOTE.format(env=env),
               [ctx.replace(value, f'os.environ["{env}"]'), *ctx.ensure_import("os")])


def _fix_deserialize(ctx: FixContext, f: Finding) -> Fix | None:
    call = ctx.at(f, ast.Call)
    if not call or not call.args:
        return None
    name = dotted_name(call.func)
    if name in ("yaml.load", "yaml.load_all"):
        safe = "yaml.safe_load" if name == "yaml.load" else "yaml.safe_load_all"
        return Fix(f"Use {safe}()", "safe_load only builds plain types (dicts, lists, strings, numbers).",
                   [ctx.replace(call, _call_text(call, func=safe, args=call.args[:1], drop={"Loader"}))])
    if name in ("pickle.loads", "pickle.load", "marshal.loads", "marshal.load"):
        json_func = "json.loads" if name.endswith("loads") else "json.load"
        return Fix("Load the data as JSON instead",
                   "JSON can only describe data, never code. The code that *writes* this data "
                   "has to switch to json.dumps too.",
                   [ctx.replace(call.func, json_func), *ctx.ensure_import("json")])
    return None


def _fix_verify(ctx: FixContext, f: Finding) -> Fix | None:
    call = ctx.at(f, ast.Call)
    if not call:
        return None
    if dotted_name(call.func) == "ssl._create_unverified_context":
        return Fix("Use a verifying SSL context", "",
                   [ctx.replace(call.func, "ssl.create_default_context")])
    for kw in call.keywords:
        if kw.arg == "verify":
            return Fix("Turn certificate verification back on",
                       "`verify=True` is the default, so you can also just delete the argument. "
                       "For a self-signed server, pass `verify=\"/path/to/ca.pem\"` instead.",
                       [ctx.replace(kw.value, "True")])
    return None


def _fix_weak_hash(ctx: FixContext, f: Finding) -> Fix | None:
    if f.cwe:  # used on a password: SHA-256 would be just as wrong, it needs bcrypt/argon2 + a salt
        return None
    call = ctx.at(f, ast.Call)
    if not call:
        return None
    name = dotted_name(call.func)
    if name in ("hashlib.md5", "hashlib.sha1"):
        edit = ctx.replace(call.func, "hashlib.sha256")
    elif name == "hashlib.new" and call.args:
        edit = ctx.replace(call.args[0], '"sha256"')
    else:
        return None
    return Fix("Switch to SHA-256", "Stored hashes made with the old algorithm will no longer match.", [edit])


def _fix_debug(ctx: FixContext, f: Finding) -> Fix | None:
    call = ctx.at(f, ast.Call)
    if call:
        for kw in call.keywords:
            if kw.arg == "debug":
                return Fix("Turn debug mode off", "Enable it locally with an environment variable, never in code.",
                           [ctx.replace(kw.value, "False")])
    target = ctx.at(f, ast.Attribute)
    if target and isinstance(ctx.parents.get(target), ast.Assign):
        return Fix("Turn debug mode off", "", [ctx.replace(ctx.parents[target].value, "False")])
    return None


def _fix_bare_except(ctx: FixContext, f: Finding) -> Fix | None:
    text = ctx.line(f.line)
    new = re.sub(r"^(\s*)except\s*:", r"\1except Exception:", text, count=1)
    if new == text:
        return None
    return Fix("Catch Exception instead of everything",
               "Ctrl+C and sys.exit() now work again. Catch something narrower if you can.",
               [Edit(f.line, f.line, [new])])


def _fix_swallowed(ctx: FixContext, f: Finding) -> Fix | None:
    handler = ctx.at(f, ast.ExceptHandler)
    if not handler or len(handler.body) != 1:
        return None
    return Fix("Log the exception instead of hiding it",
               "logging.exception records the full traceback, so the failure is visible.",
               [ctx.replace(handler.body[0], 'logging.exception("Unexpected error")'),
                *ctx.ensure_import("logging")])


def _function_body_start(func: ast.AST) -> tuple[int, ast.stmt] | None:
    """Line to insert at the top of a function's body (after its docstring)."""
    body = func.body
    if body[0].lineno == func.lineno:
        return None  # one-line function
    if ast.get_docstring(func) is not None:
        return body[0].end_lineno + 1, body[0]
    return body[0].lineno, body[0]


def _fix_mutable_default(ctx: FixContext, f: Finding) -> Fix | None:
    default = ctx.at(f, ast.List, ast.Dict, ast.Set, ast.Call)
    args = ctx.parents.get(default)
    func = ctx.parents.get(args)
    if not isinstance(args, ast.arguments) or not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    positional = args.posonlyargs + args.args
    pairs = list(zip(positional[len(positional) - len(args.defaults):], args.defaults))
    pairs += list(zip(args.kwonlyargs, args.kw_defaults))
    param = next((p for p, d in pairs if d is default), None)
    start = _function_body_start(func)
    if param is None or start is None:
        return None
    line, first_stmt = start
    indent = ctx.indent(first_stmt.lineno)
    return Fix("Default to None and create the value inside the function",
               "A default value is created once and shared by every call, so it kept growing between calls.", [
                   ctx.replace(default, "None"),
                   Edit(line, line - 1, [f"{indent}if {param.arg} is None:",
                                         f"{indent}    {param.arg} = {ctx.segment(default)}"]),
               ])


def _fix_open(ctx: FixContext, f: Finding) -> Fix | None:
    call = ctx.at(f, ast.Call)
    assign = ctx.parents.get(call)
    if not isinstance(assign, ast.Assign) or len(assign.targets) != 1 or not isinstance(assign.targets[0], ast.Name):
        return None
    var = assign.targets[0].id
    container = ctx.parents.get(assign)
    body = next((getattr(container, name) for name in ("body", "orelse", "finalbody")
                 if assign in getattr(container, name, [])), None)
    if body is None:
        return None
    index = body.index(assign)
    close = None
    for stmt in body[index + 1:]:
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call) \
                and dotted_name(stmt.value.func) == f"{var}.close" and not stmt.value.args:
            close = stmt
            break
    if close is None:
        return None
    middle = body[index + 1:body.index(close)]
    if not middle or any(isinstance(n, ast.Constant) and isinstance(n.value, str) and n.lineno != n.end_lineno
                         for stmt in middle for n in ast.walk(stmt)):
        return None  # indenting a multi-line string would change its value
    indent = ctx.indent(assign.lineno)
    inner = [("    " + text) if text.strip() else text
             for text in ctx.lines[assign.end_lineno:close.lineno - 1]]
    return Fix("Open the file in a `with` block",
               "The file is closed even if an exception is raised.",
               [Edit(assign.lineno, close.end_lineno, [f"{indent}with {ctx.segment(call)} as {var}:", *inner])])


def _fix_none_compare(ctx: FixContext, f: Finding) -> Fix | None:
    node = ctx.at(f, ast.Compare)
    if not node:
        return None
    text = ctx.segment(node)
    new = re.sub(r"\s*!=\s*None\b", " is not None", text)
    new = re.sub(r"\s*==\s*None\b", " is None", new)
    if new == text:
        return None
    return Fix("Compare to None with `is`", "", [ctx.replace(node, new)])


def _fix_print(ctx: FixContext, f: Finding) -> Fix | None:
    call = ctx.at(f, ast.Call)
    if not call or call.keywords or len(call.args) > 3 or any(isinstance(a, ast.Starred) for a in call.args):
        return None
    if len(call.args) <= 1:
        text = _call_text(call, func="logging.info", args=call.args or [ast.Constant("")])
    else:
        fmt = ast.Constant(" ".join(["%s"] * len(call.args)))
        text = _call_text(call, func="logging.info", args=[fmt, *call.args])
    return Fix("Use logging instead of print()",
               "Call logging.basicConfig(level=logging.INFO) once at startup to see these messages.",
               [ctx.replace(call, text), *ctx.ensure_import("logging")])


def _fix_star_import(ctx: FixContext, f: Finding) -> Fix | None:
    node = ctx.at(f, ast.ImportFrom)
    stars = [n for n in ast.walk(ctx.tree) if isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names)]
    if not node or len(stars) != 1 or not node.module:
        return None  # with two star imports we can't tell which one a name came from
    bound, used = set(dir(builtins)), []
    for n in ast.walk(ctx.tree):
        if isinstance(n, ast.Name):
            if isinstance(n.ctx, ast.Load):
                used.append(n.id)
            else:
                bound.add(n.id)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(n.name)
        elif isinstance(n, ast.arg):
            bound.add(n.arg)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            bound.update((a.asname or a.name).split(".")[0] for a in n.names if a.name != "*")
        elif isinstance(n, ast.ExceptHandler) and n.name:
            bound.add(n.name)
    names = sorted({u for u in used if u not in bound}, key=str.lower)
    if not names:
        return None
    return Fix("Import only the names that are used",
               "These are the names this file uses that aren't defined anywhere else in it.",
               [ctx.replace(node, f"from {'.' * node.level}{node.module} import {', '.join(names)}")])


def _rename_target(name: str, is_class: bool) -> str | None:
    lead = name[:len(name) - len(name.lstrip("_"))]
    words = [w for w in snake(name.lstrip("_")).split("_") if w]
    new = lead + ("".join(w.capitalize() for w in words) if is_class else "_".join(words))
    ok = PASCAL_CASE.match(new) if is_class else SNAKE_CASE.match(new)
    return new if ok and new != name and not keyword.iskeyword(new) else None


def _fix_naming(ctx: FixContext, f: Finding) -> Fix | None:
    node = ctx.at(f, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    if not node:
        return None
    new = _rename_target(node.name, isinstance(node, ast.ClassDef))
    if not new:
        return None
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(ctx.source).readline))
    except (tokenize.TokenError, SyntaxError):
        return None
    if any(t.type == tokenize.NAME and t.string == new for t in tokens):
        return None  # the new name is already taken
    changed: dict[int, list[tuple[int, int]]] = {}
    for t in tokens:
        if t.type == tokenize.NAME and t.string == node.name:
            changed.setdefault(t.start[0], []).append((t.start[1], t.end[1]))
    edits = []
    for number, spans in changed.items():
        text = ctx.line(number)
        for start, end in sorted(spans, reverse=True):
            text = text[:start] + new + text[end:]
        edits.append(Edit(number, number, [text]))
    uses = sum(len(s) for s in changed.values())
    return Fix(f"Rename `{node.name}` to `{new}`",
               f"Renames all {uses} uses in this file. Code in other files that uses the old name needs updating too.",
               edits)


def _fix_docstring(ctx: FixContext, f: Finding) -> Fix | None:
    node = ctx.at(f, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    if not node or node.body[0].lineno == node.lineno:
        return None
    words = snake(node.name.strip("_")).replace("_", " ").strip()
    summary = (words[:1].upper() + words[1:] + ".") if words else "Describe this."
    indent = ctx.indent(node.body[0].lineno)
    return Fix("Add a docstring", "This is a placeholder generated from the name. Replace it with a real description.",
               [Edit(node.body[0].lineno, node.body[0].lineno - 1, [f'{indent}"""{summary}"""'])])


FIXERS = {
    "SEC001": _fix_eval, "SEC002": _fix_shell, "SEC003": _fix_sql, "SEC004": _fix_secret,
    "SEC005": _fix_deserialize, "SEC006": _fix_verify, "SEC007": _fix_weak_hash, "SEC008": _fix_debug,
    "REL001": _fix_bare_except, "REL002": _fix_mutable_default, "REL003": _fix_swallowed,
    "REL004": _fix_open, "REL005": _fix_none_compare,
    "MNT005": _fix_star_import,
    "STY001": _fix_docstring, "STY002": _fix_naming, "STY004": _fix_print,
}


def suggest_fix(ctx: FixContext, finding: Finding) -> Fix | None:
    """A verified fix for this finding, or None when there's no safe automatic one."""
    fixer = FIXERS.get(finding.rule_id)
    if fixer is None:
        return None
    try:
        fix = fixer(ctx, finding)
        if fix is None or not fix.edits or _overlaps(fix.edits):
            return None
        patched = apply_edits(ctx.source, fix.edits)
        if patched == ctx.source:
            return None
        ast.parse(patched)
    except (SyntaxError, ValueError, IndexError, AttributeError, TypeError, RecursionError):
        return None
    return fix


# ------------------------------------------------------------------ fix everything
def fix_all(source: str, limits: dict, disabled: set[str] | None = None) -> tuple[str, list[dict]]:
    """Apply every available fix, one at a time, re-analyzing after each.

    Re-analyzing between fixes means line numbers, imports and overlapping
    edits are always computed against the current code. A fix that doesn't
    make its finding go away is undone and not tried again.
    """
    rank = {sev: i for i, sev in enumerate(SEVERITIES)}

    applied: list[dict] = []
    blocked: set[tuple[str, str]] = set()
    pending: tuple[tuple[str, str], int, str] | None = None  # (key, count before, source before)

    for _ in range(FIX_ITERATION_LIMIT):
        try:
            findings = PythonAnalyzer(source, limits, disabled).run()
            tree = ast.parse(source)
        except (SyntaxError, ValueError, RecursionError):
            break
        ctx = FixContext(source, tree)
        keys = [(f.rule_id, ctx.line(f.line).strip()) for f in findings]

        if pending:
            key, before, previous = pending
            pending = None
            if keys.count(key) >= before:  # didn't help: undo it
                blocked.add(key)
                applied.pop()
                source = previous
                continue

        order = sorted(zip(findings, keys), key=lambda p: (rank[RULES[p[0].rule_id].severity], p[0].line))
        for finding, key in order:
            if key in blocked:
                continue
            fix = suggest_fix(ctx, finding)
            if fix is None:
                blocked.add(key)
                continue
            pending = (key, keys.count(key), source)
            source = apply_edits(source, fix.edits)
            applied.append({"rule_id": finding.rule_id, "title": fix.title, "line": finding.line})
            break
        else:
            break
    return source, applied


def unified_diff(before: str, after: str) -> str:
    def lines(text: str) -> list[str]:
        return [line + "\n" for line in text.split("\n")]
    return "".join(difflib.unified_diff(lines(before), lines(after), "before.py", "after.py", n=2))
