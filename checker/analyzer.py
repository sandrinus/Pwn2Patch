"""Static analyzer for Python source.

It parses the code into an abstract syntax tree (AST) and walks it looking for
patterns from the rule catalog. The code being checked is NEVER executed,
imported or compiled to bytecode, so it is safe to point this at untrusted input.
"""
from __future__ import annotations

import ast
import io
import re
import tokenize
from dataclasses import dataclass

# Matched against snake_case names, as whole underscore-separated words, so that
# `db_password` and `apiKey` match but `tokenizer` and `max_tokens` don't.
SECRET_NAME = re.compile(
    r"(?:^|_)(passw(?:or)?d|pwd|secret|api_?key|access_?key|private_?key|auth_?token|"
    r"access_?token|token|credentials?)(?:_|$)"
)
CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
NOT_A_SECRET = {"bearer", "basic", "token", "password", "secret", "api_key", "apikey"}
SNAKE_CASE = re.compile(r"^_{0,2}[a-z][a-z0-9_]*$")
PASCAL_CASE = re.compile(r"^_{0,2}[A-Z][A-Za-z0-9]*$")
TODO_MARKER = re.compile(r"\b(TODO|FIXME|HACK|XXX)\b")

SQL_EXECUTORS = (".execute", ".executemany", ".executescript", ".raw")
SHELL_STRING_FUNCS = {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"}
DESERIALIZERS = {"pickle.load", "pickle.loads", "marshal.load", "marshal.loads", "shelve.open"}
WEAK_HASHES = {"hashlib.md5", "hashlib.sha1"}
MUTABLE_FACTORIES = {"list", "dict", "set", "defaultdict", "OrderedDict"}
OPEN_FUNCS = {"open", "io.open", "codecs.open"}

_BRANCH_NODES: tuple[type, ...] = (
    ast.If, ast.For, ast.AsyncFor, ast.While, ast.IfExp, ast.ExceptHandler, ast.comprehension,
)
if hasattr(ast, "match_case"):  # Python 3.10+
    _BRANCH_NODES += (ast.match_case,)


@dataclass
class Finding:
    rule_id: str
    line: int
    col: int
    message: str
    snippet: str = ""


# --------------------------------------------------------------------- helpers
def dotted_name(node: ast.AST) -> str:
    """Turn `a.b.c` / `foo().bar` into a readable dotted name."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        parts.append(dotted_name(node.func) + "()")
    else:
        parts.append("?")
    return ".".join(reversed(parts))


def is_dynamic_string(node: ast.AST) -> bool:
    """True for strings built at runtime: f-strings, "..." + x, "..." % x, "...".format(x)."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        has_str = any(isinstance(n, ast.Constant) and isinstance(n.value, str) for n in ast.walk(node))
        has_var = any(isinstance(n, (ast.Name, ast.Attribute, ast.Call, ast.Subscript)) for n in ast.walk(node))
        return has_str and has_var
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str)
    return False


def is_const(node: ast.AST | None, value: object) -> bool:
    return isinstance(node, ast.Constant) and node.value is value


def keyword_value(call: ast.Call, name: str) -> ast.AST | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def cyclomatic_complexity(func: ast.AST) -> int:
    """McCabe complexity: 1 + number of decision points (nested functions excluded)."""
    score = 1
    stack = list(ast.iter_child_nodes(func))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(node, _BRANCH_NODES):
            score += 1
        elif isinstance(node, ast.BoolOp):
            score += len(node.values) - 1
        stack.extend(ast.iter_child_nodes(node))
    return score


def is_main_guard(node: ast.If) -> bool:
    test = node.test
    return (
        isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name)
        and test.left.id == "__name__"
        and len(test.comparators) == 1
        and isinstance(test.comparators[0], ast.Constant)
        and test.comparators[0].value == "__main__"
    )


def looks_like_secret(name: str, value: ast.AST) -> bool:
    if not SECRET_NAME.search(CAMEL_BOUNDARY.sub("_", name).lower()):
        return False
    if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
        return False
    text = value.value
    return len(text) >= 6 and " " not in text and text.lower() not in NOT_A_SECRET


# -------------------------------------------------------------------- analyzer
class PythonAnalyzer(ast.NodeVisitor):
    def __init__(self, source: str, limits: dict, disabled: set[str] | None = None):
        self.source = source
        self.lines = source.splitlines()
        self.limits = limits
        self.disabled = disabled or set()
        self.findings: list[Finding] = []
        self._seen: set[tuple[str, int]] = set()

        self._depth = 0                       # nesting depth inside the current function
        self._func_stack: list[ast.AST] = []
        self._nesting_flagged: set[int] = set()
        self._with_opens: set[int] = set()    # open() calls that are safely inside `with`
        self._in_main_guard = False
        self._dynamic_str_vars: dict[str, int] = {}  # var name -> line it was built on

    # ------------------------------------------------------------- plumbing
    def run(self) -> list[Finding]:
        tree = ast.parse(self.source)
        self.visit(tree)
        self._check_text()
        self.findings.sort(key=lambda f: (f.line, f.col))
        return self.findings

    def report(self, rule_id: str, node_or_line, message: str) -> None:
        if rule_id in self.disabled:
            return
        if isinstance(node_or_line, int):
            line, col = node_or_line, 0
        else:
            line, col = getattr(node_or_line, "lineno", 1), getattr(node_or_line, "col_offset", 0)
        if (rule_id, line) in self._seen:
            return
        self._seen.add((rule_id, line))
        snippet = self.lines[line - 1].strip()[:140] if 0 < line <= len(self.lines) else ""
        self.findings.append(Finding(rule_id, line, col + 1, message, snippet))

    # ------------------------------------------------------------- nesting
    def _enter_block(self, node: ast.AST) -> None:
        self._depth += 1
        key = id(self._func_stack[-1]) if self._func_stack else 0
        if self._depth > self.limits["max_nesting"] and key not in self._nesting_flagged:
            self._nesting_flagged.add(key)
            self.report("MNT004", node, f"Code is nested {self._depth} levels deep "
                                        f"(limit {self.limits['max_nesting']}).")

    def _visit_block(self, node: ast.AST) -> None:
        self._enter_block(node)
        self.generic_visit(node)
        self._depth -= 1

    def visit_For(self, node):
        self._visit_block(node)

    visit_AsyncFor = visit_While = visit_Try = visit_AsyncWith = visit_For
    if hasattr(ast, "TryStar"):  # Python 3.11+
        visit_TryStar = visit_For

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            if isinstance(item.context_expr, ast.Call) and dotted_name(item.context_expr.func) in OPEN_FUNCS:
                self._with_opens.add(id(item.context_expr))
        self._visit_block(node)

    def visit_If(self, node: ast.If) -> None:
        main_guard = is_main_guard(node)
        previous = self._in_main_guard
        self._in_main_guard = previous or main_guard

        self.visit(node.test)
        self._enter_block(node)
        for child in node.body:
            self.visit(child)
        self._depth -= 1

        if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
            self.visit(node.orelse[0])  # `elif` stays at the same depth
        elif node.orelse:
            self._depth += 1
            for child in node.orelse:
                self.visit(child)
            self._depth -= 1
        self._in_main_guard = previous

    # ------------------------------------------------------------- functions
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_function(node)
        saved_depth, saved_vars = self._depth, self._dynamic_str_vars
        self._depth, self._dynamic_str_vars = 0, {}
        self._func_stack.append(node)
        self.generic_visit(node)
        self._func_stack.pop()
        self._depth, self._dynamic_str_vars = saved_depth, saved_vars

    visit_AsyncFunctionDef = visit_FunctionDef

    def _check_function(self, node: ast.FunctionDef) -> None:
        name = node.name
        is_public = not name.startswith("_")
        is_dunder = name.startswith("__") and name.endswith("__")

        length = (node.end_lineno or node.lineno) - node.lineno + 1
        if length > self.limits["max_function_lines"]:
            self.report("MNT001", node, f"`{name}` is {length} lines long "
                                        f"(limit {self.limits['max_function_lines']}).")

        complexity = cyclomatic_complexity(node)
        if complexity > self.limits["max_complexity"]:
            self.report("MNT002", node, f"`{name}` has a complexity of {complexity} "
                                        f"(limit {self.limits['max_complexity']}).")

        args = node.args
        params = list(args.posonlyargs + args.args + args.kwonlyargs)
        if params and params[0].arg in ("self", "cls"):
            params = params[1:]
        if len(params) > self.limits["max_params"]:
            self.report("MNT003", node, f"`{name}` takes {len(params)} parameters "
                                        f"(limit {self.limits['max_params']}).")

        positional = args.posonlyargs + args.args
        with_defaults = list(zip(positional[len(positional) - len(args.defaults):], args.defaults))
        with_defaults += [(a, d) for a, d in zip(args.kwonlyargs, args.kw_defaults) if d is not None]
        for param, default in with_defaults:
            mutable = isinstance(default, (ast.List, ast.Dict, ast.Set)) or (
                isinstance(default, ast.Call) and dotted_name(default.func) in MUTABLE_FACTORIES
            )
            if mutable:
                self.report("REL002", default, f"`{name}` uses a mutable default for `{param.arg}`.")
            if looks_like_secret(param.arg, default):
                self.report("SEC004", default, f"Parameter `{param.arg}` has a hardcoded default value.")

        if is_public and ast.get_docstring(node) is None:
            self.report("STY001", node, f"Public function `{name}` has no docstring.")

        if not SNAKE_CASE.match(name):
            self.report("STY002", node, f"Function `{name}` should be snake_case.")

        if is_public or name == "__init__":
            missing = [p.arg for p in params if p.annotation is None]
            if node.returns is None and not is_dunder:
                missing.append("return")
            if missing:
                self.report("STY006", node, f"`{name}` is missing type hints for: {', '.join(missing)}.")

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        if not node.name.startswith("_") and ast.get_docstring(node) is None:
            self.report("STY001", node, f"Public class `{node.name}` has no docstring.")
        if not PASCAL_CASE.match(node.name):
            self.report("STY002", node, f"Class `{node.name}` should be PascalCase.")
        self.generic_visit(node)

    # ------------------------------------------------------------- calls
    def visit_Call(self, node: ast.Call) -> None:
        name = dotted_name(node.func)
        short = name.rsplit(".", 1)[-1]
        first = node.args[0] if node.args else None

        # SEC001 eval / exec
        if name in ("eval", "exec"):
            self.report("SEC001", node, f"`{name}()` runs a string as Python code.")

        # SEC002 shell injection (constant commands can't be injected, so skip them)
        if name in SHELL_STRING_FUNCS and first is not None and not isinstance(first, ast.Constant):
            self.report("SEC002", node, f"`{name}()` runs a command built from variable data through a shell.")
        if is_const(keyword_value(node, "shell"), True) and first is not None \
                and not isinstance(first, ast.Constant):
            self.report("SEC002", node, f"`{name}(..., shell=True)` runs a command built from variable data.")

        # SEC003 SQL injection
        if name.endswith(SQL_EXECUTORS) or name == "execute":
            if first is not None and is_dynamic_string(first):
                self.report("SEC003", node, f"The query passed to `{short}()` is built with string formatting.")
            elif isinstance(first, ast.Name) and first.id in self._dynamic_str_vars:
                built_on = self._dynamic_str_vars[first.id]
                self.report("SEC003", node, f"`{first.id}` (built with string formatting on line {built_on}) "
                                            f"is passed to `{short}()`.")

        # SEC004 secrets passed as keyword arguments, e.g. connect(password="...")
        for kw in node.keywords:
            if kw.arg and looks_like_secret(kw.arg, kw.value):
                self.report("SEC004", kw.value, f"Hardcoded value passed as `{kw.arg}=`.")

        # SEC005 unsafe deserialization
        if name in DESERIALIZERS:
            self.report("SEC005", node, f"`{name}()` can execute code while loading data.")
        if name in ("yaml.load", "yaml.load_all"):
            loader = keyword_value(node, "Loader") or (node.args[1] if len(node.args) > 1 else None)
            if loader is None or not dotted_name(loader).endswith("SafeLoader"):
                self.report("SEC005", node, f"`{name}()` without SafeLoader can build arbitrary objects.")

        # SEC006 TLS verification disabled
        if is_const(keyword_value(node, "verify"), False):
            self.report("SEC006", node, f"`{name}(..., verify=False)` disables certificate checks.")
        if name == "ssl._create_unverified_context":
            self.report("SEC006", node, "An unverified SSL context accepts any certificate.")

        # SEC007 weak hashes (skip when explicitly marked not-for-security)
        if not is_const(keyword_value(node, "usedforsecurity"), False):
            if name in WEAK_HASHES:
                self.report("SEC007", node, f"`{name}()` is a broken hash algorithm.")
            elif name == "hashlib.new" and isinstance(first, ast.Constant) \
                    and str(first.value).lower() in ("md5", "sha1"):
                self.report("SEC007", node, f"`hashlib.new(\"{first.value}\")` is a broken hash algorithm.")

        # SEC008 debug mode
        if short == "run" and is_const(keyword_value(node, "debug"), True):
            self.report("SEC008", node, f"`{name}(debug=True)` enables the interactive debugger.")

        # REL004 open() outside `with`
        if name in OPEN_FUNCS and id(node) not in self._with_opens:
            self.report("REL004", node, "`open()` is not used in a `with` block.")

        # STY004 print outside the `if __name__ == "__main__":` block
        if name == "print" and not self._in_main_guard:
            self.report("STY004", node, "`print()` used for output; prefer logging.")

        self.generic_visit(node)

    # ------------------------------------------------------------- assignments
    def _check_assignment_target(self, target: ast.AST, value: ast.AST) -> None:
        name = target.id if isinstance(target, ast.Name) else \
            target.attr if isinstance(target, ast.Attribute) else None
        if name is None:
            return
        if looks_like_secret(name, value):
            self.report("SEC004", target, f"`{name}` is assigned a hardcoded value.")
        if isinstance(target, ast.Attribute) and name == "debug" and is_const(value, True):
            self.report("SEC008", target, f"`{dotted_name(target)} = True` enables debug mode.")
        if isinstance(target, ast.Name):
            if is_dynamic_string(value):
                self._dynamic_str_vars[name] = target.lineno
            else:
                self._dynamic_str_vars.pop(name, None)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._check_assignment_target(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._check_assignment_target(node.target, node.value)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        # query += f" AND name = '{name}'"  -> appending anything non-constant makes it dynamic
        if isinstance(node.target, ast.Name) and isinstance(node.op, ast.Add) \
                and not isinstance(node.value, ast.Constant):
            self._dynamic_str_vars.setdefault(node.target.id, node.lineno)
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        for key, value in zip(node.keys, node.values):
            if isinstance(key, ast.Constant) and isinstance(key.value, str) and looks_like_secret(key.value, value):
                self.report("SEC004", value, f"Dictionary key `{key.value}` holds a hardcoded value.")
        self.generic_visit(node)

    # ------------------------------------------------------------- misc
    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is None:
            self.report("REL001", node, "`except:` catches everything, including Ctrl+C.")
        if all(isinstance(stmt, ast.Pass) or (isinstance(stmt, ast.Expr) and is_const(stmt.value, Ellipsis))
               for stmt in node.body):
            self.report("REL003", node, "The exception is caught and ignored.")
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        for op, right in zip(node.ops, node.comparators):
            if isinstance(op, (ast.Eq, ast.NotEq)) and is_const(right, None):
                bad, good = ("==", "is None") if isinstance(op, ast.Eq) else ("!=", "is not None")
                self.report("REL005", node, f"Use `{good}` instead of `{bad} None`.")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if any(alias.name == "*" for alias in node.names):
            self.report("MNT005", node, f"`from {node.module} import *`.")
        self.generic_visit(node)

    def visit_Global(self, node: ast.Global) -> None:
        self.report("MNT006", node, f"`global {', '.join(node.names)}` modifies module state.")

    # ------------------------------------------------------------- text checks
    def _check_text(self) -> None:
        limit = self.limits["max_line_length"]
        for number, text in enumerate(self.lines, start=1):
            if len(text) > limit:
                self.report("STY003", number, f"Line is {len(text)} characters (limit {limit}).")
        try:
            for tok in tokenize.generate_tokens(io.StringIO(self.source).readline):
                match = TODO_MARKER.search(tok.string) if tok.type == tokenize.COMMENT else None
                if match:
                    self.report("STY005", tok.start[0], f"`{match.group(1)}` comment left in code.")
        except (tokenize.TokenError, SyntaxError):
            pass
