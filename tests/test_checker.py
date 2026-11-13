"""Run from the repo root with:  python -m unittest"""
import ast
import textwrap
import unittest
from pathlib import Path

from checker import CWES, RULES, analyze, patch_all
from checker.fixes import apply_edits, Edit

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def rule_ids(code: str) -> set[str]:
    report = analyze(textwrap.dedent(code))
    assert report["ok"], report
    return {f["rule_id"] for f in report["findings"]}


class SampleTests(unittest.TestCase):
    def test_bad_sample_fails_gate(self):
        report = analyze((SAMPLES / "bad_example.py").read_text(encoding="utf-8"))
        self.assertEqual(report["gate"]["status"], "FAIL")
        self.assertEqual(report["grade"], "F")
        found = {f["rule_id"] for f in report["findings"]}
        for expected in ("SEC001", "SEC002", "SEC003", "SEC004", "SEC005", "SEC006", "SEC007", "SEC008",
                         "REL001", "REL002", "REL003", "REL004", "MNT002", "MNT004"):
            self.assertIn(expected, found)

    def test_good_sample_passes_with_full_score(self):
        report = analyze((SAMPLES / "good_example.py").read_text(encoding="utf-8"))
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["score"], 100)
        self.assertEqual(report["gate"]["status"], "PASS")


class SecurityRuleTests(unittest.TestCase):
    def test_sql_injection_direct_and_via_variable(self):
        self.assertIn("SEC003", rule_ids('cur.execute(f"SELECT * FROM t WHERE id = {uid}")'))
        self.assertIn("SEC003", rule_ids('q = "SELECT * FROM t WHERE id = " + uid\ncur.execute(q)'))

    def test_parameterized_query_is_clean(self):
        self.assertNotIn("SEC003", rule_ids('cur.execute("SELECT * FROM t WHERE id = ?", (uid,))'))

    def test_reassigned_query_is_not_flagged(self):
        code = 'q = f"SELECT {x}"\nq = "SELECT 1"\ncur.execute(q)'
        self.assertNotIn("SEC003", rule_ids(code))

    def test_shell_injection_only_when_command_is_dynamic(self):
        self.assertIn("SEC002", rule_ids('import os\nos.system("rm " + path)'))
        self.assertIn("SEC002", rule_ids("subprocess.run(cmd, shell=True)"))
        self.assertNotIn("SEC002", rule_ids('import os\nos.system("clear")'))
        self.assertNotIn("SEC002", rule_ids('subprocess.run(["ls", path])'))

    def test_hardcoded_secrets(self):
        self.assertIn("SEC004", rule_ids('DB_PASSWORD = "hunter2hunter2"'))
        self.assertIn("SEC004", rule_ids('apiKey = "abcdef123456"'))
        self.assertIn("SEC004", rule_ids('connect(password="hunter2hunter2")'))
        self.assertIn("SEC004", rule_ids('cfg = {"secret": "abcdef123456"}'))
        self.assertNotIn("SEC004", rule_ids('DB_PASSWORD = os.environ["DB_PASSWORD"]'))
        self.assertNotIn("SEC004", rule_ids('tokenizer = "bert-base-uncased"'))

    def test_yaml_safe_loader_is_clean(self):
        self.assertIn("SEC005", rule_ids("yaml.load(data)"))
        self.assertNotIn("SEC005", rule_ids("yaml.load(data, Loader=yaml.SafeLoader)"))

    def test_weak_hash_allowed_when_not_for_security(self):
        self.assertIn("SEC007", rule_ids("hashlib.md5(b'x')"))
        self.assertNotIn("SEC007", rule_ids("hashlib.md5(b'x', usedforsecurity=False)"))


# Fake values. The GitHub-shaped one is assembled at runtime so no key-shaped literal sits in the repo.
FAKE_KEY = "FAKEk3yZq8vR2kLm9XyT4wPb7NcH3sJd6"   # random-looking, no provider format
FAKE_GH = "gh" + "p_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"


def secret_findings(code: str) -> list[tuple[str, int]]:
    report = analyze(textwrap.dedent(code))
    assert report["ok"], report
    return [(f["rule_id"], f["line"]) for f in report["findings"] if f["rule_id"] in ("SEC004", "SEC009")]


class RenamedSecretTests(unittest.TestCase):
    """Renaming a variable must not hide the secret it holds."""

    def test_renamed_key_used_in_a_header_is_still_a_secret(self):
        code = f'cfg = "{FAKE_KEY}"\ndef f():\n    return requests.get(u, headers={{"X-API-Key": cfg}})'
        self.assertEqual(secret_findings(code), [("SEC004", 1)])

    def test_bearer_header_built_from_a_renamed_value(self):
        self.assertEqual(secret_findings(f'v = "{FAKE_KEY}"\nh = {{"Authorization": f"Bearer {{v}}"}}'),
                         [("SEC004", 1)])
        self.assertEqual(secret_findings(f'v = "{FAKE_KEY}"\nheaders["Authorization"] = "Bearer " + v'),
                         [("SEC004", 1)])

    def test_renamed_password_used_to_log_in(self):
        self.assertEqual(primary_cwes('p = "hunter2!"\nsmtp.login("me@example.com", p)', "SEC004"), ["CWE-259"])
        self.assertEqual(primary_cwes('p = "Winter2024!"\nrequests.get(u, auth=("admin", p))', "SEC004"),
                         ["CWE-259"])
        self.assertEqual(secret_findings('def connect(h, pw="Tr0ub4dor&3"):\n'
                                         '    return psycopg2.connect(host=h, password=pw)'), [("SEC004", 1)])

    def test_attribute_and_alias_sinks(self):
        self.assertEqual(secret_findings(f'k = "{FAKE_KEY}"\nopenai.api_key = k'), [("SEC004", 1)])
        self.assertEqual(secret_findings(f'k = "{FAKE_KEY}"\nAPI_KEY = k'), [("SEC004", 1)])
        self.assertEqual(secret_findings(f'''
            class Client:
                def __init__(self):
                    self.k = "{FAKE_KEY}"
                def headers(self):
                    return {{"Authorization": "Bearer " + self.k}}
        '''), [("SEC004", 4)])

    def test_known_formats_are_caught_whatever_the_name(self):
        self.assertEqual(secret_findings(f'settings_value = "{FAKE_GH}"'), [("SEC004", 1)])
        self.assertEqual(secret_findings(f'thing = "{FAKE_GH[:4]}" + "{FAKE_GH[4:]}"'), [("SEC004", 1)])
        self.assertEqual(secret_findings(f'Github("{FAKE_GH}")'), [("SEC004", 1)])
        self.assertEqual(primary_cwes('DATABASE_URL = "postgres://admin:S3cretPa55@db:5432/app"', "SEC004"),
                         ["CWE-259"])

    def test_unused_random_looking_value_is_a_possible_secret(self):
        report = analyze(f'x = "{FAKE_KEY}"\n')
        finding = next(f for f in report["findings"] if f["rule_id"] == "SEC009")
        self.assertEqual(finding["severity"], "medium")

    def test_renaming_the_sample_key_keeps_the_finding(self):
        source = (SAMPLES / "bad_example.py").read_text(encoding="utf-8")
        renamed = source.replace("API_KEY", "cfg_value")
        before = [f for f in analyze(source)["findings"] if f["rule_id"] == "SEC004" and f["line"] == 10]
        after = [f for f in analyze(renamed)["findings"] if f["rule_id"] == "SEC004" and f["line"] == 10]
        self.assertEqual(len(before), 1)
        self.assertEqual(len(after), 1)
        self.assertIn("X-API-Key", after[0]["message"])
        self.assertEqual(analyze(source)["score"], analyze(renamed)["score"])

    def test_things_that_are_not_secrets(self):
        quiet = [
            'API_KEY = os.environ["API_KEY"]\nrequests.get(u, headers={"X-API-Key": API_KEY})',
            't = "hunter2!"\ndef f(t):\n    return {"Authorization": f"Bearer {t}"}',  # parameter shadows it
            'expected_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"',
            'ok = hashlib.sha256(d).hexdigest() == '
            '"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"',
            'h = {"Authorization": "Bearer <token>"}',
            'h = {"Authorization": "Bearer ${API_TOKEN}"}',
            'URL = "postgres://user:password@localhost/db"',
            'MODEL = "sentence-transformers/all-MiniLM-L6-v2"',
            'REQUEST_ID = "437e36fc-07cd-4c69-8d65-d9f35f2997ff"',
            'BACKEND = "MyCustomAuthenticationBackend1"',
            'PATH = "/usr/local/lib/python3.11/site-packages"',
        ]
        for code in quiet:
            self.assertEqual(secret_findings(code), [], code)


class QualityRuleTests(unittest.TestCase):
    def test_open_inside_with_is_clean(self):
        self.assertIn("REL004", rule_ids("f = open('x')"))
        self.assertNotIn("REL004", rule_ids("with open('x') as f:\n    pass"))

    def test_elif_chain_does_not_count_as_nesting(self):
        branches = "\n".join(f"elif x == {i}:\n    y = {i}" for i in range(1, 8))
        self.assertNotIn("MNT004", rule_ids(f"if x == 0:\n    y = 0\n{branches}"))

    def test_print_allowed_in_main_guard(self):
        self.assertNotIn("STY004", rule_ids('if __name__ == "__main__":\n    print("hi")'))
        self.assertIn("STY004", rule_ids('print("hi")'))


def primary_cwes(code: str, rule_id: str) -> list:
    report = analyze(textwrap.dedent(code))
    return [f["cwe"][0]["id"] if f["cwe"] else None for f in report["findings"] if f["rule_id"] == rule_id]


class CweMappingTests(unittest.TestCase):
    def test_every_rule_cwe_is_in_the_catalog(self):
        for rule in RULES.values():
            for cwe_id in rule.cwe:
                self.assertIn(cwe_id, CWES, f"{rule.id} maps to unknown {cwe_id}")

    def test_security_rules_map_to_vulnerability_cwes(self):
        for rule in RULES.values():
            if rule.category == "security":
                self.assertTrue(rule.cwe, f"{rule.id} has no CWE")
                for cwe_id in rule.cwe:
                    self.assertFalse(CWES[cwe_id].is_quality_only, f"{rule.id} uses quality-only {cwe_id}")

    def test_injection_findings(self):
        self.assertEqual(primary_cwes('cur.execute(f"SELECT {x}")', "SEC003"), ["CWE-89"])
        self.assertEqual(primary_cwes("subprocess.run(cmd, shell=True)", "SEC002"), ["CWE-78"])
        self.assertEqual(primary_cwes("eval(text)", "SEC001"), ["CWE-95"])

    def test_hardcoded_password_is_more_specific_than_credentials(self):
        self.assertEqual(primary_cwes('DB_PASSWORD = "hunter2hunter2"', "SEC004"), ["CWE-259"])
        self.assertEqual(primary_cwes('API_KEY = "abcdef123456"', "SEC004"), ["CWE-798"])

    def test_weak_hash_on_a_password_maps_to_cwe_916(self):
        code = 'def hash_password(pw):\n    return hashlib.md5(pw.encode())\n'
        self.assertEqual(primary_cwes(code, "SEC007"), ["CWE-916"])
        self.assertEqual(primary_cwes("digest = hashlib.md5(data)", "SEC007"), ["CWE-328"])

    def test_rule_without_a_cwe_reports_an_empty_list(self):
        self.assertEqual(primary_cwes("def f(x=[]):\n    return x\n", "REL002"), [None])

    def test_summary_groups_findings_by_primary_cwe(self):
        report = analyze((SAMPLES / "bad_example.py").read_text(encoding="utf-8"))
        summary = {row["id"]: row for row in report["cwe_summary"]}
        self.assertEqual(len(summary), len(report["cwe_summary"]))  # no duplicate rows
        self.assertEqual(summary["CWE-78"]["count"], 2)
        self.assertEqual(report["cwe_summary"][0]["worst_severity"], "critical")
        self.assertTrue(summary["CWE-1121"]["quality_only"])
        self.assertEqual(report["cwe_coverage"]["mapped"], sum(row["count"] for row in report["cwe_summary"]))


class ErrorHandlingTests(unittest.TestCase):
    def test_syntax_error_reports_line(self):
        report = analyze("def broken(:\n    pass\n")
        self.assertFalse(report["ok"])
        self.assertEqual(report["error"]["type"], "syntax")
        self.assertEqual(report["error"]["line"], 1)
        self.assertEqual(report["gate"]["status"], "FAIL")

    def test_empty_input(self):
        self.assertEqual(analyze("   \n")["error"]["type"], "empty")

    def test_code_is_never_executed(self):
        # If the analyzer ran this, the test process would exit.
        report = analyze("import sys\nsys.exit(1)\n")
        self.assertTrue(report["ok"])

    def test_line_numbers_match_python_with_unusual_line_breaks(self):
        # str.splitlines() also breaks on   and form feeds; Python doesn't, so snippets used to drift.
        for code in ('x = "a b"\ny = 1\nf = open("p")\n', 'x = 1\n\x0c\ny = 2\nf = open("p")\n'):
            finding = next(f for f in analyze(code)["findings"] if f["rule_id"] == "REL004")
            self.assertEqual(finding["snippet"], 'f = open("p")', repr(code))

    def test_windows_and_old_mac_line_endings(self):
        for newline in ("\r\n", "\r"):
            code = newline.join(["import os", 'API_KEY = "abcdef123456"', ""])
            finding = next(f for f in analyze(code)["findings"] if f["rule_id"] == "SEC004")
            self.assertEqual(finding["line"], 2)
            self.assertEqual(finding["fix"]["edits"][0]["lines"], ['API_KEY = os.environ["API_KEY"]'])


def fixed(code: str, rule_id: str) -> str:
    """Apply the suggested fix for the first `rule_id` finding and return the new code."""
    code = textwrap.dedent(code)
    report = analyze(code)
    finding = next(f for f in report["findings"] if f["rule_id"] == rule_id)
    assert finding["fix"], f"no fix for {rule_id}"
    edits = [Edit(**e) for e in finding["fix"]["edits"]]
    return apply_edits(code, edits)


class FixTests(unittest.TestCase):
    def test_sql_injection_via_variable_becomes_parameterized(self):
        out = fixed('''
            def get(cur, name):
                q = "SELECT * FROM t WHERE name = '" + name + "'"
                cur.execute(q)
        ''', "SEC003")
        self.assertIn('q = "SELECT * FROM t WHERE name = ?"', out)
        self.assertIn("cur.execute(q, (name,))", out)
        self.assertNotIn("SEC003", rule_ids(out))

    def test_fstring_sql_becomes_parameterized(self):
        out = fixed('cur.execute(f"SELECT * FROM t WHERE id = {uid}")', "SEC003")
        self.assertIn('cur.execute("SELECT * FROM t WHERE id = ?", (uid,))', out)

    def test_shell_string_becomes_argument_list(self):
        out = fixed('import os\nos.system("ping -c 1 " + host)', "SEC002")
        self.assertIn("subprocess.run(['ping', '-c', '1', host])", out)
        self.assertIn("import subprocess", out)

    def test_user_chosen_program_gets_no_fix(self):
        report = analyze('import subprocess\nsubprocess.run(cmd, shell=True)')
        self.assertIsNone(next(f for f in report["findings"] if f["rule_id"] == "SEC002")["fix"])

    def test_password_hash_gets_no_fix(self):
        report = analyze('import hashlib\ndef hash_password(pw):\n    return hashlib.md5(pw).hexdigest()')
        self.assertIsNone(next(f for f in report["findings"] if f["rule_id"] == "SEC007")["fix"])

    def test_secret_moves_to_environment(self):
        out = fixed('API_KEY = "abcdef123456"', "SEC004")
        self.assertIn('API_KEY = os.environ["API_KEY"]', out)
        self.assertIn("import os", out)

    def test_open_becomes_with_block(self):
        out = fixed('''
            def save(msg):
                f = open("log.txt", "a")
                f.write(msg)
                f.close()
        ''', "REL004")
        self.assertIn('    with open("log.txt", "a") as f:\n        f.write(msg)\n', out)
        self.assertNotIn("close", out)

    def test_mutable_default(self):
        out = fixed('def f(items=[]):\n    """Doc."""\n    return items', "REL002")
        self.assertIn("def f(items=None):", out)
        self.assertIn('    """Doc."""\n    if items is None:\n        items = []', out)

    def test_rename_updates_every_use(self):
        out = fixed('def getUser():\n    pass\n\ngetUser()', "STY002")
        self.assertEqual(out.count("get_user"), 2)
        self.assertNotIn("getUser", out)

    def test_star_import_lists_used_names(self):
        out = fixed('from flask import *\napp = Flask(__name__)\nx = request.args', "MNT005")
        self.assertIn("from flask import Flask, request", out)

    def test_every_offered_fix_parses(self):
        report = analyze((SAMPLES / "bad_example.py").read_text(encoding="utf-8"))
        source = (SAMPLES / "bad_example.py").read_text(encoding="utf-8")
        for f in report["findings"]:
            if f["fix"]:
                ast.parse(apply_edits(source, [Edit(**e) for e in f["fix"]["edits"]]))

    def test_patch_all_improves_bad_sample(self):
        source = (SAMPLES / "bad_example.py").read_text(encoding="utf-8")
        result = patch_all(source)
        self.assertTrue(result["ok"])
        self.assertGreater(result["score_after"], result["score_before"])
        remaining = {f["rule_id"] for f in analyze(result["code"])["findings"]}
        for gone in ("SEC001", "SEC003", "SEC005", "SEC006", "SEC008", "REL001", "REL003", "REL004"):
            self.assertNotIn(gone, remaining)
        self.assertIn("SEC002", remaining)  # the /run route lets the user pick the program: needs a human

    def test_finding_keeps_the_rules_advice_next_to_the_patch(self):
        finding = next(f for f in analyze('eval(text)')["findings"] if f["rule_id"] == "SEC001")
        self.assertEqual(finding["how_to_fix"], RULES["SEC001"].fix)
        self.assertEqual(finding["fix"]["title"], "Replace eval() with ast.literal_eval()")


def fix_for(code: str, rule_id: str):
    report = analyze(textwrap.dedent(code))
    return next(f for f in report["findings"] if f["rule_id"] == rule_id)["fix"]


class UnsafeFixTests(unittest.TestCase):
    """Cases where a mechanical fix would produce wrong code, so none may be offered."""

    def test_eval_with_extra_arguments(self):
        self.assertIsNone(fix_for('x = eval(expr, {"__builtins__": {}})', "SEC001"))

    def test_shell_syntax_in_the_command(self):
        self.assertIsNone(fix_for('import os\nos.system("cat " + f + " | grep x")', "SEC002"))
        self.assertIsNone(fix_for('import os\nos.system("grep \'a b\' " + f)', "SEC002"))
        self.assertIsNone(fix_for('import os\nos.system("ls $HOME " + f)', "SEC002"))

    def test_getoutput_always_uses_a_shell(self):
        self.assertIsNone(fix_for('import subprocess\nout = subprocess.getoutput("ls " + d)', "SEC002"))

    def test_sql_placeholder_only_where_a_value_goes(self):
        self.assertIsNone(fix_for('''cur.execute("SELECT * FROM t WHERE n LIKE '%" + q + "%'")''', "SEC003"))
        self.assertIsNone(fix_for('cur.execute("SELECT * FROM " + table)', "SEC003"))
        self.assertIsNone(fix_for('cur.execute("SELECT * FROM t WHERE " + condition)', "SEC003"))
        out = fixed('cur.execute(f"INSERT INTO t VALUES ({a}, {b})")', "SEC003")
        self.assertIn('cur.execute("INSERT INTO t VALUES (?, ?)", (a, b))', out)

    def test_methods_that_may_override_a_base_class_are_not_renamed(self):
        for base, method in (("unittest.TestCase", "setUp"), ("BaseHTTPRequestHandler", "do_GET")):
            code = f'class T({base}):\n    """D."""\n    def {method}(self):\n        """D."""\n'
            self.assertIsNone(fix_for(code, "STY002"), method)
        out = fixed('class T:\n    """D."""\n    def getX(self):\n        """D."""\n', "STY002")
        self.assertIn("def get_x(self):", out)


class FixPlacementTests(unittest.TestCase):
    def test_docstring_goes_above_a_decorated_first_method(self):
        out = fixed('class Foo:\n    @property\n    def x(self) -> int:\n        """X."""\n        return 1\n',
                    "STY001")
        self.assertIn('class Foo:\n    """Foo."""\n    @property', out)

    def test_mutable_default_before_a_decorated_inner_function(self):
        out = fixed('def f(a=[]):\n    @dec\n    def g():\n        """G."""\n    return a\n', "REL002")
        self.assertIn("def f(a=None):\n    if a is None:\n        a = []\n    @dec", out)

    def test_import_goes_below_a_shebang(self):
        out = fixed('#!/usr/bin/env python\nAPI_KEY = "abcdef123456"\n', "SEC004")
        self.assertTrue(out.startswith("#!/usr/bin/env python\nimport os\n"), out)

    def test_multi_line_bytes_are_not_reindented(self):
        code = 'def f():\n    """D."""\n    fh = open("x", "wb")\n    fh.write(b"""a\nb""")\n    fh.close()\n'
        self.assertIsNone(fix_for(code, "REL004"))


if __name__ == "__main__":
    unittest.main()
