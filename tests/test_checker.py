"""Run from the repo root with:  python -m unittest"""
import textwrap
import unittest
from pathlib import Path

from checker import analyze

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


if __name__ == "__main__":
    unittest.main()
