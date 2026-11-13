"""Run from the repo root with:  python -m unittest"""
import textwrap
import unittest
from pathlib import Path

from checker import CWES, RULES, analyze

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


if __name__ == "__main__":
    unittest.main()
