"""Workers AI patching, with the model replaced by canned answers (no network)."""
import json
import os
import unittest
from unittest import mock

from checker import load_policy
from checker.ai_fix import ai_fix, ai_status, build_messages, parse_draft
from checker.analyzer import PythonAnalyzer

POLICY = load_policy()

MD5_PASSWORD = '''"""Accounts."""
import hashlib


def hash_password(password: str) -> str:
    """Hash a password for storage."""
    return hashlib.md5(password.encode()).hexdigest()
'''

GOOD_DRAFT = {
    "title": "Hash passwords with scrypt and a salt",
    "start_line": 7,
    "end_line": 7,
    "replacement": "    salt = os.urandom(16)\n"
                   "    return salt.hex() + \":\" + hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1).hex()",
    "imports": ["import os"],
    "explanation": "scrypt is a slow, salted password hash from the standard library.",
}


def runner_returning(*answers):
    """A fake Workers AI that returns each answer in turn and records what it was sent."""
    calls = []

    def run(messages):
        calls.append(messages)
        return answers[len(calls) - 1]

    run.calls = calls
    return run



class AIFixTests(unittest.TestCase):
    def test_verified_patch_is_returned_as_edits(self):
        result = ai_fix(MD5_PASSWORD, "SEC007", 7, POLICY, runner=runner_returning(GOOD_DRAFT))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["attempts"], 1)
        self.assertGreaterEqual(result["score_after"], result["score_before"])
        edits = result["fix"]["edits"]
        self.assertIn({"start": 3, "end": 2, "lines": ["import os"]}, edits)  # after `import hashlib`
        self.assertIn("`import os`", result["fix"]["note"])

    def test_answer_as_json_string_with_code_fence(self):
        answer = "```json\n" + json.dumps(GOOD_DRAFT) + "\n```"
        result = ai_fix(MD5_PASSWORD, "SEC007", 7, POLICY, runner=runner_returning(answer))
        self.assertTrue(result["ok"], result)

    def test_patch_that_keeps_the_finding_is_retried_with_feedback(self):
        lazy = {**GOOD_DRAFT, "replacement": "    return hashlib.sha1(password.encode()).hexdigest()",
                "imports": []}
        runner = runner_returning(lazy, GOOD_DRAFT)
        result = ai_fix(MD5_PASSWORD, "SEC007", 7, POLICY, runner=runner)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["attempts"], 2)
        feedback = runner.calls[1][-1]["content"]
        self.assertIn("still reports SEC007", feedback)

    def test_rejected_twice_gives_up(self):
        broken = {**GOOD_DRAFT, "replacement": "    return (", "imports": []}
        result = ai_fix(MD5_PASSWORD, "SEC007", 7, POLICY, runner=runner_returning(broken, broken))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["type"], "rejected")
        self.assertIn("doesn't parse", result["error"]["message"])

    def test_patch_that_adds_a_critical_finding_is_rejected(self):
        sneaky = {**GOOD_DRAFT, "replacement": "    return eval(password)", "imports": []}
        result = ai_fix(MD5_PASSWORD, "SEC007", 7, POLICY, runner=runner_returning(sneaky, sneaky))
        self.assertFalse(result["ok"])
        self.assertIn("SEC001", result["error"]["message"])

    def test_edit_must_cover_the_reported_line(self):
        elsewhere = {**GOOD_DRAFT, "start_line": 2, "end_line": 2, "replacement": "import hashlib"}
        result = ai_fix(MD5_PASSWORD, "SEC007", 7, POLICY, runner=runner_returning(elsewhere, elsewhere))
        self.assertFalse(result["ok"])
        self.assertIn("must include the reported line 7", result["error"]["message"])

    def test_non_import_in_imports_is_rejected(self):
        bad = {**GOOD_DRAFT, "imports": ["os.system('id')"]}
        result = ai_fix(MD5_PASSWORD, "SEC007", 7, POLICY, runner=runner_returning(bad, bad))
        self.assertFalse(result["ok"])
        self.assertIn("not a single import", result["error"]["message"])

    def test_unknown_finding(self):
        result = ai_fix(MD5_PASSWORD, "SEC001", 7, POLICY, runner=runner_returning())
        self.assertEqual(result["error"]["type"], "not_found")

    def test_not_configured_without_credentials(self):
        with mock.patch.dict(os.environ, {"CLOUDFLARE_ACCOUNT_ID": "", "CLOUDFLARE_API_TOKEN": ""}):
            self.assertFalse(ai_status()["enabled"])
            result = ai_fix(MD5_PASSWORD, "SEC007", 7, POLICY)
        self.assertEqual(result["error"]["type"], "not_configured")

    def test_prompt_numbers_lines_and_marks_code_as_untrusted(self):
        finding = next(f for f in PythonAnalyzer(MD5_PASSWORD, POLICY["limits"]).run() if f.rule_id == "SEC007")
        system, user = build_messages(MD5_PASSWORD, finding)
        self.assertIn("untrusted data", system["content"])
        self.assertIn("7 |     return hashlib.md5", user["content"])
        self.assertIn("CWE-916", user["content"])

    def test_parse_draft_rejects_prose(self):
        with self.assertRaises(Exception):
            parse_draft("Sure! Here's how you could fix it...")

    def test_bad_sample_md5_password_gets_a_verified_ai_fix(self):
        with open("samples/bad_example.py", encoding="utf-8") as fh:
            source = fh.read()
        line = next(f.line for f in PythonAnalyzer(source, POLICY["limits"]).run() if f.rule_id == "SEC007")
        draft = {"title": "Use scrypt with a random salt", "start_line": line, "end_line": line,
                 "imports": ["import os"], "explanation": "Use a slow, salted password hash.",
                 "replacement": "    salt = os.urandom(16)\n"
                                "    return salt.hex() + hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1).hex()"}
        result = ai_fix(source, "SEC007", line, POLICY, runner=runner_returning(draft))
        self.assertTrue(result["ok"], result)
        self.assertGreaterEqual(result["score_after"], result["score_before"])  # security is clamped at 0 here
        self.assertLess(result["findings_after"], result["findings_before"])

if __name__ == "__main__":
    unittest.main()
