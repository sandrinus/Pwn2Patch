"""Repository scanning: link validation, safe extraction, summaries, the job store and the HTTP API.

Everything here runs offline: a fake fetcher stands in for git / GitHub.
"""
import io
import json
import shutil
import stat
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path

import repos
from checker import analyze, load_policy

POLICY = load_policy()


def wait(job, timeout=10):
    deadline = time.time() + timeout
    while job.state not in ("done", "error") and time.time() < deadline:
        time.sleep(0.02)
    return job


def fake_fetch(files: dict[str, str | bytes]):
    """A fetcher that 'downloads' the given files into the scan directory."""
    def fetch(link, dest, deadline):
        for path, content in files.items():
            target = dest / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content.encode() if isinstance(content, str) else content)
        return {"commit": "abc1234", "ref": "main", "method": "fake", "files_over_limit": 0}
    return fetch


class LinkTests(unittest.TestCase):
    def test_accepted_links(self):
        cases = {
            "https://github.com/pallets/flask": ("github.com", ("pallets", "flask"), None),
            "pallets/flask": ("github.com", ("pallets", "flask"), None),
            "https://github.com/psf/requests.git": ("github.com", ("psf", "requests"), None),
            "https://github.com/pallets/flask/tree/3.0.x": ("github.com", ("pallets", "flask"), "3.0.x"),
            "https://gitlab.com/group/sub/proj/-/tree/main": ("gitlab.com", ("group", "sub", "proj"), "main"),
            "  https://GitHub.com/a/b/  ": ("github.com", ("a", "b"), None),
        }
        for text, (host, path, ref) in cases.items():
            link = repos.parse_repo_link(text)
            self.assertEqual((link.host, link.path, link.ref), (host, path, ref), text)

    def test_rejected_links(self):
        for text in ["", "http://github.com/a/b", "git@github.com:a/b.git", "ssh://git@github.com/a/b",
                     "https://user:token@github.com/a/b", "https://127.0.0.1/a/b", "https://[::1]/a/b",
                     "https://localhost/a/b", "https://git.corp/a/b", "https://intranet/a/b",
                     "https://github.com:8443/a/b", "https://github.com/onlyowner",
                     "https://github.com/a/b/tree/../../etc", "https://github.com/a/-b",
                     "https://github.com/a/b/tree/-upload-pack=x", "file:///etc/passwd"]:
            with self.assertRaises(repos.RepoError, msg=text):
                repos.parse_repo_link(text)


class PathTests(unittest.TestCase):
    def test_python_paths_skip_dependencies_and_build_output(self):
        paths = ["app.py", "pkg/mod.py", "README.md", "venv/lib/x.py", ".venv/y.py", "node_modules/a/b.py",
                 "build/lib/c.py", "pkg/__pycache__/m.py", "docs/conf.py", "src/env.py"]
        self.assertEqual(repos.python_paths(paths), ["app.py", "docs/conf.py", "pkg/mod.py", "src/env.py"])

    def test_sparse_pattern_matches_exactly_one_file(self):
        self.assertEqual(repos._sparse_pattern("a/b.py"), "/a/b.py")
        self.assertEqual(repos._sparse_pattern("we*ird[1]#!.py"), r"/we\*ird\[1]\#\!.py")


class ZipTests(unittest.TestCase):
    def setUp(self):
        self.dest = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dest, ignore_errors=True)

    def make_zip(self, members):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for name, data, *mode in members:
                info = zipfile.ZipInfo(name)
                if mode:
                    info.external_attr = mode[0] << 16
                z.writestr(info, data)
        return zipfile.ZipFile(io.BytesIO(buf.getvalue()))

    def test_extracts_only_safe_python_files(self):
        archive = self.make_zip([
            ("repo-abc/app.py", "x = 1\n"),
            ("repo-abc/pkg/mod.py", "y = 2\n"),
            ("repo-abc/README.md", "hi"),
            ("repo-abc/../escape.py", "evil = 1\n"),
            ("/abs/evil.py", "evil = 1\n"),
            ("repo-abc/link.py", "/etc/passwd", stat.S_IFLNK | 0o777),
            ("repo-abc/venv/lib/dep.py", "z = 3\n"),
        ])
        repos.extract_python_files(archive, self.dest)
        found = sorted(p.relative_to(self.dest).as_posix() for p in self.dest.rglob("*") if p.is_file())
        self.assertEqual(found, ["app.py", "pkg/mod.py"])
        self.assertFalse((self.dest.parent / "escape.py").exists())

    def test_oversized_member_is_truncated_then_skipped_by_the_scan(self):
        archive = self.make_zip([("repo-abc/big.py", "x" * (repos.MAX_FILE_BYTES + 50))])
        repos.extract_python_files(archive, self.dest)
        source, reason = repos.read_source(self.dest / "big.py")
        self.assertIsNone(source)
        self.assertIn("larger than", reason)


class SummaryTests(unittest.TestCase):
    def test_empty_file_passes_and_does_not_move_the_score(self):
        empty = repos.summarize_file("pkg/__init__.py", analyze("", POLICY, patches=False))
        self.assertTrue(empty["ok"] and empty["empty"])
        self.assertEqual(empty["gate"], "PASS")
        bad = repos.summarize_file("bad.py", analyze("x = eval(y)\n", POLICY, patches=False))
        summary = repos.summarize_repo([empty, bad], [])
        self.assertEqual(summary["score"], bad["score"])
        self.assertEqual(summary["files_passing"], 1)

    def test_syntax_error_is_reported_not_raised(self):
        row = repos.summarize_file("broken.py", analyze("def (:\n", POLICY, patches=False))
        self.assertFalse(row["ok"])
        self.assertEqual(row["gate"], "FAIL")
        self.assertIn("Syntax error", row["error"])

    def test_repo_score_is_weighted_by_code_lines(self):
        files = [{"path": "a.py", "ok": True, "code_lines": 300, "score": 100, "lines": 300, "findings": 0,
                  "gate": "PASS", "severity_counts": {}, "rules": {}},
                 {"path": "b.py", "ok": True, "code_lines": 100, "score": 60, "lines": 100, "findings": 1,
                  "gate": "FAIL", "severity_counts": {"high": 1}, "rules": {"SEC004": 1}}]
        summary = repos.summarize_repo(files, [])
        self.assertEqual(summary["score"], 90)
        self.assertEqual(summary["rules"][0]["rule_id"], "SEC004")


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)

    def store(self, files):
        return repos.RepoStore(POLICY, base=self.base, fetch=fake_fetch(files))

    def test_scan_summarizes_every_python_file(self):
        store = self.store({"app.py": "import os\nos.system('ls ' + x)\n", "pkg/__init__.py": "",
                            "pkg/util.py": "def add(a: int, b: int) -> int:\n    \"\"\"Add.\"\"\"\n    return a + b\n",
                            "notes.txt": "not python", "latin1.py": b"x = '\xe9'\n"})
        job = wait(store.start("https://github.com/acme/tool"))
        self.assertEqual(job.state, "done", job.error)
        data = job.to_dict()
        self.assertEqual([f["path"] for f in data["files"]], ["app.py", "pkg/__init__.py", "pkg/util.py"])
        self.assertEqual(data["skipped"], [{"path": "latin1.py", "reason": "not UTF-8 text"}])
        self.assertEqual(data["summary"]["files_scanned"], 3)
        self.assertIn("SEC002", data["files"][0]["rules"])
        self.assertEqual(data["commit"], "abc1234")

    def test_read_file_only_serves_scanned_files(self):
        store = self.store({"app.py": "x = 1\n", "secret.txt": "token"})
        job = wait(store.start("acme/tool"))
        self.assertEqual(store.read_file(job.id, "app.py"), "x = 1\n")
        for path in ["secret.txt", "../app.py", "/etc/passwd", "app.py/../app.py"]:
            with self.assertRaises(KeyError, msg=path):
                store.read_file(job.id, path)

    def test_same_link_reuses_the_scan(self):
        store = self.store({"app.py": "x = 1\n"})
        first = wait(store.start("acme/tool"))
        self.assertIs(store.start("https://github.com/acme/tool.git"), first)

    def test_fetch_errors_become_user_messages(self):
        def failing(link, dest, deadline):
            raise repos.RepoError("Repository not found, or it's private.")
        store = repos.RepoStore(POLICY, base=self.base, fetch=failing)
        job = wait(store.start("acme/missing"))
        self.assertEqual(job.state, "error")
        self.assertIn("not found", job.to_dict()["error"])
        self.assertFalse(job.workdir.exists())

    def test_old_scans_are_deleted(self):
        store = self.store({"app.py": "x = 1\n"})
        jobs = [wait(store.start(f"acme/tool{i}")) for i in range(repos.MAX_REPOS_KEPT + 2)]
        self.assertLessEqual(len(store.jobs), repos.MAX_REPOS_KEPT + 1)
        self.assertFalse(jobs[0].workdir.exists())
        self.assertTrue(jobs[-1].workdir.exists())


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import server
        cls.base = Path(tempfile.mkdtemp())
        server.REPOS = repos.RepoStore(POLICY, base=cls.base, fetch=fake_fetch({"app.py": "x = eval(y)\n"}))
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.httpd.RequestHandlerClass.log_message = lambda *a: None
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        shutil.rmtree(cls.base, ignore_errors=True)

    def request(self, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as res:
                return res.status, dict(res.headers), res.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()

    def test_page_and_modules_are_served_with_csp(self):
        status, headers, body = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
        self.assertIn(b'type="module"', body)
        status, headers, _ = self.request("/static/js/main.js")
        self.assertEqual((status, headers["Content-Type"]), (200, "text/javascript; charset=utf-8"))

    def test_static_files_cannot_escape_the_static_folder(self):
        for path in ["/static/../server.py", "/static/%2e%2e/server.py", "/static/js/../../repos.py", "/static/nope.js"]:
            self.assertEqual(self.request(path)[0], 404, path)

    def test_repo_scan_round_trip(self):
        status, _, body = self.request("/api/repo", {"url": "acme/tool"})
        self.assertEqual(status, 202)
        job_id = json.loads(body)["id"]
        for _ in range(200):
            status, _, body = self.request(f"/api/repo/{job_id}")
            data = json.loads(body)
            if data["state"] in ("done", "error"):
                break
            time.sleep(0.02)
        self.assertEqual(data["state"], "done")
        self.assertEqual(data["files"][0]["rules"], {"SEC001": 1})
        status, _, body = self.request(f"/api/repo/{job_id}/file?path=app.py")
        self.assertEqual((status, json.loads(body)["code"]), (200, "x = eval(y)\n"))
        self.assertEqual(self.request(f"/api/repo/{job_id}/file?path=../server.py")[0], 404)

    def test_repo_errors(self):
        status, _, body = self.request("/api/repo", {"url": "https://localhost/a/b"})
        self.assertEqual(status, 400)
        self.assertIn("public", json.loads(body)["error"])
        self.assertEqual(self.request("/api/repo", {"nope": 1})[0], 400)
        self.assertEqual(self.request("/api/repo/doesnotexist")[0], 404)


if __name__ == "__main__":
    unittest.main()
