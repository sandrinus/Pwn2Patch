"""Pwn2Patch web server. Standard library only.

    python server.py            -> http://127.0.0.1:8000
    python server.py --port 9000

Endpoints
    GET  /               the web UI (static/index.html)
    POST /api/analyze    {"code": "..."}  ->  analysis report (JSON)
    POST /api/fix        {"code": "..."}  ->  every automatic fix applied, with a diff
    POST /api/ai-fix     {"code": "...", "rule_id": "SEC007", "line": 30}
                         ->  a Workers AI patch for one finding, verified by the analyzer
    POST /api/repo       {"url": "https://github.com/owner/repo"}  ->  starts a scan, returns its id
    GET  /api/repo/<id>  scan progress; when done, every Python file's score and the repo totals
    GET  /api/repo/<id>/file?path=src/app.py  ->  {"path": ..., "code": ...} for the code browser
    GET  /static/...     the UI's CSS and JavaScript modules
    GET  /api/samples    {"bad_example": "...", "good_example": "..."}
    GET  /api/policy     the active policy, the rule and CWE catalogs, and whether AI patching is on
"""
from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import mimetypes
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from checker import CWES, RULES, analyze, load_policy, patch_all
from checker.ai_fix import ai_fix, ai_status
from repos import RepoError, RepoStore

ROOT = Path(__file__).resolve().parent
STATIC_DIR = ROOT / "static"
INDEX_HTML = STATIC_DIR / "index.html"
SAMPLES_DIR = ROOT / "samples"
MAX_BODY_BYTES = 512 * 1024
POLICY = load_policy()
REPOS = RepoStore(POLICY)

# The page shows code from repositories anyone can link to. Everything is escaped before it's
# rendered; this policy is the second line of defense (no inline or third-party scripts).
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class Handler(BaseHTTPRequestHandler):
    server_version = "Pwn2Patch/0.2"

    # ------------------------------------------------------------ routes
    def do_GET(self) -> None:
        url = urlsplit(self.path)
        path = url.path
        if path in ("/", "/index.html"):
            self._send(INDEX_HTML.read_bytes(), "text/html; charset=utf-8")
        elif path.startswith("/static/"):
            self._static(unquote(path[len("/static/"):]))
        elif path.startswith("/api/repo/"):
            self._repo_get(path[len("/api/repo/"):], parse_qs(url.query))
        elif path == "/api/samples":
            samples = {p.stem: p.read_text(encoding="utf-8") for p in sorted(SAMPLES_DIR.glob("*.py"))}
            self._send_json(samples)
        elif path == "/api/policy":
            self._send_json({
                "policy": POLICY,
                "rules": [rule.to_dict() for rule in RULES.values()],
                "cwes": {cwe_id: cwe.to_dict() for cwe_id, cwe in CWES.items()},
                "ai": ai_status(),
            })
        else:
            self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        handlers = {"/api/analyze": analyze, "/api/fix": patch_all, "/api/ai-fix": None, "/api/repo": None}
        if path not in handlers:
            self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
            return
        payload = self._read_json()
        if payload is None:
            return
        if path == "/api/repo":
            self._repo_start(payload)
            return
        code = payload.get("code")
        if not isinstance(code, str):
            self._send_json({"error": "Expected {\"code\": \"...\"}"}, HTTPStatus.BAD_REQUEST)
            return
        if path == "/api/ai-fix":
            self._ai_fix(code, payload)
        else:
            self._send_json(handlers[path](code, POLICY))

    def _read_json(self) -> dict | None:
        """The request body as a JSON object, or None after sending an error response."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY_BYTES:
            self._send_json({"error": f"Body must be under {MAX_BODY_BYTES // 1024} KB"},
                            HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            payload = None
        if not isinstance(payload, dict):
            self._send_json({"error": "Body must be a JSON object"}, HTTPStatus.BAD_REQUEST)
            return None
        return payload

    # ------------------------------------------------------------ repositories
    def _repo_start(self, payload: dict) -> None:
        url = payload.get("url")
        if not isinstance(url, str) or len(url) > 500:
            self._send_json({"error": "Expected {\"url\": \"https://...\"}"}, HTTPStatus.BAD_REQUEST)
            return
        try:
            job = REPOS.start(url)
        except RepoError as exc:
            self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        print(f"    repo scan {job.id}: {job.link.url}", flush=True)
        self._send_json(job.to_dict(), HTTPStatus.ACCEPTED)

    def _repo_get(self, rest: str, query: dict) -> None:
        job_id, _, action = rest.partition("/")
        job = REPOS.get(job_id)
        if job is None:
            self._send_json({"error": "This scan has expired. Scan the repository again."}, HTTPStatus.NOT_FOUND)
        elif action == "":
            self._send_json(job.to_dict())
        elif action == "file":
            path = (query.get("path") or [""])[0]
            try:
                self._send_json({"path": path, "code": REPOS.read_file(job_id, path)})
            except KeyError:
                self._send_json({"error": "That file isn't part of this scan."}, HTTPStatus.NOT_FOUND)
        else:
            self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)

    def _static(self, rel: str) -> None:
        target = (STATIC_DIR / rel).resolve()
        if STATIC_DIR.resolve() not in target.parents or not target.is_file():
            self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
            return
        kind = {".js": "text/javascript", ".css": "text/css"}.get(target.suffix) \
            or mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self._send(target.read_bytes(), f"{kind}; charset=utf-8" if kind.startswith("text/") else kind)

    def _ai_fix(self, code: str, payload: dict) -> None:
        rule_id, line = payload.get("rule_id"), payload.get("line")
        if not isinstance(rule_id, str) or not isinstance(line, int):
            self._send_json({"error": "Expected {\"code\", \"rule_id\", \"line\"}"}, HTTPStatus.BAD_REQUEST)
            return
        result = ai_fix(code, rule_id, line, POLICY)
        for n, reason in enumerate(result.get("rejections") or [], start=1):
            print(f"    AI draft {n} for {rule_id} line {line} rejected: {reason}", flush=True)
        if result["ok"]:
            self._send_json(result)
            return
        status = {"not_configured": HTTPStatus.SERVICE_UNAVAILABLE, "ai_error": HTTPStatus.BAD_GATEWAY,
                  "not_found": HTTPStatus.CONFLICT}.get(result["error"]["type"], HTTPStatus.UNPROCESSABLE_ENTITY)
        self._send_json({**result, "error": result["error"]["message"], "error_type": result["error"]["type"]},
                        status)

    # ------------------------------------------------------------ helpers
    def _send(self, body: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if content_type.startswith("text/html"):
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, data: object, status: HTTPStatus = HTTPStatus.OK) -> None:
        self._send(json.dumps(data).encode("utf-8"), "application/json", status)

    def log_message(self, fmt: str, *args) -> None:
        print(f"  {self.command} {self.path} -> {args[1] if len(args) > 1 else ''}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Pwn2Patch web UI.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Pwn2Patch running at http://{args.host}:{args.port}  (Ctrl+C to stop)", flush=True)
    ai = ai_status()
    print(f"  AI patching: {'on, ' + ai['model'] if ai['enabled'] else 'off (set CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN)'}",
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
