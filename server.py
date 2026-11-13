"""Web server for the demo UI. Standard library only.

    python server.py            -> http://127.0.0.1:8000
    python server.py --port 9000

Endpoints
    GET  /               the web UI (static/index.html)
    POST /api/analyze    {"code": "..."}  ->  analysis report (JSON)
    GET  /api/samples    {"bad_example": "...", "good_example": "..."}
    GET  /api/policy     the active policy, the full rule catalog and the CWE catalog
"""
from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from checker import CWES, RULES, analyze, load_policy

ROOT = Path(__file__).resolve().parent
INDEX_HTML = ROOT / "static" / "index.html"
SAMPLES_DIR = ROOT / "samples"
MAX_BODY_BYTES = 512 * 1024
POLICY = load_policy()


class Handler(BaseHTTPRequestHandler):
    server_version = "ComplianceChecker/0.1"

    # ------------------------------------------------------------ routes
    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._send(INDEX_HTML.read_bytes(), "text/html; charset=utf-8")
        elif path == "/api/samples":
            samples = {p.stem: p.read_text(encoding="utf-8") for p in sorted(SAMPLES_DIR.glob("*.py"))}
            self._send_json(samples)
        elif path == "/api/policy":
            self._send_json({
                "policy": POLICY,
                "rules": [rule.to_dict() for rule in RULES.values()],
                "cwes": {cwe_id: cwe.to_dict() for cwe_id, cwe in CWES.items()},
            })
        else:
            self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        if self.path.split("?", 1)[0] != "/api/analyze":
            self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
            return
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
            self._send_json({"error": "Body must be JSON"}, HTTPStatus.BAD_REQUEST)
            return
        code = payload.get("code") if isinstance(payload, dict) else None
        if not isinstance(code, str):
            self._send_json({"error": "Expected {\"code\": \"...\"}"}, HTTPStatus.BAD_REQUEST)
            return
        self._send_json(analyze(code, POLICY))

    # ------------------------------------------------------------ helpers
    def _send(self, body: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, data: object, status: HTTPStatus = HTTPStatus.OK) -> None:
        self._send(json.dumps(data).encode("utf-8"), "application/json", status)

    def log_message(self, fmt: str, *args) -> None:
        print(f"  {self.command} {self.path} -> {args[1] if len(args) > 1 else ''}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the compliance checker web UI.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Compliance checker running at http://{args.host}:{args.port}  (Ctrl+C to stop)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
