"""Scan a public Git repository: fetch it, find the Python files, analyze each one.

    job = store.start("https://github.com/pallets/itsdangerous")
    store.status(job.id)          # {"state": "fetching" | "scanning" | "done" | "error", ...}
    store.read_file(job.id, "src/itsdangerous/signer.py")

Fetching
    * `git clone` when git is installed: shallow (--depth 1), blobless, and with a sparse
      checkout of only the .py files we will scan, so a big repo downloads only what we read.
      Hooks, submodules, LFS, credential prompts, symlinks and non-https protocols are off.
    * Otherwise, for github.com only, GitHub's zip archive (pure standard library). Only .py
      members are extracted, with path, symlink and size checks.

Only https links to public hosts are accepted: no credentials in the URL, no IP addresses,
no localhost or private names, so the server can't be pointed at its own network.

Like the rest of Pwn2Patch, nothing from the repository is ever executed or imported.
"""
from __future__ import annotations

import atexit
import io
import ipaddress
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from checker import analyze
from checker.engine import MAX_SOURCE_CHARS
from checker.rules import RULES, SEVERITIES
from checker.scoring import grade_for

MAX_PY_FILES = 1500                 # files scanned per repository
MAX_FILE_BYTES = MAX_SOURCE_CHARS   # larger files are listed as skipped
MAX_ZIP_BYTES = 100 * 1024 * 1024   # GitHub archive download limit
FETCH_TIMEOUT = 120                 # seconds for the whole download
MAX_REPOS_KEPT = 5                  # finished scans kept on disk; older ones are deleted
CACHE_SECONDS = 30 * 60             # rescanning the same link within this window reuses the scan
MAX_CONCURRENT_SCANS = 2

# Directories that hold dependencies, build output or tooling rather than the project's code.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", "node_modules", "site-packages", "dist-packages",
    ".venv", "venv", "env", ".env", "virtualenv", ".tox", ".nox", ".eggs", "build", "dist",
    ".mypy_cache", ".pytest_cache", ".ruff_cache",
}

SEGMENT = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_.-]*$")
REF = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_./-]*$")
HOSTNAME = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
PRIVATE_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home", ".corp", ".intranet")


class RepoError(Exception):
    """A problem the user can act on; the message is shown in the UI as-is."""


# ------------------------------------------------------------------ links
@dataclass(frozen=True)
class RepoLink:
    host: str
    path: tuple[str, ...]      # ("owner", "repo"), or longer for GitLab groups
    ref: str | None = None     # branch or tag from a /tree/<ref> link

    @property
    def url(self) -> str:
        return f"https://{self.host}/{'/'.join(self.path)}"

    @property
    def name(self) -> str:
        return "/".join(self.path)

    def to_dict(self) -> dict:
        return {"url": self.url, "host": self.host, "name": self.name, "ref": self.ref}


def parse_repo_link(text: str) -> RepoLink:
    """Validate a repository link. Accepts `owner/repo` as GitHub shorthand and /tree/<branch> links."""
    text = (text or "").strip()
    if not text:
        raise RepoError("Paste a link to a public Git repository.")
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", text):
        text = f"https://github.com/{text}"
    if text.startswith("git@") or text.startswith("ssh://"):
        raise RepoError("Use the repository's https:// link, not the SSH one.")
    parts = urlsplit(text)
    if parts.scheme != "https":
        raise RepoError("Only https:// links are supported.")
    if parts.username or parts.password:
        raise RepoError("Links with a username or token aren't supported. Only public repositories can be scanned.")
    try:
        port = parts.port
    except ValueError:
        raise RepoError("That link has an invalid port.") from None
    if port not in (None, 443):
        raise RepoError("Only the standard https port is supported.")
    host = (parts.hostname or "").lower().rstrip(".")
    _check_public_host(host)

    segments = [s for s in parts.path.split("/") if s]
    ref = None
    if "tree" in segments:                                   # .../tree/<ref> (GitHub) or .../-/tree/<ref> (GitLab)
        at = segments.index("tree")
        ref = "/".join(segments[at + 1:]) or None
        segments = segments[:at]
        if segments and segments[-1] == "-":
            segments = segments[:-1]
    if len(segments) < 2:
        raise RepoError("Link to a repository, like https://github.com/owner/repo.")
    if segments[-1].endswith(".git"):
        segments[-1] = segments[-1][:-4]
    if not all(SEGMENT.match(s) for s in segments) or any(s in (".", "..") for s in segments):
        raise RepoError("That doesn't look like a repository path.")
    if ref is not None and (not REF.match(ref) or ".." in ref or ref.endswith((".lock", "/"))):
        raise RepoError("That branch name isn't supported.")
    return RepoLink(host, tuple(segments), ref)


def _check_public_host(host: str) -> None:
    if not host:
        raise RepoError("That link has no host name.")
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    else:
        raise RepoError("Use the Git host's name, not an IP address.")
    if host == "localhost" or host.endswith(PRIVATE_SUFFIXES) or not HOSTNAME.match(host):
        raise RepoError("Only public Git hosts (github.com, gitlab.com, ...) are supported.")


# ------------------------------------------------------------------ fetching
def git_available() -> bool:
    return shutil.which("git") is not None


GIT_CONFIG = [
    "-c", "core.hooksPath=/dev/null",          # never run hooks
    "-c", "core.symlinks=false",               # check symlinks out as plain files
    "-c", "protocol.allow=never",              # https only, including for redirects and submodules
    "-c", "protocol.https.allow=always",
    "-c", "credential.helper=",                # never use or prompt for saved credentials
    "-c", "submodule.recurse=false",
]


def _git_env() -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1", GIT_CONFIG_NOSYSTEM="1",
               GIT_ASKPASS="echo", SSH_ASKPASS="echo", GCM_INTERACTIVE="never")
    return env


def _git(args: list[str], cwd: Path | None, deadline: float) -> str:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RepoError("Downloading the repository took too long.")
    try:
        result = subprocess.run(["git", *GIT_CONFIG, *args], cwd=cwd, env=_git_env(), stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=remaining)
    except subprocess.TimeoutExpired:
        raise RepoError("Downloading the repository took too long. Try a smaller one.") from None
    if result.returncode:
        raise RepoError(_explain_git_error(result.stderr))
    return result.stdout


def _explain_git_error(stderr: str) -> str:
    text = stderr.strip()
    low = text.lower()
    if "not found" in low and "branch" in low:
        return "That branch or tag doesn't exist in the repository."
    if any(s in low for s in ("repository not found", "could not read username", "authentication failed",
                              "terminal prompts disabled", "returned error: 404", "access denied")):
        return "Repository not found, or it's private. Only public repositories can be scanned."
    if "could not resolve host" in low:
        return "Couldn't reach that host. Check the link and your internet connection."
    last = text.splitlines()[-1] if text else "unknown error"
    return f"git couldn't download the repository: {last[:200]}"


def python_paths(paths: list[str]) -> list[str]:
    """The .py files worth scanning, outside dependency and build folders, sorted."""
    keep = []
    for path in paths:
        parts = PurePosixPath(path).parts
        if path.endswith(".py") and parts and not any(p in SKIP_DIRS for p in parts[:-1]):
            keep.append(path)
    return sorted(keep)


def _sparse_pattern(path: str) -> str:
    # gitignore-style pattern that matches exactly this file
    return "/" + re.sub(r"([*?\[\\!#])", r"\\\1", path)


def clone_repo(link: RepoLink, dest: Path, deadline: float) -> dict:
    """Shallow, blobless clone that checks out only the Python files we'll scan."""
    args = ["clone", "--depth", "1", "--filter=blob:none", "--no-checkout", "--single-branch", "--no-tags"]
    if link.ref:
        args += ["--branch", link.ref]
    _git([*args, "--", link.url, str(dest)], None, deadline)
    tracked = _git(["ls-tree", "-r", "-z", "--name-only", "HEAD"], dest, deadline).split("\0")
    wanted = python_paths([p for p in tracked if p])
    over_limit = max(0, len(wanted) - MAX_PY_FILES)
    wanted = wanted[:MAX_PY_FILES]
    if wanted:
        _write_sparse_file(dest, wanted, deadline)
        _git(["checkout", "--quiet", "HEAD"], dest, deadline)   # downloads only the selected blobs
    commit = _git(["rev-parse", "HEAD"], dest, deadline).strip()
    branch = _git(["rev-parse", "--abbrev-ref", "HEAD"], dest, deadline).strip()
    return {"commit": commit, "ref": link.ref or (branch if branch != "HEAD" else None), "method": "git",
            "files_over_limit": over_limit}


def _write_sparse_file(dest: Path, paths: list[str], deadline: float) -> None:
    # `git sparse-checkout set --stdin` reads the patterns from stdin; feed it our exact paths.
    remaining = deadline - time.monotonic()
    try:
        result = subprocess.run(
            ["git", *GIT_CONFIG, "sparse-checkout", "set", "--no-cone", "--stdin"], cwd=dest, env=_git_env(),
            input="\n".join(_sparse_pattern(p) for p in paths) + "\n", capture_output=True, text=True,
            timeout=max(1, remaining))
    except subprocess.TimeoutExpired:
        raise RepoError("Downloading the repository took too long. Try a smaller one.") from None
    if result.returncode:
        raise RepoError(_explain_git_error(result.stderr))


def download_github_zip(link: RepoLink, dest: Path, deadline: float) -> dict:
    """GitHub's zip archive, for servers without git. Extracts only .py files, safely."""
    if link.host != "github.com" or len(link.path) != 2:
        raise RepoError("git isn't installed on this server, so only github.com/owner/repo links can be scanned.")
    owner, repo = link.path
    url = f"https://codeload.github.com/{owner}/{repo}/zip/{link.ref or 'HEAD'}"
    request = urllib.request.Request(url, headers={"User-Agent": "pwn2patch-repo-scan"})
    try:
        with urllib.request.urlopen(request, timeout=max(1, deadline - time.monotonic())) as response:
            if urlsplit(response.geturl()).hostname not in ("codeload.github.com", "github.com"):
                raise RepoError("GitHub redirected the download somewhere unexpected.")
            data = bytearray()
            while chunk := response.read(1 << 16):
                data += chunk
                if len(data) > MAX_ZIP_BYTES:
                    raise RepoError(f"The repository is larger than {MAX_ZIP_BYTES // (1 << 20)} MB.")
                if time.monotonic() > deadline:
                    raise RepoError("Downloading the repository took too long. Try a smaller one.")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise RepoError("Repository or branch not found, or it's private. "
                            "Only public repositories can be scanned.") from None
        raise RepoError(f"GitHub returned an error ({exc.code}).") from None
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RepoError(f"Couldn't download from GitHub: {getattr(exc, 'reason', exc)}") from None
    try:
        archive = zipfile.ZipFile(io.BytesIO(bytes(data)))
    except zipfile.BadZipFile:
        raise RepoError("GitHub sent a broken archive.") from None
    info = extract_python_files(archive, dest)
    commit = archive.comment.decode("ascii", "ignore").strip() or None
    return {"commit": commit, "ref": link.ref, "method": "zip", **info}


def extract_python_files(archive: zipfile.ZipFile, dest: Path) -> dict:
    """Extract the scannable .py members. Rejects absolute paths, `..`, symlinks and oversized files."""
    members: dict[str, zipfile.ZipInfo] = {}
    for info in archive.infolist():
        if info.is_dir() or (info.external_attr >> 16) & 0o170000 == 0o120000:   # directory or symlink
            continue
        parts = PurePosixPath(info.filename.replace("\\", "/")).parts[1:]       # drop "<repo>-<sha>/"
        if not parts or any(p in ("", ".", "..") or ":" in p for p in parts) or info.filename.startswith("/"):
            continue
        members["/".join(parts)] = info
    wanted = python_paths(list(members))
    over_limit = max(0, len(wanted) - MAX_PY_FILES)
    root = dest.resolve()
    for path in wanted[:MAX_PY_FILES]:
        target = (dest / path).resolve()
        if root not in target.parents:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(members[path]) as src:
            target.write_bytes(src.read(MAX_FILE_BYTES + 1))   # never trust the header's size
    return {"files_over_limit": over_limit}


# ------------------------------------------------------------------ scanning
def list_python_files(root: Path) -> list[str]:
    """Relative paths of the .py files on disk, skipping symlinks and dependency folders."""
    found = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in filenames:
            path = Path(dirpath, name)
            if name.endswith(".py") and not path.is_symlink():
                found.append(path.relative_to(root).as_posix())
    return python_paths(found)


def read_source(path: Path) -> tuple[str | None, str | None]:
    """(source, None), or (None, reason it was skipped)."""
    data = path.read_bytes()[:MAX_FILE_BYTES + 1]
    if len(data) > MAX_FILE_BYTES:
        return None, f"larger than {MAX_FILE_BYTES // 1000} KB"
    try:
        return data.decode("utf-8-sig").replace("\r\n", "\n"), None
    except UnicodeDecodeError:
        return None, "not UTF-8 text"


def summarize_file(path: str, report: dict) -> dict:
    if not report["ok"] and report["error"]["type"] == "empty":   # e.g. an empty __init__.py: nothing to check
        return {"path": path, "ok": True, "empty": True, "lines": 0, "code_lines": 0, "score": 100, "grade": "A",
                "gate": "PASS", "findings": 0, "worst": None, "severity_counts": {sev: 0 for sev in SEVERITIES},
                "categories": {}, "rules": {}, "cwes": []}
    if not report["ok"]:
        error = report["error"]
        return {"path": path, "ok": False, "error": error["message"], "error_line": error.get("line"),
                "gate": "FAIL"}
    findings = report["findings"]
    worst = next((sev for sev in SEVERITIES if report["severity_counts"][sev]), None)
    return {
        "path": path, "ok": True,
        "lines": report["stats"]["lines"], "code_lines": report["stats"]["code_lines"],
        "score": report["score"], "grade": report["grade"], "gate": report["gate"]["status"],
        "findings": len(findings), "worst": worst,
        "severity_counts": report["severity_counts"],
        "categories": {name: c["score"] for name, c in report["categories"].items()},
        "rules": dict(Counter(f["rule_id"] for f in findings)),
        "cwes": sorted({f["cwe"][0]["id"] for f in findings if f["cwe"]}),
    }


def summarize_repo(files: list[dict], skipped: list[dict]) -> dict:
    """Roll the per-file results up into repo totals. The repo score weights files by code lines."""
    ok = [f for f in files if f["ok"]]
    weighted = [f for f in ok if f["code_lines"] > 0]          # empty files don't move the score
    weight = sum(f["code_lines"] for f in weighted)
    score = round(sum(f["score"] * f["code_lines"] for f in weighted) / weight) if weighted else None
    severity = Counter()
    rules: dict[str, dict] = {}
    for f in ok:
        severity.update(f["severity_counts"])
        for rule_id, count in f["rules"].items():
            row = rules.setdefault(rule_id, {"rule_id": rule_id, "title": RULES[rule_id].title,
                                             "severity": RULES[rule_id].severity,
                                             "category": RULES[rule_id].category, "count": 0, "files": 0})
            row["count"] += count
            row["files"] += 1
    rank = {sev: i for i, sev in enumerate(SEVERITIES)}
    return {
        "score": score,
        "grade": grade_for(score) if score is not None else None,
        "files_scanned": len(files),
        "files_passing": sum(1 for f in files if f["gate"] == "PASS"),
        "files_unparsable": len(files) - len(ok),
        "files_skipped": len(skipped),
        "lines": sum(f["lines"] for f in ok),
        "findings": sum(f["findings"] for f in ok),
        "severity_counts": {sev: severity[sev] for sev in SEVERITIES},
        "rules": sorted(rules.values(), key=lambda r: (rank[r["severity"]], -r["count"], r["rule_id"])),
    }


# ------------------------------------------------------------------ jobs
@dataclass
class RepoJob:
    id: str
    link: RepoLink
    workdir: Path
    state: str = "queued"          # queued -> fetching -> scanning -> done | error
    message: str = "Waiting to start…"
    done: int = 0
    total: int = 0
    error: str | None = None
    started: float = field(default_factory=time.time)
    meta: dict = field(default_factory=dict)
    files: list[dict] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)
    summary: dict | None = None

    @property
    def root(self) -> Path:
        """Where the repository's files are checked out."""
        return self.workdir / "src"

    def to_dict(self) -> dict:
        data = {"id": self.id, "state": self.state, "message": self.message, "repo": self.link.to_dict(),
                "progress": {"done": self.done, "total": self.total}}
        if self.state == "error":
            data["error"] = self.error
        if self.state == "done":
            data.update(commit=self.meta.get("commit"), ref=self.meta.get("ref"), method=self.meta.get("method"),
                        files=self.files, skipped=self.skipped, summary=self.summary,
                        files_over_limit=self.meta.get("files_over_limit", 0), max_files=MAX_PY_FILES)
        return data


class RepoStore:
    """Runs scans in background threads and keeps the last few on disk for the code browser."""

    def __init__(self, policy: dict, base: Path | None = None, fetch=None):
        self.policy = policy
        self.base = Path(base or tempfile.mkdtemp(prefix="pwn2patch-repos-"))
        self.jobs: OrderedDict[str, RepoJob] = OrderedDict()
        self.lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(MAX_CONCURRENT_SCANS)
        self.fetch = fetch or self._fetch
        atexit.register(self.close)

    def start(self, text: str) -> RepoJob:
        link = parse_repo_link(text)
        with self.lock:
            for job in reversed(self.jobs.values()):
                if job.link == link and job.state != "error" and time.time() - job.started < CACHE_SECONDS:
                    self.jobs.move_to_end(job.id)
                    return job
            job = RepoJob(uuid.uuid4().hex[:12], link, self.base / uuid.uuid4().hex[:12])
            self.jobs[job.id] = job
            self._evict()
        threading.Thread(target=self._run, args=(job,), daemon=True, name=f"repo-{job.id}").start()
        return job

    def get(self, job_id: str) -> RepoJob | None:
        with self.lock:
            return self.jobs.get(job_id)

    def read_file(self, job_id: str, path: str) -> str:
        job = self.get(job_id)
        if job is None or job.state != "done":
            raise KeyError("scan not found")
        if path not in {f["path"] for f in job.files}:      # only files we scanned, so no path tricks
            raise KeyError("file not found")
        target = (job.root / path).resolve()
        if job.root.resolve() not in target.parents:
            raise KeyError("file not found")
        source, _ = read_source(target)
        if source is None:
            raise KeyError("file not readable")
        return source

    def _evict(self) -> None:
        finished = [j for j in self.jobs.values() if j.state in ("done", "error")]
        for job in finished[:max(0, len(self.jobs) - MAX_REPOS_KEPT)]:
            del self.jobs[job.id]
            shutil.rmtree(job.workdir, ignore_errors=True)

    def _fetch(self, link: RepoLink, dest: Path, deadline: float) -> dict:
        if git_available():
            return clone_repo(link, dest, deadline)
        return download_github_zip(link, dest, deadline)

    def _run(self, job: RepoJob) -> None:
        with self.slots:
            try:
                job.state, job.message = "fetching", f"Downloading {job.link.name}…"
                job.workdir.mkdir(parents=True, exist_ok=True)
                job.meta = self.fetch(job.link, job.root, time.monotonic() + FETCH_TIMEOUT)
                root = job.root
                paths = list_python_files(root)
                job.state, job.total = "scanning", len(paths)
                job.message = f"Analyzing {len(paths)} Python file{'s' if len(paths) != 1 else ''}…"
                for path in paths:
                    source, reason = read_source(root / path)
                    if source is None:
                        job.skipped.append({"path": path, "reason": reason})
                    else:
                        job.files.append(summarize_file(path, analyze(source, self.policy, patches=False)))
                    job.done += 1
                job.summary = summarize_repo(job.files, job.skipped)
                job.state = "done"
                job.message = (f"Scanned {len(job.files)} Python files" if job.files
                               else "No Python files found in this repository")
            except RepoError as exc:
                job.state, job.error, job.message = "error", str(exc), str(exc)
            except Exception as exc:   # noqa: BLE001 - report anything unexpected instead of hanging the UI
                job.state, job.error = "error", f"Scan failed: {type(exc).__name__}"
                job.message = job.error
            if job.state == "error":
                shutil.rmtree(job.workdir, ignore_errors=True)

    def close(self) -> None:
        shutil.rmtree(self.base, ignore_errors=True)
