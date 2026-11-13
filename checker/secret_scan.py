"""Secret detection that doesn't trust variable names.

Renaming `API_KEY` to `x` doesn't make the key any less secret, so the analyzer
uses three independent signals:

1. Name     - the variable/argument/key is called something like `api_key` (analyzer.py).
2. Value    - the string itself looks like a secret (this module):
                * it matches a provider's key format (GitHub, AWS, Stripe, ...), or
                * it is a long, random-looking token (high Shannon entropy).
3. Usage    - a hardcoded value flows into a credential sink such as an
              `Authorization` header, `password=`, `auth=(user, pw)` or `smtp.login()`
              (analyzer.py, using `credential_part` / `is_plausible_credential` from here).

Known formats and usage are strong evidence (rule SEC004, high). Entropy alone is
weaker, since hashes and IDs are random-looking too, so it reports SEC009 (medium).
"""
from __future__ import annotations

import ast
import math
import re
from collections import Counter
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretMatch:
    kind: str              # "format" (known provider format) or "entropy" (random-looking)
    label: str             # e.g. "GitHub token"
    is_password: bool = False


# Public, well-documented token formats (the same idea as gitleaks / GitHub secret scanning).
# Order matters where formats overlap: Anthropic keys also match the generic `sk-` pattern.
KNOWN_FORMATS: list[tuple[str, re.Pattern, bool]] = [
    ("private key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"), False),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"), False),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"), False),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"), False),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"), False),
    ("Slack webhook URL", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}"), False),
    ("Stripe secret key", re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}"), False),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}"), False),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"), False),
    ("OpenAI-style API key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}"), False),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}"), False),
    ("SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"), False),
    ("Twilio API key", re.compile(r"\bSK[0-9a-f]{32}\b"), False),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), False),
    ("PyPI token", re.compile(r"\bpypi-[A-Za-z0-9_-]{50,}"), False),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), False),
    # scheme://user:password@host  (the password group is checked against placeholders below)
    ("password in a connection URL",
     re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@{}%$<>]+:([^\s/@{}%$<>]{3,})@"), True),
]

PLACEHOLDERS = {
    "bearer", "basic", "token", "password", "passwd", "pass", "pwd", "secret", "api_key", "apikey",
    "your_api_key", "your-api-key", "your_token", "your-token", "username", "user", "none", "null",
    "example", "dummy", "redacted",
}
TEMPLATE = re.compile(r"[{}<>]|%s|%\(|\$\{|\$[A-Z_]")       # "{token}", "<KEY>", "${API_KEY}", "%s"
AUTH_SCHEME = re.compile(r"^(?:bearer|basic|token|digest|apikey|api-key)\s+", re.IGNORECASE)

# Entropy heuristics. Random keys are long, mix upper/lower/digits, and have a long
# unbroken alphanumeric run. Readable strings (identifiers, paths, model names like
# "sentence-transformers/all-MiniLM-L6-v2") are broken into short segments.
TOKEN_SPLIT = re.compile(r"[\s'\"`,;()\[\]{}<>|\\]+")
B64_CHARS = re.compile(r"^[A-Za-z0-9+/=_-]+$")
HEX_CHARS = re.compile(r"^(?:[0-9a-f]+|[0-9A-F]+)$")
SEGMENT_SPLIT = re.compile(r"[/_.+=:-]+")
UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
DIGEST_HEX_LENGTHS = {32, 40, 56, 64, 96, 128}  # md5, sha1, sha224, sha256, sha384, sha512
MIN_TOKEN, MAX_TOKEN, MIN_RUN = 20, 512, 16


def shannon_entropy(text: str) -> float:
    """Bits per character. English words score ~3-3.5; random base64 keys score 4.5+."""
    counts, total = Counter(text), len(text)
    return -sum(n / total * math.log2(n / total) for n in counts.values()) if total else 0.0


def _char_class(c: str) -> str:
    return "d" if c.isdigit() else "l" if c.islower() else "u" if c.isupper() else "s"


def class_switch_ratio(token: str) -> float:
    """How often the character type (lower/upper/digit/symbol) changes from one char to the next.

    Random keys flip constantly (~0.45-0.65); words and CamelCase names only flip at
    word boundaries (~0.1-0.25), e.g. "MyCustomAuthenticationBackend1".
    """
    if len(token) < 2:
        return 0.0
    classes = [_char_class(c) for c in token]
    return sum(a != b for a, b in zip(classes, classes[1:])) / (len(token) - 1)


CAMEL_WORD = re.compile(r"[A-Z]?[a-z]{3,}")


def wordiness(token: str) -> float:
    """Share of the token made of Capitalized words. CamelCase names score 0.65+, random keys ~0.2."""
    return sum(len(w) for w in CAMEL_WORD.findall(token)) / len(token) if token else 0.0


def random_looking_token(text: str) -> str | None:
    """The first token in `text` that looks like a random key, or None."""
    for token in TOKEN_SPLIT.split(text):
        if not MIN_TOKEN <= len(token) <= MAX_TOKEN or UUID.match(token) or not B64_CHARS.match(token):
            continue
        if max(len(seg) for seg in SEGMENT_SPLIT.split(token)) < MIN_RUN:
            continue  # structured text: paths, model names, long_snake_identifiers
        if class_switch_ratio(token) < 0.3:
            continue  # readable: words, CamelCase, "abc...xyz0123..."
        entropy = shannon_entropy(token)
        has_digit = any(c.isdigit() for c in token)
        has_lower = any(c.islower() for c in token)
        has_upper = any(c.isupper() for c in token)
        if has_upper and has_lower and wordiness(token) >= 0.6:
            continue  # CamelCase names like "ResNet50ImageClassifierV2Large"
        if HEX_CHARS.match(token):
            if len(token) >= 32 and has_digit and (has_lower or has_upper) and entropy >= 3.0:
                return token
        elif has_digit and has_lower and has_upper and entropy >= 3.9:
            return token
        elif has_digit and (has_lower or has_upper) and len(token) >= 24 and entropy >= 3.9:
            return token
    return None


def is_hash_digest(token: str) -> bool:
    return bool(HEX_CHARS.match(token)) and len(token) in DIGEST_HEX_LENGTHS


def classify_secret(text: str) -> SecretMatch | None:
    """Does this string look like a secret on its own, regardless of what it's called?"""
    for label, pattern, is_password in KNOWN_FORMATS:
        match = pattern.search(text)
        if match and not (is_password and is_placeholder(match.group(1))):
            return SecretMatch("format", label, is_password)
    token = random_looking_token(text)
    if token:
        return SecretMatch("entropy", f"random-looking {len(token)}-character string")
    return None


def is_placeholder(text: str) -> bool:
    t = text.strip().lower()
    return t in PLACEHOLDERS or len(set(t)) <= 2 or bool(TEMPLATE.search(text))


def credential_part(text: str) -> str:
    """'Bearer abc123' -> 'abc123'."""
    return AUTH_SCHEME.sub("", text.strip())


def is_plausible_credential(text: str) -> bool:
    """Could this hardcoded value really be a credential (not empty, a placeholder or a template)?"""
    cred = credential_part(text)
    return len(cred) >= 6 and not any(ch.isspace() for ch in cred) and not is_placeholder(cred)


def fold_str(node: ast.AST | None) -> str | None:
    """The string value of a constant expression: "a", b"a", "a" + "b", f"ab". None if it's dynamic.

    Folding catches keys split up to dodge scanners, e.g. "ghp_" + "abc...".
    """
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            return node.value
        if isinstance(node.value, bytes):
            return node.value.decode("latin-1")
        return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = fold_str(node.left), fold_str(node.right)
        return left + right if left is not None and right is not None else None
    if isinstance(node, ast.JoinedStr):
        parts = [fold_str(v) if isinstance(v, ast.Constant) else None for v in node.values]
        return "".join(parts) if all(p is not None for p in parts) else None
    return None
