"""Order service: the same features as bad_example.py, written to pass the policy."""
from __future__ import annotations

import ast
import hashlib
import json
import logging
import os
import re
import secrets
import sqlite3
import subprocess
from dataclasses import dataclass

import requests
from flask import Flask, abort, request

logger = logging.getLogger(__name__)
app = Flask(__name__)

DB_PATH = os.environ.get("APP_DB", "app.db")
API_KEY = os.environ.get("API_KEY", "")
HOSTNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}")
ALLOWED_COMMANDS = {"uptime": ["uptime"], "disk": ["df", "-h"]}
COUPON_DISCOUNT = {"HACKNIGHT": 0.8}


@dataclass
class Order:
    """A customer order: line items plus shipping options."""

    items: list[dict]
    region: str
    express: bool = False
    coupon: str | None = None


def get_user(conn: sqlite3.Connection, username: str) -> tuple | None:
    """Return the user row for `username`, or None if there is no such user."""
    cursor = conn.execute("SELECT id, name FROM users WHERE name = ?", (username,))
    return cursor.fetchone()


def ping_host(host: str) -> bool:
    """Ping a host once and report whether it answered."""
    if not HOSTNAME.fullmatch(host):
        raise ValueError(f"Not a valid host name: {host!r}")
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, check=False, timeout=5)
    return result.returncode == 0


def hash_password(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """Hash a password with scrypt and a random salt. Returns (salt, digest)."""
    salt = salt or secrets.token_bytes(16)
    return salt, hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)


def load_session(data: str) -> dict:
    """Load a session that was stored as JSON."""
    return json.loads(data)


def parse_value(text: str) -> object:
    """Safely parse a Python literal such as a number, list or dict."""
    return ast.literal_eval(text)


def fetch_report(url: str, items: list[str] | None = None) -> list[str]:
    """Download a report and append its text to `items`."""
    items = [] if items is None else items
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    items.append(response.text)
    return items


def save_log(message: str, path: str = "app.log") -> None:
    """Append one line to the application log file."""
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"[{os.getpid()}] {message}\n")


def item_total(item: dict, region: str, express: bool) -> float:
    """Price of one line item, including regional tax and shipping."""
    subtotal = item["price"] * item["qty"]
    if region == "EU":
        return subtotal * 1.2
    if region == "US":
        return subtotal + (15 if express else 5)
    return subtotal


def order_total(order: Order) -> float:
    """Total for an order, applying a coupon discount when there is one."""
    total = sum(item_total(i, order.region, order.express) for i in order.items if i["qty"] > 0)
    discount = COUPON_DISCOUNT.get(order.coupon or "", 1.0)
    logger.info("Order total %.2f (discount %.0f%%)", total, (1 - discount) * 100)
    return total * discount


def run_command(name: str) -> str:
    """Run one of a fixed set of diagnostic commands by name."""
    args = ALLOWED_COMMANDS.get(name)
    if args is None:
        raise ValueError(f"Unknown command: {name}")
    return subprocess.run(args, capture_output=True, text=True, check=True, timeout=10).stdout


@app.route("/run")
def run_endpoint() -> str:
    """HTTP endpoint for the allowlisted diagnostic commands."""
    try:
        return run_command(request.args.get("cmd", ""))
    except ValueError:
        abort(400)


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
