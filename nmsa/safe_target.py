"""Strict loopback-only API fixture target and path validation.

Reject hostnames (even localhost), IPv6 ambiguity, percent-encoding,
query strings, redirects in route specifications, and unknown spec keys.
The network connection uses only the literal IPv4 loopback address.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

ROUTE = re.compile(r"/(?:[A-Za-z0-9_.~/-]{0,250})\Z")


def validate_fixture_origin(value):
    if not isinstance(value, str):
        raise ValueError("Origin must be string")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid origin or port") from exc
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
            or parsed.netloc != f"127.0.0.1:{port}"
            or parsed.path not in ("", "/")
            or parsed.query or parsed.fragment or parsed.username or parsed.password
            or port is None or not 1 <= port <= 65535):
        raise ValueError("Only literal http://127.0.0.1:PORT permitted")
    return "127.0.0.1", port


def validate_fixture_path(path):
    if not isinstance(path, str) or not ROUTE.fullmatch(path):
        raise ValueError("Fixture route must be a plain, path-only absolute URL path")
    if path.startswith("//") or any(part in (".", "..") for part in path.split("/")):
        raise ValueError("Fixture route traversal or double slash is forbidden")
    return path
