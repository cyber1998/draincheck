# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Guards that keep every chain connection on the local machine.

Draincheck only ever talks to a local anvil node. Every component that opens an RPC
connection must pass its URL through :func:`assert_local_rpc` first.
"""

from __future__ import annotations

import ipaddress
import tempfile
from pathlib import Path
from urllib.parse import unquote, urlsplit

ALLOWED_SCHEMES = frozenset({"http", "https", "ws", "wss"})


class NonLocalRPCError(ValueError):
    """Raised when an RPC URL points anywhere other than this machine."""


def is_local_host(host: str) -> bool:
    """Return True if `host` is localhost or a loopback IP address."""
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def assert_local_rpc(url: str) -> str:
    """Return `url` unchanged if it points at this machine, else raise NonLocalRPCError."""
    parts = urlsplit(url)
    if parts.scheme not in ALLOWED_SCHEMES:
        raise NonLocalRPCError(f"RPC URL must use http(s) or ws(s), got {url!r}")
    host = parts.hostname or ""
    if not is_local_host(host):
        raise NonLocalRPCError(
            f"Draincheck only connects to a local node (127.0.0.1 / localhost), got {host!r}"
        )
    return url


def assert_local_service(url: str) -> str:
    """Like :func:`assert_local_rpc`, but also allows a ``file://`` path on this machine.

    Entry points hand agents local services (an HTTP endpoint on 127.0.0.1) or local files
    (a memory store). A file URL must name no host and an absolute path.
    """
    parts = urlsplit(url)
    if parts.scheme == "file":
        # Windows reads backslashes as separators, and "//host/share" as a network share.
        path = unquote(parts.path).replace("\\", "/")
        if parts.netloc not in ("", "localhost") or not path.startswith("/") or "//" in path:
            raise NonLocalRPCError(f"file URL must be an absolute local path, got {url!r}")
        # Draincheck only hands out files it made in the temp directory. That also rules
        # out automounted network paths such as macOS's /net/<host>.
        temp = Path(tempfile.gettempdir()).resolve()
        if not Path(path).resolve().is_relative_to(temp):
            raise NonLocalRPCError(f"file URL must be inside {temp}, got {url!r}")
        return url
    return assert_local_rpc(url)
