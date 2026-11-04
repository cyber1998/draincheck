# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Guards that keep every chain connection on the local machine.

Draincheck only ever talks to a local anvil node. Every component that opens an RPC
connection must pass its URL through :func:`assert_local_rpc` first.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

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
