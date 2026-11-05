# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Guards that keep every chain connection on the local machine.

Draincheck only ever talks to a local anvil node. Every component that opens an RPC
connection must pass its URL through :func:`assert_local_rpc` first, and should build its
client with :func:`local_web3` or :func:`local_http_client`: a proxy set in the
environment or the system settings would otherwise carry "local" traffic off the machine.
"""

from __future__ import annotations

import ipaddress
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import httpx
import requests
from web3 import Web3

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


def local_web3(rpc_url: str, timeout: float = 30.0) -> Web3:
    """A Web3 client for a local node that ignores proxies and never follows redirects.

    requests (under web3) reads proxies from the environment and system settings even for
    127.0.0.1, including host-keyed ``<url>_proxy`` variables, so the session is built with
    ``trust_env`` off rather than by overriding single keys.
    """
    session = requests.Session()
    session.trust_env = False
    provider = Web3.HTTPProvider(
        assert_local_rpc(rpc_url),
        session=session,
        request_kwargs={"allow_redirects": False, "timeout": timeout},
    )
    return Web3(provider)


def local_http_client(**kwargs: Any) -> httpx.Client:
    """An httpx client for local services that ignores proxies and never follows redirects.

    Callers still check each URL with :func:`assert_local_rpc` or
    :func:`assert_local_service`.
    """
    return httpx.Client(trust_env=False, follow_redirects=False, **kwargs)


class NonDevKeyError(ValueError):
    """Raised when a key is not one of anvil's published dev keys."""


def assert_dev_key(private_key: str, address: str | None = None) -> str:
    """Return `private_key` if it belongs to one of anvil's ten default accounts.

    Checked by the address it signs for, so no key needs to be listed here. With
    `address`, the key must also be that account's.
    """
    from eth_account import Account

    from draincheck.fork.accounts import ANVIL_ADDRESSES

    try:
        signer = Account.from_key(private_key).address
    except (ValueError, TypeError) as err:
        raise NonDevKeyError("agent key is not a valid private key") from err
    if signer not in ANVIL_ADDRESSES:
        raise NonDevKeyError("Draincheck only signs with anvil's published dev keys")
    if address is not None:
        try:
            expected = Web3.to_checksum_address(address)
        except (ValueError, TypeError) as err:
            raise NonDevKeyError(f"{address!r} is not an address") from err
        if expected != signer:
            raise NonDevKeyError(f"agent key signs for {signer}, not {address}")
    return private_key
