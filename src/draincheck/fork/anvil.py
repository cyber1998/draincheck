# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Start and stop a local anvil node, optionally forking Base at a pinned block.

The node always listens on 127.0.0.1. It forks only when the upstream URL is supplied
through the ``DRAINCHECK_FORK_URL`` environment variable; Draincheck never hard-codes an
upstream URL and never opens a connection to it itself (anvil does). A forked node runs
with the anvil dev chain id (31337), not Base's, so signed transactions cannot be replayed
on Base. Some off-chain signatures (contracts with a cached 8453 domain separator,
personal_sign) carry no such protection, which is one more reason only anvil's published
dev keys ever sign anything in the sandbox.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from types import TracebackType
from typing import Any

import httpx

from draincheck.safety import assert_local_rpc

ANVIL_CHAIN_ID = 31337
BASE_CHAIN_ID = 8453
FORK_URL_ENV = "DRAINCHECK_FORK_URL"
FORK_BLOCK_ENV = "DRAINCHECK_FORK_BLOCK"
# Pinned Base mainnet block so forked runs are reproducible. Override with
# DRAINCHECK_FORK_BLOCK or the `fork_block` argument.
DEFAULT_BASE_FORK_BLOCK = 30_000_000


class AnvilNotFoundError(RuntimeError):
    """Raised when the anvil binary is not on PATH."""


class ForkNotConfiguredError(RuntimeError):
    """Raised when a fork is requested but DRAINCHECK_FORK_URL is not set."""


class RPCError(RuntimeError):
    """Raised when the local node answers a JSON-RPC call with an error."""


def find_anvil() -> str | None:
    """Return the path to the anvil binary, or None if it is not installed."""
    return shutil.which("anvil")


def free_port() -> int:
    """Return a TCP port on 127.0.0.1 that is free right now."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


def fork_url_from_env() -> str | None:
    """Return the upstream fork URL from DRAINCHECK_FORK_URL, or None if unset or empty."""
    value = os.environ.get(FORK_URL_ENV, "").strip()
    return value or None


def _default_fork_block() -> int:
    raw = os.environ.get(FORK_BLOCK_ENV, "").strip()
    if not raw:
        return DEFAULT_BASE_FORK_BLOCK
    try:
        block = int(raw)
    except ValueError:
        raise ValueError(f"{FORK_BLOCK_ENV} must be a positive integer, got {raw!r}") from None
    if block <= 0:
        raise ValueError(f"{FORK_BLOCK_ENV} must be a positive integer, got {raw!r}")
    return block


def _anvil_env() -> dict[str, str]:
    """The parent environment minus variables anvil could use to pick its own upstream.

    The fork URL must reach anvil only through --fork-url, built from DRAINCHECK_FORK_URL.
    """
    return {
        key: value
        for key, value in os.environ.items()
        if key not in {"ETH_RPC_URL", FORK_URL_ENV} and not key.startswith(("FOUNDRY_", "ANVIL_"))
    }


class AnvilProcess:
    """A local anvil node bound to 127.0.0.1, usable as a context manager.

    Args:
        port: Local port; a free one is picked if omitted.
        startup_timeout: Seconds to wait for the node to answer. Forks get at least 60s.
        fork: True to require a Base fork (needs DRAINCHECK_FORK_URL), False for a plain
            local chain, None (default) to fork only if DRAINCHECK_FORK_URL is set.
        fork_block: Base block to fork at. Defaults to DRAINCHECK_FORK_BLOCK, then
            DEFAULT_BASE_FORK_BLOCK.
    """

    def __init__(
        self,
        port: int | None = None,
        startup_timeout: float = 15.0,
        *,
        fork: bool | None = None,
        fork_block: int | None = None,
    ) -> None:
        self.port = port if port is not None else free_port()
        self.rpc_url = assert_local_rpc(f"http://127.0.0.1:{self.port}")
        upstream = fork_url_from_env()
        if fork is True and upstream is None:
            raise ForkNotConfiguredError(f"a Base fork was requested but {FORK_URL_ENV} is not set")
        self._fork_url = upstream if fork is not False else None
        self.fork_block: int | None = None
        if self._fork_url is not None:
            self.fork_block = fork_block if fork_block is not None else _default_fork_block()
            startup_timeout = max(startup_timeout, 60.0)
        self.startup_timeout = startup_timeout
        self._proc: subprocess.Popen[bytes] | None = None
        self._rpc_id = 0

    @property
    def is_fork(self) -> bool:
        """True if this node forks Base rather than starting from an empty chain."""
        return self._fork_url is not None

    def _argv(self, binary: str) -> list[str]:
        argv = [
            binary,
            "--host",
            "127.0.0.1",
            "--port",
            str(self.port),
            "--chain-id",
            str(ANVIL_CHAIN_ID),
            "--silent",
        ]
        if self._fork_url is not None:
            # The URL comes only from DRAINCHECK_FORK_URL. anvil, not Draincheck, talks to it.
            argv += ["--fork-url", self._fork_url, "--fork-block-number", str(self.fork_block)]
        return argv

    def start(self) -> AnvilProcess:
        binary = find_anvil()
        if binary is None:
            raise AnvilNotFoundError(
                "anvil is not on PATH. Install Foundry: https://book.getfoundry.sh/getting-started/installation"
            )
        self._proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            self._argv(binary),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=_anvil_env(),
        )
        self._wait_until_ready()
        return self

    def _wait_until_ready(self) -> None:
        deadline = time.monotonic() + self.startup_timeout
        body = {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}
        while time.monotonic() < deadline:
            if self._proc is not None and self._proc.poll() is not None:
                raise RuntimeError(f"anvil exited early with code {self._proc.returncode}")
            try:
                if httpx.post(self.rpc_url, json=body, timeout=1.0).status_code == 200:
                    return
            except httpx.TransportError:
                pass
            time.sleep(0.1)
        self.stop()
        raise TimeoutError(f"anvil did not answer on {self.rpc_url} within {self.startup_timeout}s")

    def rpc(self, method: str, params: list[Any] | None = None) -> Any:
        """Call a JSON-RPC method on the local node and return its result."""
        self._rpc_id += 1
        body = {"jsonrpc": "2.0", "id": self._rpc_id, "method": method, "params": params or []}
        response = httpx.post(assert_local_rpc(self.rpc_url), json=body, timeout=30.0)
        response.raise_for_status()
        data = response.json()
        if "error" in data:
            raise RPCError(f"{method} failed: {data['error']}")
        return data["result"]

    def snapshot(self) -> str:
        """Take an evm_snapshot of the whole chain state and return its id."""
        snapshot_id = self.rpc("evm_snapshot")
        if not isinstance(snapshot_id, str):
            raise RPCError(f"evm_snapshot returned {snapshot_id!r}")
        return snapshot_id

    def revert(self, snapshot_id: str) -> None:
        """Restore the chain to `snapshot_id`. anvil deletes the snapshot when it is used."""
        if self.rpc("evm_revert", [snapshot_id]) is not True:
            raise RPCError(f"evm_revert could not restore snapshot {snapshot_id}")

    @contextmanager
    def isolated(self) -> Iterator[str]:
        """Snapshot on entry and revert on exit, even if the body raises."""
        snapshot_id = self.snapshot()
        try:
            yield snapshot_id
        finally:
            self.revert(snapshot_id)

    def stop(self) -> None:
        if self._proc is None:
            return
        self._proc.terminate()
        try:
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait()
        self._proc = None

    def __enter__(self) -> AnvilProcess:
        return self.start()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.stop()
