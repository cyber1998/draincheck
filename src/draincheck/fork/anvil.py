# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Start and stop a local anvil node, optionally forking Base at a pinned block.

The node always listens on 127.0.0.1 and always reports chain id 31337, even when it forks
Base, so a signature made in the sandbox can never be replayed on the real network.

The upstream URL for a fork comes only from the ``DRAINCHECK_FORK_URL`` environment
variable. Draincheck never connects to it itself: it hands it to the anvil process, which
reads state from it. Every connection Draincheck opens goes to the local node.
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
from urllib.parse import urlsplit

import httpx
from web3 import Web3

from draincheck.safety import assert_local_rpc

ANVIL_CHAIN_ID = 31337
FORK_URL_ENV = "DRAINCHECK_FORK_URL"
FORK_BLOCK_ENV = "DRAINCHECK_FORK_BLOCK"
BASE_CHAIN_ID = 8453
# A Base mainnet block from May 2025. Pinned so every fork run sees the same state.
BASE_FORK_BLOCK = 30_000_000


class AnvilNotFoundError(RuntimeError):
    """Raised when the anvil binary is not on PATH."""


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
    """Return the upstream fork URL from ``DRAINCHECK_FORK_URL``, or None if unset.

    The value is never logged or put in an error message: it may carry an API key.
    """
    url = os.environ.get(FORK_URL_ENV, "").strip()
    if not url:
        return None
    if urlsplit(url).scheme not in {"http", "https", "ws", "wss"}:
        raise ValueError(f"{FORK_URL_ENV} must be an http(s) or ws(s) URL")
    return url


def fork_block_from_env() -> int:
    """Return the pinned fork block: ``DRAINCHECK_FORK_BLOCK`` if set, else the default."""
    raw = os.environ.get(FORK_BLOCK_ENV, "").strip()
    if not raw:
        return BASE_FORK_BLOCK
    block = int(raw)
    if block <= 0:
        raise ValueError(f"{FORK_BLOCK_ENV} must be a positive block number")
    return block


def anvil_env() -> dict[str, str]:
    """The environment for the anvil process, minus Foundry/anvil settings.

    Only the argv decides whether anvil forks and which chain id it reports, so a stray
    variable in the user's shell cannot change that behind :attr:`AnvilProcess.is_fork`.
    """
    return {k: v for k, v in os.environ.items() if not k.startswith(("ETH_", "ANVIL_", "FOUNDRY_"))}


def rpc_call(rpc_url: str, method: str, params: list[Any] | None = None) -> Any:
    """Send one JSON-RPC request to a local node and return its ``result``."""
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}
    response = httpx.post(assert_local_rpc(rpc_url), json=body, timeout=30.0)
    response.raise_for_status()
    payload = response.json()
    if "error" in payload:
        raise RPCError(f"{method} failed: {payload['error']}")
    return payload.get("result")


class AnvilProcess:
    """A local anvil node bound to 127.0.0.1, usable as a context manager.

    With ``fork=False`` (the default) it starts an empty local chain. With ``fork=True`` it
    forks Base at ``fork_block`` if ``DRAINCHECK_FORK_URL`` is set, and falls back to an
    empty local chain if it is not. Check :attr:`is_fork` to see which one you got.
    """

    def __init__(
        self,
        port: int | None = None,
        startup_timeout: float | None = None,
        *,
        fork: bool = False,
        fork_block: int | None = None,
    ) -> None:
        self.port = port if port is not None else free_port()
        self.rpc_url = assert_local_rpc(f"http://127.0.0.1:{self.port}")
        self._fork_url = fork_url_from_env() if fork else None
        self.fork_block: int | None = None
        if self._fork_url is not None:
            self.fork_block = fork_block if fork_block is not None else fork_block_from_env()
        if startup_timeout is None:
            startup_timeout = 60.0 if self._fork_url else 15.0
        self.startup_timeout = startup_timeout
        self._proc: subprocess.Popen[bytes] | None = None
        self._w3: Web3 | None = None

    @property
    def is_fork(self) -> bool:
        """True if this node forks Base, False if it is an empty local chain."""
        return self._fork_url is not None

    def _argv(self, binary: str) -> list[str]:
        argv = [binary, "--host", "127.0.0.1", "--port", str(self.port), "--silent"]
        # Always 31337, also when forking: sandbox signatures must not replay on Base.
        argv += ["--chain-id", str(ANVIL_CHAIN_ID)]
        if self._fork_url is not None:
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
            env=anvil_env(),
        )
        self._wait_until_ready()
        chain_id = int(self.rpc("eth_chainId"), 16)
        if chain_id != ANVIL_CHAIN_ID:
            self.stop()
            raise RuntimeError(f"anvil reported chain id {chain_id}, expected {ANVIL_CHAIN_ID}")
        return self

    def _wait_until_ready(self) -> None:
        deadline = time.monotonic() + self.startup_timeout
        body = {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}
        while time.monotonic() < deadline:
            if self._proc is not None and self._proc.poll() is not None:
                code = self._proc.returncode
                self._proc = None
                raise RuntimeError(f"anvil exited early with code {code}")
            try:
                if httpx.post(self.rpc_url, json=body, timeout=1.0).status_code == 200:
                    return
            except httpx.TransportError:
                pass
            time.sleep(0.1)
        self.stop()
        raise TimeoutError(f"anvil did not answer on {self.rpc_url} within {self.startup_timeout}s")

    def rpc(self, method: str, params: list[Any] | None = None) -> Any:
        """Send one JSON-RPC request to this node and return its ``result``."""
        try:
            return rpc_call(self.rpc_url, method, params)
        except RPCError as err:
            # A forked node may quote its upstream URL, which can carry an API key.
            if self._fork_url and self._fork_url in str(err):
                raise RPCError(str(err).replace(self._fork_url, f"<{FORK_URL_ENV}>")) from None
            raise

    def snapshot(self) -> str:
        """Take an EVM snapshot of the whole chain state and return its id."""
        snapshot_id = self.rpc("evm_snapshot")
        if not isinstance(snapshot_id, str):
            raise RPCError(f"evm_snapshot returned {snapshot_id!r}")
        return snapshot_id

    def revert(self, snapshot_id: str) -> None:
        """Restore the chain to `snapshot_id`. Anvil deletes the snapshot after reverting."""
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

    @property
    def w3(self) -> Web3:
        """A Web3 client for this node, created once. Local only."""
        if self._w3 is None:
            self._w3 = Web3(Web3.HTTPProvider(assert_local_rpc(self.rpc_url)))
        return self._w3

    def stop(self) -> None:
        self._w3 = None
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
