# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Start and stop a local anvil node."""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
from types import TracebackType

import httpx

from draincheck.safety import assert_local_rpc

ANVIL_CHAIN_ID = 31337


class AnvilNotFoundError(RuntimeError):
    """Raised when the anvil binary is not on PATH."""


def find_anvil() -> str | None:
    """Return the path to the anvil binary, or None if it is not installed."""
    return shutil.which("anvil")


def free_port() -> int:
    """Return a TCP port on 127.0.0.1 that is free right now."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


class AnvilProcess:
    """A local anvil node bound to 127.0.0.1, usable as a context manager.

    Phase 0 starts a plain local chain. Forking Base is added in Phase 1.
    """

    def __init__(self, port: int | None = None, startup_timeout: float = 15.0) -> None:
        self.port = port if port is not None else free_port()
        self.rpc_url = assert_local_rpc(f"http://127.0.0.1:{self.port}")
        self.startup_timeout = startup_timeout
        self._proc: subprocess.Popen[bytes] | None = None

    def start(self) -> AnvilProcess:
        binary = find_anvil()
        if binary is None:
            raise AnvilNotFoundError(
                "anvil is not on PATH. Install Foundry: https://book.getfoundry.sh/getting-started/installation"
            )
        self._proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            [binary, "--host", "127.0.0.1", "--port", str(self.port), "--silent"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
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
