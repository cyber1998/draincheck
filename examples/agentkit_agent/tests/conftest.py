# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Fixtures for the AgentKit example, copied from the repo's tests/conftest.py.

Tests marked `anvil` skip when anvil is missing, unless DRAINCHECK_REQUIRE_ANVIL=1 (set in
CI), where a missing anvil is a failure.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from draincheck.fork import AnvilProcess, find_anvil


def _require_anvil() -> None:
    if find_anvil() is None:
        if os.environ.get("DRAINCHECK_REQUIRE_ANVIL") == "1":
            pytest.fail("anvil is required (DRAINCHECK_REQUIRE_ANVIL=1) but not on PATH")
        pytest.skip("anvil not on PATH")


def pytest_runtest_setup(item: pytest.Item) -> None:
    if item.get_closest_marker("anvil") is not None:
        _require_anvil()


@pytest.fixture
def anvil() -> Iterator[AnvilProcess]:
    _require_anvil()
    with AnvilProcess() as node:
        yield node


_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}


@pytest.fixture(autouse=True)
def no_outside_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Fail any HTTP request to a host other than this machine, from any library.

    AgentKit has phoned home before (analytics); this catches the next one.
    """
    from urllib.parse import urlsplit

    import httpx
    import requests

    blocked: list[str] = []

    def check(url: object) -> None:
        host = urlsplit(str(url)).hostname or ""
        if host not in _LOCAL_HOSTS:
            blocked.append(host)
            raise RuntimeError(f"test tried to reach {host!r}, outside this machine")

    real_request = requests.Session.request
    real_send = httpx.Client.send
    real_async_send = httpx.AsyncClient.send

    def request(
        self: requests.Session, method: str, url: str, *args: object, **kw: object
    ) -> object:
        check(url)
        return real_request(self, method, url, *args, **kw)  # type: ignore[arg-type]

    def send(self: httpx.Client, request: httpx.Request, *args: object, **kw: object) -> object:
        check(request.url)
        return real_send(self, request, *args, **kw)  # type: ignore[arg-type]

    async def async_send(
        self: httpx.AsyncClient, request: httpx.Request, *args: object, **kw: object
    ) -> object:
        check(request.url)
        return await real_async_send(self, request, *args, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(requests.Session, "request", request)
    monkeypatch.setattr(httpx.Client, "send", send)
    monkeypatch.setattr(httpx.AsyncClient, "send", async_send)
    yield blocked
    assert not blocked, f"requests left the machine: {blocked}"
