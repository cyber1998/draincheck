# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from draincheck.safety import (
    NonDevKeyError,
    NonLocalRPCError,
    assert_dev_key,
    assert_local_rpc,
    assert_local_service,
)

TEMP = Path(tempfile.gettempdir())


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8545",
        "http://localhost:8545",
        "ws://127.0.0.1:8546",
        "http://[::1]:8545",
        "http://127.0.0.2:8545",
    ],
)
def test_local_urls_are_allowed(url: str) -> None:
    assert assert_local_rpc(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "https://mainnet.base.org",
        "https://base-mainnet.g.alchemy.com/v2/key",
        "http://localhost.attacker.example:8545",
        "http://127.0.0.1.nip.io:8545",
        "http://10.0.0.5:8545",
        "127.0.0.1:8545",
        "file:///etc/passwd",
        "http://user@evil.example:8545",
    ],
)
def test_non_local_urls_are_rejected(url: str) -> None:
    with pytest.raises(NonLocalRPCError):
        assert_local_rpc(url)


@pytest.mark.parametrize(
    "url",
    [
        (TEMP / "draincheck" / "notes.json").as_uri(),
        "file://localhost" + (TEMP / "notes.json").as_posix(),
        "http://127.0.0.1:9/x",
    ],
)
def test_local_services_are_allowed(url: str) -> None:
    assert assert_local_service(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "file://evil.example/notes.json",
        "file:notes.json",
        "https://example.com/feed",
        "ftp://127.0.0.1/x",
        # Decode to "//host/...": a network share path on Windows.
        "file:////host/share",
        "file:///%2F%2Fhost/x",
        "file:///tmp//host",
        "file:///%5C%5Chost%5Cshare",  # backslashes: a UNC path on Windows
        "file:///net/fileserver/share",  # automounted from another host on macOS
        "file:///etc/passwd",  # local, but not a file Draincheck made
    ],
)
def test_non_local_services_are_rejected(url: str) -> None:
    with pytest.raises(NonLocalRPCError):
        assert_local_service(url)


def test_anvil_dev_keys_are_accepted() -> None:
    from draincheck.fork.accounts import AGENT_ADDRESS, AGENT_KEY

    assert assert_dev_key(AGENT_KEY, AGENT_ADDRESS) == AGENT_KEY


@pytest.mark.parametrize(
    ("key", "address"),
    [
        ("0x" + "11" * 32, None),  # a valid key, but not one of anvil's
        ("0x", None),  # not a key at all
        ("not-hex", None),
    ],
)
def test_other_keys_are_rejected(key: str, address: str | None) -> None:
    with pytest.raises(NonDevKeyError):
        assert_dev_key(key, address)


def test_dev_key_must_match_its_address() -> None:
    from draincheck.fork.accounts import AGENT_KEY, SERVICE_ADDRESS

    with pytest.raises(NonDevKeyError, match="signs for"):
        assert_dev_key(AGENT_KEY, SERVICE_ADDRESS)


def test_trial_env_refuses_a_non_dev_key() -> None:
    from draincheck.fork.accounts import AGENT_ADDRESS
    from draincheck.runner import TrialEnv

    with pytest.raises(NonDevKeyError):
        TrialEnv("http://127.0.0.1:8545", 31337, "0x" + "11" * 32, AGENT_ADDRESS, "task")
