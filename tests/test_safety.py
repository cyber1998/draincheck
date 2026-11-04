# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
from __future__ import annotations

import pytest

from draincheck.safety import NonLocalRPCError, assert_local_rpc


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
