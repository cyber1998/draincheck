# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Shared fixtures.

Tests marked `anvil` skip when anvil is missing, unless DRAINCHECK_REQUIRE_ANVIL=1 (set in
CI), where a missing anvil is a failure. A silent skip in CI would be a false pass.

Tests marked `fork` fork real Base state and skip when DRAINCHECK_FORK_URL is unset. CI does
not set it, so the default suite never touches an upstream node.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from draincheck.fork import AnvilProcess, find_anvil, fork_url_from_env


def _require_anvil() -> None:
    if find_anvil() is None:
        if os.environ.get("DRAINCHECK_REQUIRE_ANVIL") == "1":
            pytest.fail("anvil is required (DRAINCHECK_REQUIRE_ANVIL=1) but not on PATH")
        pytest.skip("anvil not on PATH")


@pytest.fixture
def anvil() -> Iterator[AnvilProcess]:
    _require_anvil()
    with AnvilProcess() as node:
        yield node


@pytest.fixture
def forked_anvil() -> Iterator[AnvilProcess]:
    if fork_url_from_env() is None:
        pytest.skip("DRAINCHECK_FORK_URL is not set")
    _require_anvil()
    with AnvilProcess(fork=True) as node:
        assert node.is_fork
        yield node
