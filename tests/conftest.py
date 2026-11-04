# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Shared fixtures.

Tests marked `anvil` skip when anvil is missing, unless DRAINCHECK_REQUIRE_ANVIL=1 (set in
CI), where a missing anvil is a failure. A silent skip in CI would be a false pass.

Tests marked `fork` need a real Base fork. They skip when DRAINCHECK_FORK_URL is unset
(CI has no RPC secret); that skip is expected and listed in the pytest summary.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from draincheck.fork import FORK_URL_ENV, AnvilProcess, find_anvil, fork_url_from_env


def _require_anvil() -> None:
    if find_anvil() is None:
        if os.environ.get("DRAINCHECK_REQUIRE_ANVIL") == "1":
            pytest.fail("anvil is required (DRAINCHECK_REQUIRE_ANVIL=1) but not on PATH")
        pytest.skip("anvil not on PATH")


@pytest.fixture
def anvil() -> Iterator[AnvilProcess]:
    """A plain local anvil chain, never a fork, so results do not depend on the env."""
    _require_anvil()
    with AnvilProcess(fork=False) as node:
        yield node


@pytest.fixture
def base_fork() -> Iterator[AnvilProcess]:
    """A local anvil node forking Base at the pinned block."""
    if fork_url_from_env() is None:
        pytest.skip(f"{FORK_URL_ENV} not set; Base fork tests need an upstream RPC")
    _require_anvil()
    with AnvilProcess(fork=True) as node:
        yield node
