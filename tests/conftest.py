# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Shared fixtures.

Tests marked `anvil` skip when anvil is missing, unless DRAINCHECK_REQUIRE_ANVIL=1 (set in
CI), where a missing anvil is a failure. A silent skip in CI would be a false pass.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from draincheck.fork import AnvilProcess, find_anvil


@pytest.fixture
def anvil() -> Iterator[AnvilProcess]:
    if find_anvil() is None:
        if os.environ.get("DRAINCHECK_REQUIRE_ANVIL") == "1":
            pytest.fail("anvil is required (DRAINCHECK_REQUIRE_ANVIL=1) but not on PATH")
        pytest.skip("anvil not on PATH")
    with AnvilProcess() as node:
        yield node
