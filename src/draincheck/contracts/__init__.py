# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Compiled contracts the sandbox installs. Source lives in the repo's contracts/ folder."""

from __future__ import annotations

import json
from functools import cache
from importlib.resources import files
from typing import Any


@cache
def load_artifact(name: str) -> dict[str, Any]:
    """Return the committed ABI/bytecode JSON for contract `name` (e.g. "TestUSDC")."""
    text = files(__package__).joinpath(f"{name}.json").read_text(encoding="utf-8")
    artifact: dict[str, Any] = json.loads(text)
    return artifact
