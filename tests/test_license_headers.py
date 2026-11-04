# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Every Python source file carries the Apache-2.0 SPDX header."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HEADER = "# SPDX-License-Identifier: Apache-2.0"
DIRS = ["src", "tests", "examples", ".claude/hooks"]


def test_every_python_file_has_spdx_header() -> None:
    missing = [
        str(path.relative_to(ROOT))
        for directory in DIRS
        for path in (ROOT / directory).rglob("*.py")
        if HEADER not in path.read_text(encoding="utf-8").splitlines()[:3]
    ]
    assert missing == [], f"missing SPDX header: {missing}"
