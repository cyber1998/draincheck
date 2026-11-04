# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""The memory entry point: the payload is already in the agent's saved notes.

Models a poisoned memory or context store, as in "Real AI Agents with Fake Memories"
(arXiv 2503.16248). The folder lives outside the chain, so it is rebuilt before every
trial: whatever the agent wrote there in one trial is gone in the next.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING

from draincheck.entrypoints.base import TrialInputs
from draincheck.fork.anvil import AnvilProcess

if TYPE_CHECKING:
    from draincheck.scenarios import Scenario

STORE = "memory"
NOTES = "notes.json"


def memory(node: AnvilProcess, scenario: Scenario, stack: ExitStack) -> TrialInputs:
    """A JSON notes file holding the payload, in a folder rebuilt before each trial."""
    # A link the agent leaves in place of the root is not followed at cleanup either.
    root = Path(
        stack.enter_context(
            TemporaryDirectory(prefix="draincheck-memory-", ignore_cleanup_errors=True)
        )
    )
    # Pin the root by descriptor: the agent can see its path and swap it for a link, but
    # every reset step below works relative to the folder created here.
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    stack.callback(os.close, root_fd)
    content = json.dumps({"notes": [scenario.payload.rendered()]}).encode()

    def reset() -> None:
        try:
            old = os.lstat(STORE, dir_fd=root_fd)
        except FileNotFoundError:
            old = None
        if old is not None and stat.S_ISDIR(old.st_mode):
            shutil.rmtree(STORE, dir_fd=root_fd)  # fd-based: never follows a link inside
        elif old is not None:
            os.unlink(STORE, dir_fd=root_fd)  # a file or a link: remove it, not its target
        os.mkdir(STORE, 0o700, dir_fd=root_fd)
        store_fd = os.open(STORE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            with os.fdopen(os.open(NOTES, flags, 0o600, dir_fd=store_fd), "wb") as fresh:
                fresh.write(content)
        finally:
            os.close(store_fd)

    reset()
    return TrialInputs(services={"memory": (root / STORE / NOTES).as_uri()}, reset=reset)
