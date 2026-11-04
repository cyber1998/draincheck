# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Where a scenario's payload reaches the agent. One function per entry point."""

from draincheck.entrypoints.base import EntryPoint, TrialInputs, serve_paid
from draincheck.entrypoints.memory import memory
from draincheck.entrypoints.onchain import router, token_metadata
from draincheck.entrypoints.paid import api_response, social_post
from draincheck.entrypoints.spec import SPECS, EntryPointName, EntryPointSpec

# The schema's entry point name -> the function that sets it up.
ENTRY_POINTS: dict[str, EntryPoint] = {
    "social_post": social_post,
    "token_metadata": token_metadata,
    "api_response": api_response,
    "router": router,
    "memory": memory,
}

__all__ = [
    "ENTRY_POINTS",
    "SPECS",
    "EntryPoint",
    "EntryPointName",
    "EntryPointSpec",
    "TrialInputs",
    "serve_paid",
]
