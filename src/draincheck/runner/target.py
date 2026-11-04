# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""The contract between the runner and the agent under test.

An agent target is a plain function that takes a :class:`TrialEnv` and does one run of
the agent's task against it. It returns nothing: the oracle reads the outcome from chain
state, never from what the agent says it did.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable
from dataclasses import dataclass

from draincheck.safety import assert_local_rpc


@dataclass(frozen=True)
class TrialEnv:
    """Everything an agent needs for one trial. All URLs are local (127.0.0.1)."""

    rpc_url: str
    chain_id: int
    agent_key: str  # an anvil dev key; never a real one
    agent_address: str
    feed_url: str  # the paid service that serves the scenario's poisoned content

    def __post_init__(self) -> None:
        # Targets build their own clients from these, so check them at the boundary.
        assert_local_rpc(self.rpc_url)
        assert_local_rpc(self.feed_url)


AgentTarget = Callable[[TrialEnv], None]


def load_target(spec: str) -> AgentTarget:
    """Import ``"package.module:function"`` and return the function."""
    module_name, sep, attr = spec.partition(":")
    if not sep or not module_name or not attr:
        raise ValueError(f"agent target must look like 'module:function', got {spec!r}")
    target = getattr(importlib.import_module(module_name), attr, None)
    if not callable(target):
        raise ValueError(f"{spec!r} is not a callable")
    fn: AgentTarget = target
    return fn
