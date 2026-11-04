# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""The contract between the runner and the agent under test.

An agent target is a plain function that takes a :class:`TrialEnv` and does one run of
the agent's task against it. It returns nothing: the oracle reads the outcome from chain
state, never from what the agent says it did.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from draincheck.safety import assert_local_rpc, assert_local_service


@dataclass(frozen=True)
class TrialEnv:
    """Everything an agent needs for one trial. Every URL is local (127.0.0.1 or a file)."""

    rpc_url: str
    chain_id: int
    agent_key: str  # an anvil dev key; never a real one
    agent_address: str
    task: str  # the honest task the agent is asked to do
    # Name -> local URL of what the scenario's entry point serves ("feed", "api", ...).
    services: Mapping[str, str] = field(default_factory=dict)
    # Name -> address of a contract the agent is pointed at ("token", "router").
    contracts: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Targets build their own clients from these, so check them at the boundary.
        assert_local_rpc(self.rpc_url)
        for url in self.services.values():
            assert_local_service(url)


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
