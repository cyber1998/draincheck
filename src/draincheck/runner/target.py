# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""The contract between the runner and the agent under test.

An agent target is a function that takes a :class:`TrialEnv` and does one run of the
agent's task against it. Adapters (:mod:`draincheck.adapters`) turn other kinds of agent,
such as a local HTTP service, into one. It returns nothing: the oracle reads the outcome
from chain state, never from what the agent says it did.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from draincheck.safety import assert_dev_key, assert_local_rpc, assert_local_service


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
        assert_dev_key(self.agent_key, self.agent_address)

    def to_wire(self) -> dict[str, Any]:
        """JSON form, as sent to an agent that runs as a separate service."""
        return {
            "rpc_url": self.rpc_url,
            "chain_id": self.chain_id,
            "agent_key": self.agent_key,
            "agent_address": self.agent_address,
            "task": self.task,
            "services": dict(self.services),
            "contracts": dict(self.contracts),
        }

    @classmethod
    def from_wire(cls, data: Mapping[str, Any]) -> TrialEnv:
        """Rebuild a TrialEnv on the agent's side. Checks every URL again."""
        return cls(
            rpc_url=str(data["rpc_url"]),
            chain_id=int(data["chain_id"]),
            agent_key=str(data["agent_key"]),
            agent_address=str(data["agent_address"]),
            task=str(data["task"]),
            services={str(k): str(v) for k, v in dict(data.get("services") or {}).items()},
            contracts={str(k): str(v) for k, v in dict(data.get("contracts") or {}).items()},
        )


AgentTarget = Callable[[TrialEnv], None]


def load_target(spec: str) -> AgentTarget:
    """Turn ``--agent`` into a target.

    - ``package.module:function``: a Python function taking a :class:`TrialEnv`.
    - ``http://127.0.0.1:PORT/path``: an agent running as a local HTTP service (see
      :mod:`draincheck.adapters.http`).
    - ``langgraph:package.module:factory``: a LangGraph agent (needs the ``langgraph``
      extra; see :mod:`draincheck.adapters.langgraph`).

    Adapters are imported only when used, so optional extras stay optional.
    """
    if spec.startswith(("http://", "https://")):
        from draincheck.adapters.http import http_target

        return http_target(spec)
    if spec.startswith("langgraph:"):
        from draincheck.adapters.langgraph import langgraph_target

        return langgraph_target(spec.removeprefix("langgraph:"))
    return python_target(spec)


def python_target(spec: str) -> AgentTarget:
    """Import ``"package.module:function"`` and return the function."""
    module_name, sep, attr = spec.partition(":")
    if not sep or not module_name or not attr:
        raise ValueError(
            f"agent target must look like 'module:function' or a local URL, got {spec!r}"
        )
    target = getattr(importlib.import_module(module_name), attr, None)
    if not callable(target):
        raise ValueError(f"{spec!r} is not a callable")
    fn: AgentTarget = target
    return fn
