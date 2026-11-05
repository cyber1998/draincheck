# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""The contract between an entry point and the runner.

An entry point puts a scenario's payload where the agent will find it (a paid feed, an API
response, a token's name, a router listing, a memory file) and returns :class:`TrialInputs`:
what the agent is given, and what the oracle needs to judge the trial. It starts once per
scenario; chain state it creates is part of the snapshot every trial reverts to.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import ExitStack
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

from draincheck.facilitator.server import Facilitator, create_facilitator_app, serve_in_thread
from draincheck.facilitator.services import PaidRoute, ServiceLog, create_paid_service
from draincheck.fork.anvil import AnvilProcess, free_port

if TYPE_CHECKING:
    from draincheck.scenarios import Scenario


@dataclass(frozen=True)
class TrialInputs:
    """What one entry point adds to every trial of a scenario."""

    # Name -> local URL the agent may read (http://127.0.0.1:... or file://).
    services: Mapping[str, str] = field(default_factory=dict)
    # Name -> address of a contract the agent is pointed at.
    contracts: Mapping[str, str] = field(default_factory=dict)
    # Extra role names invariants may use, e.g. "router" -> its address.
    roles: Mapping[str, str] = field(default_factory=dict)
    # Extra tokens whose balances the oracle captures before and after.
    tokens: tuple[str, ...] = ()
    # x402 quotes: (pay_to, token) -> price in base units, and how many paid reads the
    # honest task needs.
    quotes: Mapping[tuple[str, str], int] = field(default_factory=dict)
    paid_reads: int = 0
    # Restores state that lives outside the chain (a file) before each trial.
    reset: Callable[[], None] | None = None


class EntryPoint(Protocol):
    def __call__(self, node: AnvilProcess, scenario: Scenario, stack: ExitStack) -> TrialInputs:
        """Set the payload up for `scenario`; register anything to stop on `stack`."""
        ...


def serve_paid(node: AnvilProcess, stack: ExitStack, route: PaidRoute) -> str:
    """Serve `route` behind x402, settled by a mock facilitator on `node`; return its URL."""
    facilitator = create_facilitator_app(Facilitator(node.rpc_url))
    facilitator_url = stack.enter_context(serve_in_thread(facilitator, free_port()))
    app = create_paid_service(facilitator_url, [route], ServiceLog())
    return stack.enter_context(serve_in_thread(app, free_port())) + route.path
