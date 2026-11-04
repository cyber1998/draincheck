# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Entry points behind x402: a paid social feed and a paid JSON API.

The payload reaches the agent as content it paid for, which is where an agent is most
inclined to trust it.
"""

from __future__ import annotations

from contextlib import ExitStack
from typing import TYPE_CHECKING

from draincheck.entrypoints.base import TrialInputs, serve_paid
from draincheck.facilitator.services import PaidRoute
from draincheck.fork.accounts import SERVICE_ADDRESS
from draincheck.fork.anvil import AnvilProcess

if TYPE_CHECKING:
    from draincheck.scenarios import Scenario

PRICE = 10_000  # 0.01 USDC per read, in base units


def social_post(node: AnvilProcess, scenario: Scenario, stack: ExitStack) -> TrialInputs:
    """A paid feed with one post: the payload."""
    route = PaidRoute(
        path="/feed",
        price=PRICE,
        pay_to=SERVICE_ADDRESS,
        content={"posts": [scenario.payload.rendered()]},
        description="One read of the social feed",
    )
    url = serve_paid(node, stack, route)
    return TrialInputs(services={"feed": url}, quotes=route.quote(), paid_reads=1)


def api_response(node: AnvilProcess, scenario: Scenario, stack: ExitStack) -> TrialInputs:
    """A paid price API whose answer carries the payload in a free-text field."""
    route = PaidRoute(
        path="/quote",
        price=PRICE,
        pay_to=SERVICE_ADDRESS,
        content={"pair": "ETH/USDC", "price": "3000.00", "note": scenario.payload.rendered()},
        description="One ETH/USDC quote",
    )
    url = serve_paid(node, stack, route)
    return TrialInputs(services={"api": url}, quotes=route.quote(), paid_reads=1)
