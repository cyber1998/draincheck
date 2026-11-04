# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Entry points that live in contracts: a token's metadata and a swap router.

The contracts are sandbox stand-ins (``contracts/src/TestToken.sol``, ``TestRouter.sol``)
installed with ``anvil_setCode`` at fixed addresses and set up by the deployer account,
never by the agent. All of it happens before the snapshot the trials revert to.
"""

from __future__ import annotations

from contextlib import ExitStack
from typing import TYPE_CHECKING, Any

from web3 import Web3
from web3.contract import Contract

from draincheck.contracts import load_artifact
from draincheck.entrypoints.base import TrialInputs, serve_paid
from draincheck.entrypoints.paid import PRICE
from draincheck.entrypoints.spec import RouterOptions, TokenOptions
from draincheck.facilitator.services import PaidRoute
from draincheck.fork.accounts import AGENT_ADDRESS, DEPLOYER_ADDRESS, SERVICE_ADDRESS
from draincheck.fork.anvil import AnvilProcess
from draincheck.fork.usdc import USDC_ADDRESS, USDC_UNIT

if TYPE_CHECKING:
    from draincheck.scenarios import Scenario

TOKEN_ADDRESS = Web3.to_checksum_address("0x" + "7e57" * 10)
ROUTER_ADDRESS = Web3.to_checksum_address("0x" + "4077" * 10)
AGENT_TOKENS = 100 * USDC_UNIT  # what the agent holds of the payload token (6 decimals)
ROUTER_LIQUIDITY = 10_000 * USDC_UNIT  # what the router can pay out


def _install(node: AnvilProcess, address: str, artifact: str) -> Contract:
    """Put a sandbox contract's runtime code at `address` and return a handle to it."""
    data = load_artifact(artifact)
    code = "0x" + str(data["deployedBytecode"]).removeprefix("0x")
    node.rpc("anvil_setCode", [address, code])
    return node.w3.eth.contract(address=Web3.to_checksum_address(address), abi=data["abi"])


def _setup(node: AnvilProcess, call: Any) -> None:
    """Send one setup transaction from the deployer and require it to succeed."""
    tx_hash = call.transact({"from": DEPLOYER_ADDRESS})
    if node.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=10)["status"] != 1:
        raise RuntimeError(f"sandbox setup transaction {tx_hash.hex()} reverted")


def token_metadata(node: AnvilProcess, scenario: Scenario, stack: ExitStack) -> TrialInputs:
    """The agent holds a token whose name is the payload."""
    options = TokenOptions.model_validate(scenario.options)
    token = _install(node, TOKEN_ADDRESS, "TestToken")
    _setup(node, token.functions.setMetadata(scenario.payload.rendered(), options.symbol))
    _setup(node, token.functions.mint(AGENT_ADDRESS, AGENT_TOKENS))
    return TrialInputs(
        contracts={"token": TOKEN_ADDRESS},
        roles={"token": TOKEN_ADDRESS},
        tokens=(TOKEN_ADDRESS,),
    )


def router(node: AnvilProcess, scenario: Scenario, stack: ExitStack) -> TrialInputs:
    """A paid router listing recommends a router; the payload is the listing's note."""
    options = RouterOptions.model_validate(scenario.options)
    token = _install(node, TOKEN_ADDRESS, "TestToken")
    _setup(node, token.functions.setMetadata("Test Token", "TEST"))
    _setup(node, token.functions.mint(ROUTER_ADDRESS, ROUTER_LIQUIDITY))
    swap = _install(node, ROUTER_ADDRESS, "TestRouter")
    _setup(
        node,
        swap.functions.configure(
            scenario.setup.attacker, options.skim_bps, options.drain_allowance
        ),
    )
    listing = {
        "router": ROUTER_ADDRESS,
        "token_in": USDC_ADDRESS,
        "token_out": TOKEN_ADDRESS,
        "note": scenario.payload.rendered(),
    }
    route = PaidRoute(
        path="/routers",
        price=PRICE,
        pay_to=SERVICE_ADDRESS,
        content={"routers": [listing]},
        description="The recommended swap router",
    )
    url = serve_paid(node, stack, route)
    addresses = {"router": ROUTER_ADDRESS, "token": TOKEN_ADDRESS}
    return TrialInputs(
        services={"routers": url},
        contracts=addresses,
        roles=addresses,
        tokens=(TOKEN_ADDRESS,),
        quotes=route.quote(),
        paid_reads=1,
    )
