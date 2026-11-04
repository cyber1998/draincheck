# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""collect() sees ETH, USDC, approvals and EIP-3009 settlements from chain state."""

from __future__ import annotations

import pytest
from web3 import Web3

from draincheck.facilitator.client import build_exact_payment
from draincheck.facilitator.server import Facilitator
from draincheck.facilitator.services import PaidRoute
from draincheck.facilitator.types import FacilitatorRequest, PaymentRequirements
from draincheck.fork import AnvilProcess
from draincheck.fork.accounts import (
    AGENT_ADDRESS,
    AGENT_KEY,
    ATTACKER_ADDRESS,
    SERVICE_ADDRESS,
)
from draincheck.fork.usdc import (
    USDC_ADDRESS,
    USDC_UNIT,
    ensure_usdc,
    fund_usdc,
    usdc_contract,
)
from draincheck.oracle import Evidence, StateCapture, capture, collect
from draincheck.oracle.evidence import APPROVAL_TOPIC, NATIVE, UNKNOWN_ALLOWANCE
from draincheck.safety import assert_local_rpc

MAX_UINT256 = 2**256 - 1


def _w3(anvil: AnvilProcess) -> Web3:
    return Web3(Web3.HTTPProvider(assert_local_rpc(anvil.rpc_url)))


def _watched() -> list[str]:
    return [AGENT_ADDRESS, SERVICE_ADDRESS, ATTACKER_ADDRESS]


def _start(anvil: AnvilProcess) -> tuple[Web3, StateCapture]:
    """Fund the agent with test USDC and capture the state before the action."""
    w3 = _w3(anvil)
    fund_usdc(anvil, AGENT_ADDRESS, 100)
    pre = capture(w3, _watched(), [USDC_ADDRESS])
    return w3, pre


def _finish(w3: Web3, pre: StateCapture) -> Evidence:
    post = capture(w3, _watched(), [USDC_ADDRESS])
    return collect(w3, [AGENT_ADDRESS], pre, post)


@pytest.mark.anvil
def test_eth_transfer_is_a_movement(anvil: AnvilProcess) -> None:
    w3, pre = _start(anvil)
    tx_hash = w3.eth.send_transaction(
        {"from": AGENT_ADDRESS, "to": ATTACKER_ADDRESS, "value": Web3.to_wei(1, "ether")}
    )
    w3.eth.wait_for_transaction_receipt(tx_hash)
    ev = _finish(w3, pre)

    native = [m for m in ev.movements if m.asset == NATIVE]
    assert any(m.to == ATTACKER_ADDRESS and m.amount == 10**18 and m.direct for m in native), native
    assert ev.native_net_outflow(AGENT_ADDRESS) == 10**18
    assert len(ev.agent_txs) == 1


@pytest.mark.anvil
def test_usdc_transfer_is_a_movement(anvil: AnvilProcess) -> None:
    w3, pre = _start(anvil)
    usdc = usdc_contract(w3)
    tx_hash = usdc.functions.transfer(ATTACKER_ADDRESS, 5 * USDC_UNIT).transact(
        {"from": AGENT_ADDRESS}
    )
    w3.eth.wait_for_transaction_receipt(tx_hash)
    ev = _finish(w3, pre)

    assert any(
        m.asset == USDC_ADDRESS and m.to == ATTACKER_ADDRESS and m.amount == 5 * USDC_UNIT
        for m in ev.movements
    ), ev.movements


@pytest.mark.anvil
def test_approve_is_a_new_approval(anvil: AnvilProcess) -> None:
    w3, pre = _start(anvil)
    ensure_usdc(anvil)
    usdc = usdc_contract(w3)
    tx_hash = usdc.functions.approve(ATTACKER_ADDRESS, MAX_UINT256).transact(
        {"from": AGENT_ADDRESS}
    )
    w3.eth.wait_for_transaction_receipt(tx_hash)
    ev = _finish(w3, pre)

    assert len(ev.approvals) == 1
    approval = ev.approvals[0]
    assert approval.token == USDC_ADDRESS
    assert approval.owner == AGENT_ADDRESS
    assert approval.spender == ATTACKER_ADDRESS
    assert approval.before == 0
    assert approval.after == MAX_UINT256


@pytest.mark.anvil
def test_revoking_an_approval_is_not_new(anvil: AnvilProcess) -> None:
    w3, _ = _start(anvil)
    usdc = usdc_contract(w3)
    tx_hash = usdc.functions.approve(ATTACKER_ADDRESS, 10 * USDC_UNIT).transact(
        {"from": AGENT_ADDRESS}
    )
    w3.eth.wait_for_transaction_receipt(tx_hash)
    pre = capture(w3, _watched(), [USDC_ADDRESS])

    tx_hash = usdc.functions.approve(ATTACKER_ADDRESS, 0).transact({"from": AGENT_ADDRESS})
    w3.eth.wait_for_transaction_receipt(tx_hash)
    ev = _finish(w3, pre)

    assert ev.approvals == []


@pytest.mark.anvil
def test_eip3009_settlement_is_seen(anvil: AnvilProcess) -> None:
    w3, pre = _start(anvil)
    route = PaidRoute(path="/feed", price=10_000, pay_to=SERVICE_ADDRESS, content={})
    reqs: PaymentRequirements = route.requirements()
    fac = Facilitator(anvil.rpc_url)
    payment = build_exact_payment(AGENT_KEY, AGENT_ADDRESS, reqs, fac.now())
    # The facilitator submits the transaction, not the agent.
    settled = fac.settle(FacilitatorRequest(payment_payload=payment, payment_requirements=reqs))
    assert settled.success is True
    ev = _finish(w3, pre)

    assert len(ev.settlements) == 1
    settlement = ev.settlements[0]
    assert settlement.payer == AGENT_ADDRESS
    assert settlement.pay_to == SERVICE_ADDRESS
    assert settlement.amount == 10_000
    assert settlement.token == USDC_ADDRESS
    # Required for the oracle: the settled value must also show up as a movement.
    assert any(
        m.asset == USDC_ADDRESS and m.to == SERVICE_ADDRESS and m.amount == 10_000
        for m in ev.movements
    ), ev.movements


@pytest.mark.anvil
def test_nothing_happened_is_empty(anvil: AnvilProcess) -> None:
    w3, pre = _start(anvil)
    ev = _finish(w3, pre)

    assert ev.movements == []
    assert ev.approvals == []
    assert ev.settlements == []
    assert ev.agent_txs == []


@pytest.mark.anvil
def test_approval_kept_when_allowance_cannot_be_read(anvil: AnvilProcess) -> None:
    # A contract with no allowance(): it only emits Approval(caller, attacker) with 3 topics.
    # Before the fix both allowance reads returned 0, so `0 > 0` dropped the approval.
    weird = Web3.to_checksum_address("0x" + "ab" * 20)
    code = (
        "0x73"
        + ATTACKER_ADDRESS[2:].lower()  # PUSH20 attacker  (topic2)
        + "33"  # CALLER (topic1)
        + "7f"
        + APPROVAL_TOPIC[2:]  # PUSH32 Approval topic (topic0)
        + "6000"  # PUSH1 0 (size)
        + "6000"  # PUSH1 0 (offset)
        + "a3"  # LOG3
        + "00"  # STOP
    )
    anvil.rpc("anvil_setCode", [weird, code])
    w3, pre = _start(anvil)
    tx = w3.eth.send_transaction({"from": AGENT_ADDRESS, "to": weird})
    w3.eth.wait_for_transaction_receipt(tx)
    ev = _finish(w3, pre)

    assert len(ev.approvals) == 1
    approval = ev.approvals[0]
    assert (approval.token, approval.spender) == (weird, ATTACKER_ADDRESS)
    assert approval.after == UNKNOWN_ALLOWANCE
