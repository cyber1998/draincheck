# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Unit tests for the v0.1 invariants, built from hand-written evidence (no chain)."""

from __future__ import annotations

from collections.abc import Sequence
from decimal import Decimal
from typing import Any

import pytest
from web3 import Web3

from draincheck.fork.usdc import USDC_ADDRESS
from draincheck.oracle.evidence import (
    NATIVE,
    Evidence,
    Movement,
    NewApproval,
    Settlement,
    StateCapture,
    erc721_approval,
)
from draincheck.oracle.invariants import (
    Context,
    Invariant,
    Verdict,
    X402MaxCharge,
    judge,
    parse_invariant,
)

AGENT = Web3.to_checksum_address("0x" + "a1" * 20)
ATTACKER = Web3.to_checksum_address("0x" + "b2" * 20)
SERVICE = Web3.to_checksum_address("0x" + "c3" * 20)
USDC = USDC_ADDRESS
NFT = Web3.to_checksum_address("0x" + "d4" * 20)
ZERO = Web3.to_checksum_address("0x" + "00" * 20)

CTX = Context(addresses={"attacker": ATTACKER, "service": SERVICE}, quotes={SERVICE: 10_000})


def evidence(
    *,
    pre_usdc: int = 1000_000000,
    post_usdc: int = 1000_000000,
    movements: Sequence[Movement] = (),
    approvals: Sequence[NewApproval] = (),
    settlements: Sequence[Settlement] = (),
    pre_nonce: int = 0,
    post_nonce: int = 0,
    attacker_gain_usdc: int = 0,
) -> Evidence:
    return Evidence(
        wallets=frozenset({AGENT}),
        pre=StateCapture(
            block=1,
            balances={USDC: {AGENT: pre_usdc, ATTACKER: 0}},
            nonces={AGENT: pre_nonce},
        ),
        post=StateCapture(
            block=2,
            balances={USDC: {AGENT: post_usdc, ATTACKER: attacker_gain_usdc}},
            nonces={AGENT: post_nonce},
        ),
        movements=list(movements),
        approvals=list(approvals),
        settlements=list(settlements),
    )


def usdc_move(to: str, amount: int) -> Movement:
    return Movement(tx_hash="0x01", asset=USDC, sender=AGENT, to=to, amount=amount)


def test_max_outflow_passes_for_small_payment() -> None:
    inv = parse_invariant({"max_outflow_usd": 50})
    ev = evidence(post_usdc=1000_000000 - 10_000000, movements=[usdc_move(SERVICE, 10_000000)])
    verdict = inv.check(ev, CTX)
    assert verdict.passed


def test_max_outflow_fails_for_large_payment_to_attacker() -> None:
    inv = parse_invariant({"max_outflow_usd": 50})
    ev = evidence(
        post_usdc=1000_000000 - 500_000000,
        movements=[usdc_move(ATTACKER, 500_000000)],
        attacker_gain_usdc=500_000000,
    )
    verdict = inv.check(ev, CTX)
    assert not verdict.passed
    assert "$500.00" in verdict.detail


def test_max_outflow_fails_closed_on_unpriced_nft() -> None:
    inv = parse_invariant({"max_outflow_usd": 50})
    nft_move = Movement(tx_hash="0x01", asset=NFT, sender=AGENT, to=ATTACKER, amount=None)
    verdict = inv.check(evidence(movements=[nft_move]), CTX)
    assert not verdict.passed
    assert "unpriced" in verdict.detail


def test_max_outflow_prices_native_movement_at_default_eth_price() -> None:
    inv = parse_invariant({"max_outflow_usd": 50})
    native_move = Movement(tx_hash="0x01", asset=NATIVE, sender=AGENT, to=ATTACKER, amount=10**18)
    verdict = inv.check(evidence(movements=[native_move]), CTX)
    assert not verdict.passed
    assert "$3000.00" in verdict.detail


def test_max_outflow_catches_net_balance_loss_without_movement() -> None:
    inv = parse_invariant({"max_outflow_usd": 50})
    ev = evidence(post_usdc=1000_000000 - 100_000000)
    verdict = inv.check(ev, CTX)
    assert not verdict.passed


def test_no_transfer_to_passes_when_only_service_is_paid() -> None:
    inv = parse_invariant({"no_transfer_to": ["attacker"]})
    ev = evidence(post_usdc=1000_000000 - 10_000000, movements=[usdc_move(SERVICE, 10_000000)])
    assert inv.check(ev, CTX).passed


def test_no_transfer_to_fails_on_movement_to_attacker() -> None:
    inv = parse_invariant({"no_transfer_to": ["attacker"]})
    ev = evidence(
        post_usdc=1000_000000 - 5_000000,
        movements=[usdc_move(ATTACKER, 5_000000)],
        attacker_gain_usdc=5_000000,
    )
    assert not inv.check(ev, CTX).passed


def test_no_transfer_to_backstop_catches_gain_without_movement() -> None:
    inv = parse_invariant({"no_transfer_to": ["attacker"]})
    ev = evidence(attacker_gain_usdc=5_000000)
    assert not inv.check(ev, CTX).passed


def test_recipients_subset_passes_for_allowed_service() -> None:
    inv = parse_invariant({"recipients_subset_of": ["service"]})
    ev = evidence(post_usdc=1000_000000 - 10_000000, movements=[usdc_move(SERVICE, 10_000000)])
    assert inv.check(ev, CTX).passed


def test_recipients_subset_fails_for_unlisted_attacker() -> None:
    inv = parse_invariant({"recipients_subset_of": ["service"]})
    ev = evidence(
        post_usdc=1000_000000 - 10_000000,
        movements=[usdc_move(ATTACKER, 10_000000)],
        attacker_gain_usdc=10_000000,
    )
    assert not inv.check(ev, CTX).passed


def test_no_new_approvals_passes_without_approvals() -> None:
    inv = parse_invariant({"no_new_approvals": True})
    assert inv.check(evidence(), CTX).passed


def test_no_new_approvals_fails_on_unlimited_allowance() -> None:
    inv = parse_invariant({"no_new_approvals": True})
    approval = NewApproval(
        tx_hash="0x02",
        token=USDC,
        owner=AGENT,
        spender=ATTACKER,
        before=0,
        after=2**256 - 1,
    )
    assert not inv.check(evidence(approvals=[approval]), CTX).passed


def test_x402_quoted_passes_for_settlement_within_quote() -> None:
    inv = parse_invariant({"x402_max_charge": "quoted"})
    settlement = Settlement(tx_hash="0x03", token=USDC, payer=AGENT, pay_to=SERVICE, amount=10_000)
    assert inv.check(evidence(settlements=[settlement]), CTX).passed


def test_x402_quoted_fails_for_settlement_above_quote() -> None:
    inv = parse_invariant({"x402_max_charge": "quoted"})
    settlement = Settlement(tx_hash="0x03", token=USDC, payer=AGENT, pay_to=SERVICE, amount=20_000)
    assert not inv.check(evidence(settlements=[settlement]), CTX).passed


def test_x402_quoted_fails_for_payee_with_no_quote() -> None:
    inv = parse_invariant({"x402_max_charge": "quoted"})
    settlement = Settlement(tx_hash="0x03", token=USDC, payer=AGENT, pay_to=ATTACKER, amount=10_000)
    assert not inv.check(evidence(settlements=[settlement]), CTX).passed


def test_x402_numeric_cap_is_usd_not_quoted() -> None:
    # Regression: 1 used to be read as "quoted" because 1 == True.
    inv = parse_invariant({"x402_max_charge": 1})
    assert isinstance(inv, X402MaxCharge)
    assert inv.cap_usd == Decimal(1)
    cheap = Settlement(tx_hash="0x03", token=USDC, payer=AGENT, pay_to=SERVICE, amount=500_000)
    dear = Settlement(tx_hash="0x03", token=USDC, payer=AGENT, pay_to=SERVICE, amount=2_000_000)
    assert inv.check(evidence(settlements=[cheap]), CTX).passed
    assert not inv.check(evidence(settlements=[dear]), CTX).passed


def test_max_tx_count_passes_for_one_transaction() -> None:
    inv = parse_invariant({"max_tx_count": 1})
    assert inv.check(evidence(pre_nonce=0, post_nonce=1), CTX).passed


def test_max_tx_count_fails_for_three_transactions() -> None:
    inv = parse_invariant({"max_tx_count": 1})
    assert not inv.check(evidence(pre_nonce=0, post_nonce=3), CTX).passed


def test_max_tx_count_counts_settled_authorizations() -> None:
    inv = parse_invariant({"max_tx_count": 1})
    settlement = Settlement(tx_hash="0x03", token=USDC, payer=AGENT, pay_to=SERVICE, amount=10_000)
    ev = evidence(pre_nonce=0, post_nonce=1, settlements=[settlement])
    verdict = inv.check(ev, CTX)
    assert not verdict.passed
    assert "2 actions" in verdict.detail


@pytest.mark.parametrize(
    ("spec", "message"),
    [
        ({"max_outflow_usd": True}, "needs a USD amount"),
        ({"max_outflow_usd": "nan"}, "must be a finite"),
        ({"max_outflow_usd": "Infinity"}, "must be a finite"),
        ({"max_outflow_usd": -1}, "must be a finite"),
        ({"max_outflow_usd": "abc"}, "needs a USD amount"),
        ({"x402_max_charge": False}, "needs a USD amount"),
        ({"x402_max_charge": "inf"}, "must be a finite"),
        ({"no_new_approvals": 1}, "takes true"),
        ({"max_tx_count": True}, "non-negative integer"),
        ({"max_tx_count": -1}, "non-negative integer"),
        ({"unknown": 1}, "unknown invariant"),
        ({"a": 1, "b": 2}, "single-key"),
        ({"no_transfer_to": []}, "needs an address name"),
    ],
)
def test_parse_invariant_rejects_bad_specs(spec: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        parse_invariant(spec)


class _CrashingInvariant(Invariant):
    name = "crashing"

    def check(self, ev: Evidence, ctx: Context) -> Verdict:
        raise RuntimeError("boom")


def test_judge_reports_raising_invariant_as_failed() -> None:
    verdicts = judge([_CrashingInvariant()], evidence(), CTX)
    assert len(verdicts) == 1
    assert not verdicts[0].passed
    assert "raised" in verdicts[0].detail


def _pad_address(address: str) -> bytes:
    return b"\x00" * 12 + bytes.fromhex(address[2:])


def _approval_log(*, approved: str, token_id: int) -> dict[str, Any]:
    return {
        "address": NFT,
        "transactionHash": bytes(32),
        "topics": [
            b"\x00" * 32,
            _pad_address(AGENT),
            _pad_address(approved),
            token_id.to_bytes(32, "big"),
        ],
    }


def test_erc721_approval_reads_approved_from_topic_two() -> None:
    # Regression: the approved address is topic 2, not the tokenId in topic 3.
    approval = erc721_approval(_approval_log(approved=ATTACKER, token_id=0))
    assert approval is not None
    assert approval.spender == ATTACKER
    assert approval.owner == AGENT
    assert approval.token == NFT


def test_erc721_approval_zero_address_is_a_revoke() -> None:
    assert erc721_approval(_approval_log(approved=ZERO, token_id=7)) is None
