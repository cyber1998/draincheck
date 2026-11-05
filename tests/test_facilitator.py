# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""The mock x402 facilitator: /supported, /verify rejections, /settle and a paid service."""

from __future__ import annotations

from typing import Any

import pytest

from draincheck.facilitator.client import build_exact_payment
from draincheck.facilitator.server import (
    NETWORK,
    Facilitator,
    create_facilitator_app,
    serve_in_thread,
)
from draincheck.facilitator.services import PaidRoute, ServiceLog, create_paid_service
from draincheck.facilitator.types import (
    PAYMENT_SIGNATURE_HEADER,
    FacilitatorRequest,
    PaymentRequired,
    PaymentRequirements,
    encode_header,
)
from draincheck.fork import AnvilProcess
from draincheck.fork.accounts import (
    AGENT_ADDRESS,
    AGENT_KEY,
    ATTACKER_ADDRESS,
    SERVICE_ADDRESS,
)
from draincheck.fork.anvil import free_port
from draincheck.fork.usdc import USDC_UNIT, fund_usdc, usdc_balance
from draincheck.safety import local_http_client

PRICE = 10_000


def _setup(anvil: AnvilProcess) -> tuple[Facilitator, PaymentRequirements]:
    fund_usdc(anvil, AGENT_ADDRESS, 100)
    route = PaidRoute(path="/feed", price=PRICE, pay_to=SERVICE_ADDRESS, content={"ok": True})
    return Facilitator(anvil.rpc_url), route.requirements()


def _request(fac: Facilitator, reqs: PaymentRequirements, **overrides: Any) -> FacilitatorRequest:
    payment = build_exact_payment(AGENT_KEY, AGENT_ADDRESS, reqs, fac.now(), **overrides)
    return FacilitatorRequest(payment_payload=payment, payment_requirements=reqs)


@pytest.mark.anvil
def test_supported_lists_exact_on_anvil(anvil: AnvilProcess) -> None:
    fac, _ = _setup(anvil)
    with (
        serve_in_thread(create_facilitator_app(fac), free_port()) as base,
        local_http_client() as client,
    ):
        body: dict[str, Any] = client.get(base + "/supported").json()
    kinds: list[dict[str, Any]] = body["kinds"]
    assert any(k["scheme"] == "exact" and k["network"] == NETWORK for k in kinds)


@pytest.mark.anvil
def test_verify_accepts_good_payment(anvil: AnvilProcess) -> None:
    fac, reqs = _setup(anvil)
    result = fac.verify(_request(fac, reqs))
    assert result.is_valid is True
    assert result.payer == AGENT_ADDRESS


@pytest.mark.anvil
@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"value": 9_999}, "invalid_exact_evm_payload_authorization_value_mismatch"),
        ({"value": 10_001}, "invalid_exact_evm_payload_authorization_value_mismatch"),
        ({"pay_to": ATTACKER_ADDRESS}, "invalid_exact_evm_payload_recipient_mismatch"),
        ({"valid_before": "EXPIRED"}, "invalid_exact_evm_payload_authorization_valid_before"),
    ],
)
def test_verify_rejects(anvil: AnvilProcess, overrides: dict[str, Any], reason: str) -> None:
    fac, reqs = _setup(anvil)
    kwargs = dict(overrides)
    if kwargs.get("valid_before") == "EXPIRED":
        # Inside the 6 second margin the facilitator requires before expiry.
        kwargs["valid_before"] = fac.now() + 1
    result = fac.verify(_request(fac, reqs, **kwargs))
    assert result.is_valid is False
    assert result.invalid_reason == reason


@pytest.mark.anvil
def test_verify_rejects_bad_signature(anvil: AnvilProcess) -> None:
    fac, reqs = _setup(anvil)
    good = build_exact_payment(AGENT_KEY, AGENT_ADDRESS, reqs, fac.now())
    other = build_exact_payment(AGENT_KEY, AGENT_ADDRESS, reqs, fac.now(), value=1)
    # A signature over a different authorization, pasted onto the good one.
    good.payload["signature"] = other.payload["signature"]
    result = fac.verify(FacilitatorRequest(payment_payload=good, payment_requirements=reqs))
    assert result.is_valid is False
    assert result.invalid_reason == "invalid_exact_evm_payload_signature"


@pytest.mark.anvil
def test_verify_rejects_insufficient_balance(anvil: AnvilProcess) -> None:
    fac, reqs = _setup(anvil)
    fund_usdc(anvil, AGENT_ADDRESS, 0)
    result = fac.verify(_request(fac, reqs))
    assert result.is_valid is False
    assert result.invalid_reason == "invalid_exact_evm_insufficient_balance"


@pytest.mark.anvil
def test_settle_moves_usdc_and_blocks_replay(anvil: AnvilProcess) -> None:
    fac, reqs = _setup(anvil)
    req = _request(fac, reqs)

    first = fac.settle(req)
    assert first.success is True
    assert first.amount == str(PRICE)
    assert first.transaction.startswith("0x")
    assert usdc_balance(anvil, SERVICE_ADDRESS) == PRICE
    assert usdc_balance(anvil, AGENT_ADDRESS) == 100 * USDC_UNIT - PRICE

    replay = fac.settle(req)
    assert replay.success is False
    assert replay.error_reason == "invalid_exact_evm_nonce_already_used"
    assert usdc_balance(anvil, SERVICE_ADDRESS) == PRICE


@pytest.mark.anvil
def test_verify_rejects_reused_nonce(anvil: AnvilProcess) -> None:
    fac, reqs = _setup(anvil)
    first = build_exact_payment(AGENT_KEY, AGENT_ADDRESS, reqs, fac.now())
    assert fac.settle(FacilitatorRequest(payment_payload=first, payment_requirements=reqs)).success

    nonce = str(first.payload["authorization"]["nonce"])
    second = _request(fac, reqs, nonce=nonce)
    result = fac.verify(second)
    assert result.is_valid is False
    assert result.invalid_reason == "invalid_exact_evm_nonce_already_used"


@pytest.mark.anvil
def test_paid_service_402_then_content(anvil: AnvilProcess) -> None:
    fac, _ = _setup(anvil)
    route = PaidRoute(path="/feed", price=PRICE, pay_to=SERVICE_ADDRESS, content={"posts": ["hi"]})
    log = ServiceLog()
    with (
        serve_in_thread(create_facilitator_app(fac), free_port()) as fac_url,
        serve_in_thread(create_paid_service(fac_url, [route], log), free_port()) as base,
    ):
        client = local_http_client()
        challenge = client.get(base + "/feed")
        assert challenge.status_code == 402
        required = PaymentRequired.model_validate(challenge.json())
        reqs = required.accepts[0]
        assert reqs == route.requirements()

        payment = build_exact_payment(AGENT_KEY, AGENT_ADDRESS, reqs, fac.now())
        headers = {PAYMENT_SIGNATURE_HEADER: encode_header(payment)}
        paid = client.get(base + "/feed", headers=headers)
        client.close()
        assert paid.status_code == 200
        assert paid.json() == {"posts": ["hi"]}

    assert len(log.settlements) == 1
    assert usdc_balance(anvil, SERVICE_ADDRESS) == PRICE
