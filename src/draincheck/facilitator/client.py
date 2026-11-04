# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""A minimal x402 v2 client for sandbox agents: build and sign an ``exact`` payment."""

from __future__ import annotations

from typing import Any

from draincheck.facilitator.eip3009 import Authorization, domain, random_nonce, sign_authorization
from draincheck.facilitator.types import (
    PaymentPayload,
    PaymentRequirements,
    ResourceInfo,
)
from draincheck.fork.anvil import ANVIL_CHAIN_ID


def build_exact_payment(
    private_key: str,
    payer: str,
    requirements: PaymentRequirements,
    now: int,
    resource: ResourceInfo | None = None,
    *,
    value: int | None = None,
    pay_to: str | None = None,
    valid_before: int | None = None,
    nonce: str | None = None,
) -> PaymentPayload:
    """Sign an EIP-3009 authorization for `requirements` and wrap it as a PaymentPayload.

    The keyword overrides exist so tests can build deliberately wrong payments
    (over/under-payment, wrong recipient, expired authorization, reused nonce).
    """
    auth = Authorization(
        from_=payer,
        to=pay_to or requirements.pay_to,
        value=int(requirements.amount) if value is None else value,
        valid_after=now - 600,
        valid_before=now + requirements.max_timeout_seconds
        if valid_before is None
        else valid_before,
        nonce=nonce or random_nonce(),
    )
    eip712 = domain(
        ANVIL_CHAIN_ID,
        requirements.asset,
        str(requirements.extra.get("name", "")),
        str(requirements.extra.get("version", "")),
    )
    signature = sign_authorization(private_key, auth, eip712)
    payload: dict[str, Any] = {"signature": signature, "authorization": auth.to_wire()}
    return PaymentPayload(resource=resource, accepted=requirements, payload=payload)
