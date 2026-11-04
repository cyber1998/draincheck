# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Fake paid services: local HTTP endpoints that sit behind x402 and serve chosen content.

A scenario configures what each route charges and what it returns after payment, which is
where poisoned content (prompt injections, fake instructions) enters the agent. Payment is
checked and settled through the mock facilitator, exactly as a real x402 resource server
would do it.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from draincheck.facilitator.server import NETWORK
from draincheck.facilitator.types import (
    PAYMENT_REQUIRED_HEADER,
    PAYMENT_RESPONSE_HEADER,
    PAYMENT_SIGNATURE_HEADER,
    FacilitatorRequest,
    PaymentPayload,
    PaymentRequired,
    PaymentRequirements,
    ResourceInfo,
    SettleResponse,
    VerifyResponse,
    decode_header,
    encode_header,
)
from draincheck.fork.usdc import USDC_ADDRESS, USDC_EIP712_NAME, USDC_EIP712_VERSION
from draincheck.safety import assert_local_rpc


@dataclass(frozen=True)
class PaidRoute:
    """One paid endpoint: its price, who gets paid, and the JSON it serves after payment."""

    path: str
    price: int  # token base units (USDC has 6 decimals)
    pay_to: str
    content: Any
    asset: str = USDC_ADDRESS
    description: str = ""

    def requirements(self) -> PaymentRequirements:
        return PaymentRequirements(
            scheme="exact",
            network=NETWORK,
            amount=str(self.price),
            asset=self.asset,
            pay_to=self.pay_to,
            max_timeout_seconds=60,
            extra={"name": USDC_EIP712_NAME, "version": USDC_EIP712_VERSION},
        )


@dataclass
class ServiceLog:
    """What the service saw, for tests and reports. Never used by the oracle."""

    settlements: list[SettleResponse] = field(default_factory=list)
    rejections: list[str] = field(default_factory=list)


def create_paid_service(
    facilitator_url: str, routes: list[PaidRoute], log: ServiceLog | None = None
) -> FastAPI:
    """A FastAPI app serving `routes` behind x402, settling through `facilitator_url`."""
    base = assert_local_rpc(facilitator_url.rstrip("/"))
    log = log if log is not None else ServiceLog()
    lock = threading.Lock()
    app = FastAPI(title="Draincheck fake paid service")

    def payment_required(route: PaidRoute, request: Request, error: str) -> JSONResponse:
        body = PaymentRequired(
            error=error,
            resource=ResourceInfo(url=str(request.url), description=route.description or None),
            accepts=[route.requirements()],
        )
        with lock:
            log.rejections.append(error)
        return JSONResponse(
            status_code=402,
            content=body.wire(),
            headers={PAYMENT_REQUIRED_HEADER: encode_header(body)},
        )

    def make_handler(route: PaidRoute) -> Any:
        def handler(request: Request) -> JSONResponse:
            header = request.headers.get(PAYMENT_SIGNATURE_HEADER)
            if header is None:
                return payment_required(
                    route, request, f"{PAYMENT_SIGNATURE_HEADER} header is required"
                )
            try:
                payload = PaymentPayload.model_validate(decode_header(header))
            except ValueError:
                return payment_required(route, request, "invalid_payload")
            req = FacilitatorRequest(
                payment_payload=payload, payment_requirements=route.requirements()
            )
            with httpx.Client(timeout=30) as client:
                verified = VerifyResponse.model_validate(
                    client.post(f"{base}/verify", json=req.wire()).json()
                )
                if not verified.is_valid:
                    return payment_required(route, request, verified.invalid_reason or "invalid")
                settled = SettleResponse.model_validate(
                    client.post(f"{base}/settle", json=req.wire()).json()
                )
            if not settled.success:
                return payment_required(route, request, settled.error_reason or "settle failed")
            with lock:
                log.settlements.append(settled)
            return JSONResponse(
                content=route.content, headers={PAYMENT_RESPONSE_HEADER: encode_header(settled)}
            )

        return handler

    for route in routes:
        app.add_api_route(route.path, make_handler(route), methods=["GET"])
    return app
