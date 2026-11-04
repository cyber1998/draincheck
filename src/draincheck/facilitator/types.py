# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""x402 v2 wire types (https://github.com/x402-foundation/x402, specs/x402-specification-v2.md).

Implemented here rather than imported from the ``x402`` package: its EVM payload types are
not pydantic models, its response models carry SDK-internal fields, and this mock must
parse hostile or malformed payloads on its own terms. Field names follow the spec exactly.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

X402_VERSION = 2
PAYMENT_REQUIRED_HEADER = "PAYMENT-REQUIRED"
PAYMENT_SIGNATURE_HEADER = "PAYMENT-SIGNATURE"
PAYMENT_RESPONSE_HEADER = "PAYMENT-RESPONSE"


class WireModel(BaseModel):
    """camelCase on the wire, snake_case in Python; unknown fields are kept."""

    model_config = ConfigDict(
        alias_generator=to_camel, populate_by_name=True, serialize_by_alias=True, extra="allow"
    )

    def wire(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class ResourceInfo(WireModel):
    url: str
    description: str | None = None
    mime_type: str | None = None


class PaymentRequirements(WireModel):
    scheme: str
    network: str
    amount: str
    asset: str
    pay_to: str
    max_timeout_seconds: int = 60
    extra: dict[str, Any] = Field(default_factory=dict)


class PaymentRequired(WireModel):
    x402_version: int = Field(default=X402_VERSION, alias="x402Version")
    error: str | None = None
    resource: ResourceInfo
    accepts: list[PaymentRequirements]


class PaymentPayload(WireModel):
    x402_version: int = Field(default=X402_VERSION, alias="x402Version")
    resource: ResourceInfo | None = None
    accepted: PaymentRequirements
    payload: dict[str, Any]


class FacilitatorRequest(WireModel):
    """Body of both ``POST /verify`` and ``POST /settle``."""

    x402_version: int = Field(default=X402_VERSION, alias="x402Version")
    payment_payload: PaymentPayload
    payment_requirements: PaymentRequirements


class VerifyResponse(WireModel):
    is_valid: bool
    invalid_reason: str | None = None
    invalid_message: str | None = None
    payer: str | None = None


class SettleResponse(WireModel):
    success: bool
    error_reason: str | None = None
    error_message: str | None = None
    payer: str | None = None
    transaction: str = ""
    network: str
    amount: str | None = None


def encode_header(model: WireModel) -> str:
    """Base64 JSON, as the v2 HTTP transport puts it in a header."""
    return base64.b64encode(json.dumps(model.wire()).encode()).decode()


def decode_header(value: str) -> dict[str, Any]:
    """Inverse of :func:`encode_header`. Raises ValueError on malformed input."""
    try:
        data = json.loads(base64.b64decode(value, validate=True))
    except (ValueError, TypeError) as err:
        raise ValueError("header is not base64 JSON") from err
    if not isinstance(data, dict):
        raise ValueError("header JSON is not an object")
    return data
