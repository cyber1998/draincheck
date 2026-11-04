# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""EIP-3009 ``TransferWithAuthorization`` typed data: build, sign and recover.

Used by sandbox agents to sign x402 ``exact`` payments and by the mock facilitator to
check them. Only anvil dev keys ever reach :func:`sign_authorization`.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any

from eth_account import Account
from eth_account.messages import encode_typed_data
from web3 import Web3

from draincheck.fork.anvil import ANVIL_CHAIN_ID
from draincheck.fork.usdc import USDC_ADDRESS, USDC_EIP712_NAME, USDC_EIP712_VERSION

TRANSFER_WITH_AUTHORIZATION_TYPES: dict[str, list[dict[str, str]]] = {
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"},
        {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
    ]
}


@dataclass(frozen=True)
class Authorization:
    """The six fields of an EIP-3009 ``TransferWithAuthorization``."""

    from_: str
    to: str
    value: int
    valid_after: int
    valid_before: int
    nonce: str  # 0x-prefixed 32-byte hex

    def message(self) -> dict[str, Any]:
        return {
            "from": Web3.to_checksum_address(self.from_),
            "to": Web3.to_checksum_address(self.to),
            "value": self.value,
            "validAfter": self.valid_after,
            "validBefore": self.valid_before,
            "nonce": bytes.fromhex(self.nonce.removeprefix("0x")),
        }

    def to_wire(self) -> dict[str, str]:
        """The x402 JSON form: every field a string."""
        return {
            "from": Web3.to_checksum_address(self.from_),
            "to": Web3.to_checksum_address(self.to),
            "value": str(self.value),
            "validAfter": str(self.valid_after),
            "validBefore": str(self.valid_before),
            "nonce": self.nonce,
        }

    @classmethod
    def from_wire(cls, data: dict[str, Any]) -> Authorization:
        nonce = str(data["nonce"])
        if len(bytes.fromhex(nonce.removeprefix("0x"))) != 32:
            raise ValueError("nonce must be 32 bytes")
        return cls(
            from_=Web3.to_checksum_address(str(data["from"])),
            to=Web3.to_checksum_address(str(data["to"])),
            value=int(data["value"]),
            valid_after=int(data["validAfter"]),
            valid_before=int(data["validBefore"]),
            nonce="0x" + nonce.removeprefix("0x").lower(),
        )


def random_nonce() -> str:
    """A fresh random 32-byte authorization nonce."""
    return "0x" + secrets.token_hex(32)


def domain(
    chain_id: int = ANVIL_CHAIN_ID,
    verifying_contract: str = USDC_ADDRESS,
    name: str = USDC_EIP712_NAME,
    version: str = USDC_EIP712_VERSION,
) -> dict[str, Any]:
    """The EIP-712 domain of USDC (or TestUSDC) on the sandbox chain."""
    return {
        "name": name,
        "version": version,
        "chainId": chain_id,
        "verifyingContract": Web3.to_checksum_address(verifying_contract),
    }


def sign_authorization(
    private_key: str, auth: Authorization, eip712_domain: dict[str, Any] | None = None
) -> str:
    """Sign `auth` with `private_key` and return the 65-byte signature as 0x hex."""
    signed = Account.sign_typed_data(
        private_key,
        domain_data=eip712_domain or domain(),
        message_types=TRANSFER_WITH_AUTHORIZATION_TYPES,
        message_data=auth.message(),
    )
    return "0x" + bytes(signed.signature).hex()


def recover_signer(
    auth: Authorization, signature: str, eip712_domain: dict[str, Any] | None = None
) -> str:
    """Return the address that signed `auth`, as a checksum address."""
    message = encode_typed_data(
        domain_data=eip712_domain or domain(),
        message_types=TRANSFER_WITH_AUTHORIZATION_TYPES,
        message_data=auth.message(),
    )
    signer: str = Account.recover_message(message, signature=signature)
    return Web3.to_checksum_address(signer)


def split_signature(signature: str) -> tuple[int, bytes, bytes]:
    """Split a 65-byte r||s||v signature into (v, r, s)."""
    raw = bytes.fromhex(signature.removeprefix("0x"))
    if len(raw) != 65:
        raise ValueError("signature must be 65 bytes")
    v = raw[64]
    if v < 27:
        v += 27
    return v, raw[:32], raw[32:64]
