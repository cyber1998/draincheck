# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Permit2 ``PermitWitnessTransferFrom`` typed data for the x402 ``upto`` scheme.

Byte-compatible with real Permit2: domain {name "Permit2", chainId, verifyingContract}
(no version) and the witness type string from the x402 upto proxy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from eth_account import Account
from eth_account.messages import encode_typed_data
from web3 import Web3

from draincheck.fork.anvil import ANVIL_CHAIN_ID
from draincheck.fork.permit2 import PERMIT2_ADDRESS, UPTO_PROXY_ADDRESS

WITNESS_TYPE_STRING = (
    "Witness witness)TokenPermissions(address token,uint256 amount)"
    "Witness(address to,address facilitator,uint256 validAfter)"
)
PERMIT_WITNESS_TYPES: dict[str, list[dict[str, str]]] = {
    "PermitWitnessTransferFrom": [
        {"name": "permitted", "type": "TokenPermissions"},
        {"name": "spender", "type": "address"},
        {"name": "nonce", "type": "uint256"},
        {"name": "deadline", "type": "uint256"},
        {"name": "witness", "type": "Witness"},
    ],
    "TokenPermissions": [
        {"name": "token", "type": "address"},
        {"name": "amount", "type": "uint256"},
    ],
    "Witness": [
        {"name": "to", "type": "address"},
        {"name": "facilitator", "type": "address"},
        {"name": "validAfter", "type": "uint256"},
    ],
}


def permit2_domain(
    chain_id: int = ANVIL_CHAIN_ID, permit2: str = PERMIT2_ADDRESS
) -> dict[str, Any]:
    return {"name": "Permit2", "chainId": chain_id, "verifyingContract": permit2}


@dataclass(frozen=True)
class UptoAuthorization:
    """The ``permit2Authorization`` object of an x402 upto payload."""

    token: str
    max_amount: int
    from_: str
    nonce: int
    deadline: int
    to: str
    facilitator: str
    valid_after: int
    spender: str = UPTO_PROXY_ADDRESS

    def message(self) -> dict[str, Any]:
        return {
            "permitted": {"token": Web3.to_checksum_address(self.token), "amount": self.max_amount},
            "spender": Web3.to_checksum_address(self.spender),
            "nonce": self.nonce,
            "deadline": self.deadline,
            "witness": {
                "to": Web3.to_checksum_address(self.to),
                "facilitator": Web3.to_checksum_address(self.facilitator),
                "validAfter": self.valid_after,
            },
        }

    def to_wire(self) -> dict[str, Any]:
        return {
            "permitted": {
                "token": Web3.to_checksum_address(self.token),
                "amount": str(self.max_amount),
            },
            "from": Web3.to_checksum_address(self.from_),
            "spender": Web3.to_checksum_address(self.spender),
            "nonce": str(self.nonce),
            "deadline": str(self.deadline),
            "witness": {
                "to": Web3.to_checksum_address(self.to),
                "facilitator": Web3.to_checksum_address(self.facilitator),
                "validAfter": str(self.valid_after),
            },
        }

    @classmethod
    def from_wire(cls, data: dict[str, Any]) -> UptoAuthorization:
        nonce = str(data["nonce"])
        return cls(
            token=Web3.to_checksum_address(str(data["permitted"]["token"])),
            max_amount=int(data["permitted"]["amount"]),
            from_=Web3.to_checksum_address(str(data["from"])),
            nonce=int(nonce, 16) if nonce.startswith("0x") else int(nonce),
            deadline=int(data["deadline"]),
            to=Web3.to_checksum_address(str(data["witness"]["to"])),
            facilitator=Web3.to_checksum_address(str(data["witness"]["facilitator"])),
            valid_after=int(data["witness"]["validAfter"]),
            spender=Web3.to_checksum_address(str(data["spender"])),
        )


def sign_upto(
    private_key: str, auth: UptoAuthorization, domain: dict[str, Any] | None = None
) -> str:
    signed = Account.sign_typed_data(
        private_key,
        domain_data=domain or permit2_domain(),
        message_types=PERMIT_WITNESS_TYPES,
        message_data=auth.message(),
    )
    return "0x" + bytes(signed.signature).hex()


def recover_upto_signer(
    auth: UptoAuthorization, signature: str, domain: dict[str, Any] | None = None
) -> str:
    message = encode_typed_data(
        domain_data=domain or permit2_domain(),
        message_types=PERMIT_WITNESS_TYPES,
        message_data=auth.message(),
    )
    signer: str = Account.recover_message(message, signature=signature)
    return Web3.to_checksum_address(signer)
