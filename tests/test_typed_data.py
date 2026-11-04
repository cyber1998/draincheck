# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""The Python EIP-3009 signing path hashes exactly what TestUSDC and real USDC hash.
Each test rebuilds the EIP-712 digest with the contracts' formula."""

from __future__ import annotations

from eth_abi.abi import encode
from eth_account import Account
from eth_account.messages import _hash_eip191_message, encode_typed_data
from eth_utils.crypto import keccak

from draincheck.facilitator.eip3009 import (
    TRANSFER_WITH_AUTHORIZATION_TYPES,
    Authorization,
    domain,
    recover_signer,
    sign_authorization,
)
from draincheck.fork.usdc import USDC_ADDRESS

# Anvil dev account 0.
KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
PAYER = Account.from_key(KEY).address
PAY_TO = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
FACILITATOR = "0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f"


def _digest(domain_separator: bytes, struct_hash: bytes) -> bytes:
    return keccak(b"\x19\x01" + domain_separator + struct_hash)


def test_eip3009_digest_matches_usdc_formula() -> None:
    auth = Authorization(PAYER, PAY_TO, 10_000, 0, 2**40, "0x" + "ab" * 32)
    domain_sep = keccak(
        encode(
            ["bytes32", "bytes32", "bytes32", "uint256", "address"],
            [
                keccak(
                    text="EIP712Domain(string name,string version,uint256 chainId,"
                    "address verifyingContract)"
                ),
                keccak(text="USD Coin"),
                keccak(text="2"),
                31337,
                USDC_ADDRESS,
            ],
        )
    )
    typehash = keccak(
        text="TransferWithAuthorization(address from,address to,uint256 value,"
        "uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    )
    struct_hash = keccak(
        encode(
            ["bytes32", "address", "address", "uint256", "uint256", "uint256", "bytes32"],
            [typehash, PAYER, PAY_TO, 10_000, 0, 2**40, bytes.fromhex("ab" * 32)],
        )
    )
    message = encode_typed_data(
        domain_data=domain(),
        message_types=TRANSFER_WITH_AUTHORIZATION_TYPES,
        message_data=auth.message(),
    )
    assert _hash_eip191_message(message) == _digest(domain_sep, struct_hash)
    assert recover_signer(auth, sign_authorization(KEY, auth)) == PAYER
