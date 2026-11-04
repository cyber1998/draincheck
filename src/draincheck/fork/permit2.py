# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Permit2 and the x402 ``upto`` proxy for the sandbox.

On a plain local chain, :func:`ensure_upto_contracts` installs two MINIMAL TEST STAND-INS
with ``anvil_setCode``: ``MiniPermit2`` (only the SignatureTransfer witness path of
Permit2) and ``X402UptoProxy``. They are not a Permit2 implementation. They are installed
only where the canonical address has no code. On a Base fork the real deployed contracts
are used and never overwritten.
"""

from __future__ import annotations

from web3 import Web3

from draincheck.contracts import load_artifact
from draincheck.fork.usdc import LocalNode, _w3

# Canonical Permit2 address (same on every EVM chain).
PERMIT2_ADDRESS = Web3.to_checksum_address("0x000000000022D473030F116dDEE9F6B43aC78BA3")
# x402 upto proxy address from specs/schemes/upto/scheme_upto_evm.md.
UPTO_PROXY_ADDRESS = Web3.to_checksum_address("0x4020A4f3b7b90ccA423B9fabCc0CE57C6C240002")


class MissingContractError(RuntimeError):
    """Raised when a fork lacks a contract Draincheck must not install there."""


def ensure_upto_contracts(node: LocalNode) -> tuple[str, str]:
    """Make sure Permit2 and the upto proxy exist; return their addresses.

    Installs the local stand-ins only on a plain local chain and only into empty
    addresses. On a fork, a missing contract is an error, never an install.
    """
    w3 = _w3(node)
    for address, artifact in (
        (PERMIT2_ADDRESS, "MiniPermit2"),
        (UPTO_PROXY_ADDRESS, "X402UptoProxy"),
    ):
        if len(w3.eth.get_code(address)) > 0:
            continue
        if node.is_fork:
            raise MissingContractError(f"{artifact} target {address} has no code on the fork")
        code = load_artifact(artifact)["deployedBytecode"]
        node.rpc("anvil_setCode", [address, "0x" + str(code).removeprefix("0x")])
    return PERMIT2_ADDRESS, UPTO_PROXY_ADDRESS
