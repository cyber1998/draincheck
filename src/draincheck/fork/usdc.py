# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Test USDC for the sandbox.

On a Base fork the real USDC contract is already there; :func:`fund_usdc` writes the
account's balance straight into its storage with ``anvil_setStorageAt``.

On a plain local chain (the default, and what CI uses) :func:`ensure_usdc` installs
``TestUSDC``, a stand-in with 6 decimals, the same EIP-712 domain name and version as
USDC, EIP-2612 permit and EIP-3009 authorizations. It is installed at the same address
USDC has on Base, so scenarios and agents use one address in both modes. Signatures still
cannot replay on Base: the EIP-712 domain includes chain id 31337.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any, Protocol

from eth_utils.crypto import keccak
from web3 import Web3
from web3.contract import Contract

from draincheck.contracts import load_artifact
from draincheck.safety import assert_local_rpc

# Native USDC on Base (Circle). The local stand-in is installed at the same address.
USDC_ADDRESS = Web3.to_checksum_address("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
USDC_DECIMALS = 6
USDC_UNIT = 10**USDC_DECIMALS
# EIP-712 domain of USDC on Base, which TestUSDC copies.
USDC_EIP712_NAME = "USD Coin"
USDC_EIP712_VERSION = "2"
# Mapping slots tried when looking for the balance mapping. TestUSDC uses 0; Circle's
# FiatToken v2.2 (Base USDC) uses 9.
_BALANCE_SLOT_CANDIDATES = (0, 9, *range(1, 9), *range(10, 32))


class FundingError(RuntimeError):
    """Raised when an account could not be funded with test USDC."""


class LocalNode(Protocol):
    """What the USDC helpers need from a node: a local RPC URL and a fork flag."""

    rpc_url: str

    @property
    def is_fork(self) -> bool: ...

    def rpc(self, method: str, params: list[Any] | None = None) -> Any: ...


def usdc_artifact() -> dict[str, Any]:
    """ABI and bytecode of the TestUSDC stand-in."""
    return load_artifact("TestUSDC")


def usdc_abi() -> list[dict[str, Any]]:
    """The TestUSDC ABI. Its ERC-20, permit and EIP-3009 parts match Base USDC."""
    abi: list[dict[str, Any]] = usdc_artifact()["abi"]
    return abi


def usdc_contract(w3: Web3, address: str = USDC_ADDRESS) -> Contract:
    """A web3 contract handle for USDC (or TestUSDC) at `address`."""
    return w3.eth.contract(address=Web3.to_checksum_address(address), abi=usdc_abi())


def to_units(amount: Decimal | int | str) -> int:
    """Convert a USDC amount (e.g. ``"12.5"``) to base units (6 decimals)."""
    value = Decimal(amount) * USDC_UNIT
    if value != value.to_integral_value() or value < 0:
        raise ValueError(f"{amount!r} is not a non-negative USDC amount with at most 6 decimals")
    return int(value)


def from_units(units: int) -> Decimal:
    """Convert USDC base units to a USDC amount."""
    return Decimal(units) / Decimal(USDC_UNIT)


def _w3(node: LocalNode) -> Web3:
    return Web3(Web3.HTTPProvider(assert_local_rpc(node.rpc_url)))


def ensure_usdc(node: LocalNode) -> str:
    """Make sure USDC exists on `node` and return its address.

    On a fork the real contract must already be there. On a local chain TestUSDC's runtime
    code is installed with ``anvil_setCode`` if the address is empty.
    """
    w3 = _w3(node)
    if len(w3.eth.get_code(USDC_ADDRESS)) > 0:
        return USDC_ADDRESS
    if node.is_fork:
        raise FundingError(f"no USDC contract at {USDC_ADDRESS} on the fork; is it Base?")
    node.rpc(
        "anvil_setCode",
        [USDC_ADDRESS, "0x" + usdc_artifact()["deployedBytecode"].removeprefix("0x")],
    )
    return USDC_ADDRESS


def balance_slot_key(holder: str, mapping_slot: int) -> str:
    """Storage key of ``mapping(address => uint256)`` at `mapping_slot` for `holder`."""
    key = keccak(
        bytes.fromhex(Web3.to_checksum_address(holder)[2:].rjust(64, "0"))
        + mapping_slot.to_bytes(32, "big")
    )
    return "0x" + key.hex()


def _word(value: int) -> str:
    return "0x" + value.to_bytes(32, "big").hex()


def usdc_balance(node: LocalNode, holder: str, token: str = USDC_ADDRESS) -> int:
    """USDC balance of `holder` in base units."""
    units: int = (
        usdc_contract(_w3(node), token).functions.balanceOf(Web3.to_checksum_address(holder)).call()
    )
    return units


def set_usdc_balance(node: LocalNode, holder: str, units: int, token: str = USDC_ADDRESS) -> None:
    """Set `holder`'s USDC balance to exactly `units` by writing the token's storage.

    Finds the balance mapping by writing each candidate slot and checking ``balanceOf``;
    a candidate that does not match is restored. Raises FundingError if none matches.
    """
    if not 0 <= units < 2**255:  # FiatToken v2.2 keeps a blacklist flag in the top bit
        raise ValueError("balance out of range")
    holder = Web3.to_checksum_address(holder)
    # A sentinel that cannot be confused with an existing balance.
    probe = units if units != usdc_balance(node, holder, token) else units + 1
    for slot in _BALANCE_SLOT_CANDIDATES:
        key = balance_slot_key(holder, slot)
        old = node.rpc("eth_getStorageAt", [token, key, "latest"])
        node.rpc("anvil_setStorageAt", [token, key, _word(probe)])
        if usdc_balance(node, holder, token) == probe:
            if probe != units:
                node.rpc("anvil_setStorageAt", [token, key, _word(units)])
            if usdc_balance(node, holder, token) != units:
                raise FundingError(f"balanceOf({holder}) did not read back {units}")
            return
        node.rpc("anvil_setStorageAt", [token, key, _word(int(old, 16))])
    raise FundingError(f"could not find the balance slot of {token}")


def fund_usdc(node: LocalNode, holder: str, amount: Decimal | int | str) -> int:
    """Give `holder` exactly `amount` test USDC (whole-dollar units, e.g. ``1000``).

    Installs TestUSDC first on a local chain. Returns the new balance in base units,
    verified through ``balanceOf``.
    """
    token = ensure_usdc(node)
    units = to_units(amount)
    set_usdc_balance(node, holder, units, token)
    return units
