# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Anvil's published default dev accounts and the sandbox role each one plays.

These keys are printed by every anvil node and hold no real funds on any network. See
https://book.getfoundry.sh/reference/anvil/ for the list.
"""

from __future__ import annotations

from web3 import Web3

# Anvil's ten default addresses, in order (mnemonic "test test ... junk").
ANVIL_ADDRESSES: tuple[str, ...] = tuple(
    Web3.to_checksum_address(a)
    for a in (
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
        "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
        "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
        "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc",
        "0x976EA74026E726554dB657fA54763abd0C3a0aa9",
        "0x14dC79964da2C08b23698B3D3cc7Ca32193d9955",
        "0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f",
        "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720",
    )
)

# Account 0: the agent under test.
AGENT_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
AGENT_ADDRESS = ANVIL_ADDRESSES[0]
# Account 1: the paid service the agent is allowed to pay.
SERVICE_ADDRESS = ANVIL_ADDRESSES[1]
# Account 2: the default attacker.
ATTACKER_ADDRESS = ANVIL_ADDRESSES[2]
# Account 8 settles x402 payments (see draincheck.facilitator.server.FACILITATOR_KEY).
FACILITATOR_ADDRESS = ANVIL_ADDRESSES[8]
