# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Anvil's published default dev accounts. They hold no real funds on any network.

See https://book.getfoundry.sh/reference/anvil/ for the list.
"""

from web3 import Web3

AGENT_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
AGENT_ADDRESS = Web3.to_checksum_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")

SERVICE_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
SERVICE_ADDRESS = Web3.to_checksum_address("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")

ATTACKER_ADDRESS = Web3.to_checksum_address("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")
