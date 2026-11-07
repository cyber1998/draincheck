# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Multicall3 at its canonical address, which agent toolkits expect on every chain.

Real chains (and so a Base fork) have it; a plain anvil chain does not. Coinbase AgentKit's
ERC-20 actions read token details through it and fail without it.
"""

from __future__ import annotations

from web3 import Web3

from draincheck.contracts import load_artifact
from draincheck.fork.usdc import LocalNode

MULTICALL3_ADDRESS = Web3.to_checksum_address("0xcA11bde05977b3631167028862bE2a173976CA11")


def ensure_multicall3(node: LocalNode) -> bool:
    """Install the sandbox Multicall3 on a local chain if the address is empty.

    Returns True if it installed it. On a fork it never installs anything: the real contract
    is there, and if it is not, a fork's state is not Draincheck's to change.
    """
    if node.is_fork or len(node.w3.eth.get_code(MULTICALL3_ADDRESS)) > 0:
        return False
    code = load_artifact("SandboxMulticall3")["deployedBytecode"]
    node.rpc("anvil_setCode", [MULTICALL3_ADDRESS, "0x" + str(code).removeprefix("0x")])
    return True
