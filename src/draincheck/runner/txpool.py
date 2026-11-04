# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Keep a trial's transactions inside the trial.

The oracle judges the blocks between two captures. A transaction the agent leaves pending
(automine off, a nonce gap) or sends after the capture would escape that window, or land in
the next trial after the revert. These checks turn such a transaction into an evidence gap,
which fails the trial.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from web3 import Web3

from draincheck.fork.anvil import AnvilProcess

# evm_mine calls before giving up on a txpool that will not drain.
MAX_MINE_ROUNDS = 32


def _pooled_txs(node: AnvilProcess, wallets: Iterable[str]) -> int:
    """Transactions from `wallets` waiting in the node's txpool, pending or queued."""
    content = node.rpc("txpool_content") or {}
    wanted = {w.lower() for w in wallets}
    return sum(
        len(by_nonce)
        for section in ("pending", "queued")
        for sender, by_nonce in (content.get(section) or {}).items()
        if sender.lower() in wanted
    )


def unattributed_txs(
    node: AnvilProcess, expected_nonces: Mapping[str, int], when: str
) -> list[str]:
    """Agent transactions outside the captured window: nonce moved or txpool not empty."""
    problems = []
    for wallet, expected in expected_nonces.items():
        now = node.w3.eth.get_transaction_count(Web3.to_checksum_address(wallet), "pending")
        if now != expected:
            problems.append(f"{wallet} nonce is {now} {when}, expected {expected}")
    stuck = _pooled_txs(node, expected_nonces)
    if stuck:
        problems.append(f"{stuck} agent transaction(s) in the txpool {when}")
    return problems


def mine_pending(node: AnvilProcess, wallets: Iterable[str]) -> list[str]:
    """Mine what the agent left in the txpool; return what still could not be mined.

    Catches transactions sent with automine off. A transaction that stays (a nonce gap, a
    fee too low) never executes inside the trial, so the oracle cannot judge it.
    """
    for _ in range(MAX_MINE_ROUNDS):
        status = node.rpc("txpool_status") or {}
        if int(str(status.get("pending", "0x0")), 16) == 0:
            break
        node.rpc("evm_mine")
    mined = {
        w: node.w3.eth.get_transaction_count(Web3.to_checksum_address(w), "latest") for w in wallets
    }
    return unattributed_txs(node, mined, "after mining")
