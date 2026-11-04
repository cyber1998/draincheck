# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Collect what happened on chain during one trial.

The oracle never sees the agent's text. It sees two state captures (before and after the
trial) and the blocks mined in between: transactions, call traces, and the Transfer,
Approval and AuthorizationUsed logs that involve the agent's wallets.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from eth_utils.crypto import keccak
from web3 import Web3

from draincheck.fork.usdc import usdc_contract

TRANSFER_TOPIC = "0x" + keccak(text="Transfer(address,address,uint256)").hex()
APPROVAL_TOPIC = "0x" + keccak(text="Approval(address,address,uint256)").hex()
APPROVAL_FOR_ALL_TOPIC = "0x" + keccak(text="ApprovalForAll(address,address,bool)").hex()
AUTHORIZATION_USED_TOPIC = "0x" + keccak(text="AuthorizationUsed(address,bytes32)").hex()

NATIVE = "native"
# Recorded as `after` when an approved allowance cannot be read back.
UNKNOWN_ALLOWANCE = 2**256 - 1


def _topic(address: str) -> str:
    return "0x" + Web3.to_checksum_address(address)[2:].lower().rjust(64, "0")


def _addr(topic: Any) -> str:
    raw = bytes(topic) if not isinstance(topic, str) else bytes.fromhex(topic.removeprefix("0x"))
    return Web3.to_checksum_address(raw[-20:])


def _hex(value: Any) -> str:
    if isinstance(value, str):
        return "0x" + value.removeprefix("0x").lower()
    return "0x" + bytes(value).hex()


def _int(data: Any) -> int:
    raw = bytes(data) if not isinstance(data, str) else bytes.fromhex(data.removeprefix("0x"))
    return int.from_bytes(raw, "big") if raw else 0


@dataclass(frozen=True)
class StateCapture:
    """Balances at one block. `balances[asset][address]`, asset is NATIVE or a token."""

    block: int
    balances: dict[str, dict[str, int]]
    nonces: dict[str, int]

    def balance(self, asset: str, address: str) -> int:
        return self.balances.get(asset, {}).get(Web3.to_checksum_address(address), 0)


@dataclass(frozen=True)
class Movement:
    """Value that moved out of an agent wallet, or into a watched address.

    `asset` is NATIVE or a token address. `amount` is None for an NFT (ERC-721) transfer.
    `direct` is True when the agent wallet is the sender; False for value that reached
    `to` inside a transaction the agent sent (for example through a router).
    """

    tx_hash: str
    asset: str
    sender: str
    to: str
    amount: int | None
    direct: bool = True


@dataclass(frozen=True)
class NewApproval:
    """An allowance an agent wallet granted (approve, permit or setApprovalForAll)."""

    tx_hash: str
    token: str
    owner: str
    spender: str
    before: int
    after: int


@dataclass(frozen=True)
class Settlement:
    """An EIP-3009 authorization signed by an agent wallet and spent on chain."""

    tx_hash: str
    token: str
    payer: str
    pay_to: str
    amount: int


@dataclass
class Evidence:
    """Everything the invariants may look at for one trial."""

    wallets: frozenset[str]
    pre: StateCapture
    post: StateCapture
    agent_txs: list[dict[str, Any]] = field(default_factory=list)
    movements: list[Movement] = field(default_factory=list)
    approvals: list[NewApproval] = field(default_factory=list)
    settlements: list[Settlement] = field(default_factory=list)
    gas_spent: dict[str, int] = field(default_factory=dict)
    trace_supported: bool = True

    def native_net_outflow(self, wallet: str) -> int:
        """How much native value the wallet lost, not counting gas it paid."""
        lost = self.pre.balance(NATIVE, wallet) - self.post.balance(NATIVE, wallet)
        return max(0, lost - self.gas_spent.get(wallet, 0))


def capture(
    w3: Web3, addresses: Iterable[str], tokens: Iterable[str], block: int | None = None
) -> StateCapture:
    """Read native and token balances (and nonces) of `addresses` at `block`."""
    number = w3.eth.block_number if block is None else block
    addrs = sorted({Web3.to_checksum_address(a) for a in addresses})
    balances: dict[str, dict[str, int]] = {
        NATIVE: {a: w3.eth.get_balance(a, block_identifier=number) for a in addrs}
    }
    for token in sorted({Web3.to_checksum_address(t) for t in tokens}):
        if len(w3.eth.get_code(token, block_identifier=number)) == 0:
            balances[token] = dict.fromkeys(addrs, 0)
            continue
        contract = usdc_contract(w3, token)  # only balanceOf is used: plain ERC-20
        balances[token] = {
            a: int(contract.functions.balanceOf(a).call(block_identifier=number)) for a in addrs
        }
    nonces: dict[str, int] = {
        a: int(w3.eth.get_transaction_count(a, block_identifier=number)) for a in addrs
    }
    return StateCapture(block=number, balances=balances, nonces=nonces)


def _logs(w3: Web3, start: int, end: int, topics: list[Any]) -> list[Any]:
    if end < start:
        return []
    return list(w3.eth.get_logs({"fromBlock": start, "toBlock": end, "topics": topics}))


def _trace_value_calls(w3: Web3, tx_hash: str) -> list[dict[str, Any]] | None:
    """All call frames that carry value, via the callTracer. None if tracing fails."""
    try:
        trace = w3.provider.make_request(
            "debug_traceTransaction",  # type: ignore[arg-type]
            [tx_hash, {"tracer": "callTracer"}],
        )
    except Exception:  # any tracing failure means "no trace"
        return None
    result = trace.get("result")
    if not isinstance(result, dict):
        return None
    frames: list[dict[str, Any]] = []
    stack = [result]
    while stack:
        frame = stack.pop()
        if int(str(frame.get("value", "0x0")), 16) > 0 and frame.get("type") in {
            "CALL",
            "CREATE",
            "CREATE2",
            "SELFDESTRUCT",
        }:
            frames.append(frame)
        stack.extend(frame.get("calls", []) or [])
    return frames


def erc721_approval(log: Any) -> NewApproval | None:
    """An ERC-721 ``Approval(owner, approved, tokenId)`` log as a new approval.

    The approved address is topic 2. Approving the zero address is a revoke, not a grant.
    """
    topics = log["topics"]
    approved = _addr(topics[2])
    if int(approved, 16) == 0:
        return None
    token = Web3.to_checksum_address(log["address"])
    return NewApproval(_hex(log["transactionHash"]), token, _addr(topics[1]), approved, 0, 1)


def collect(
    w3: Web3,
    wallets: Iterable[str],
    pre: StateCapture,
    post: StateCapture,
) -> Evidence:
    """Build the evidence for blocks ``pre.block + 1 .. post.block``."""
    wallet_set = frozenset(Web3.to_checksum_address(w) for w in wallets)
    ev = Evidence(wallets=wallet_set, pre=pre, post=post)
    start, end = pre.block + 1, post.block
    wallet_topics = [_topic(w) for w in sorted(wallet_set)]

    # Transactions the agent's wallets sent, their gas and native value (incl. internal).
    for number in range(start, end + 1):
        block = w3.eth.get_block(number, full_transactions=True)
        for tx in block["transactions"]:
            if isinstance(tx, bytes):  # pragma: no cover - full_transactions=True
                continue
            sender = Web3.to_checksum_address(tx["from"])
            if sender not in wallet_set:
                continue
            tx_hash = _hex(tx["hash"])
            receipt = w3.eth.get_transaction_receipt(tx["hash"])
            ev.agent_txs.append({"hash": tx_hash, "from": sender, "to": tx.get("to")})
            gas = int(receipt["gasUsed"]) * int(receipt["effectiveGasPrice"])
            ev.gas_spent[sender] = ev.gas_spent.get(sender, 0) + gas
            if receipt["status"] != 1:
                continue
            frames = _trace_value_calls(w3, tx_hash)
            if frames is None:
                ev.trace_supported = False
                to = tx.get("to")
                if to is not None and int(tx["value"]) > 0:
                    frames = [{"from": sender, "to": to, "value": hex(int(tx["value"]))}]
                else:
                    frames = []
            for frame in frames:
                frame_from = Web3.to_checksum_address(str(frame["from"]))
                frame_to = frame.get("to")
                if frame_to is None:
                    continue
                ev.movements.append(
                    Movement(
                        tx_hash=tx_hash,
                        asset=NATIVE,
                        sender=frame_from,
                        to=Web3.to_checksum_address(str(frame_to)),
                        amount=int(str(frame["value"]), 16),
                        direct=frame_from in wallet_set,
                    )
                )
            # Token transfers inside the agent's own transactions that did not come from
            # its wallet (e.g. a router paying a third party with the agent's funds).
            for log in receipt["logs"]:
                topics = log["topics"]
                if len(topics) >= 3 and _hex(topics[0]) == TRANSFER_TOPIC:
                    log_from = _addr(topics[1])
                    if log_from in wallet_set:
                        continue  # counted below with every other direct transfer
                    ev.movements.append(
                        Movement(
                            tx_hash=tx_hash,
                            asset=Web3.to_checksum_address(log["address"]),
                            sender=log_from,
                            to=_addr(topics[2]),
                            amount=_int(log["data"]) if len(topics) == 3 else None,
                            direct=False,
                        )
                    )

    # Token transfers out of the agent's wallets, whoever submitted the transaction.
    for log in _logs(w3, start, end, [TRANSFER_TOPIC, wallet_topics]):
        topics = log["topics"]
        if len(topics) < 3:
            continue
        ev.movements.append(
            Movement(
                tx_hash=_hex(log["transactionHash"]),
                asset=Web3.to_checksum_address(log["address"]),
                sender=_addr(topics[1]),
                to=_addr(topics[2]),
                amount=_int(log["data"]) if len(topics) == 3 else None,
            )
        )

    # Allowances granted by the agent's wallets.
    for log in _logs(w3, start, end, [APPROVAL_TOPIC, wallet_topics]):
        topics = log["topics"]
        token = Web3.to_checksum_address(log["address"])
        owner, spender = _addr(topics[1]), _addr(topics[2])
        if len(topics) == 4:  # ERC-721 single-token approval
            approval = erc721_approval(log)
            if approval is not None:
                ev.approvals.append(approval)
            continue
        read_before = _allowance(w3, token, owner, spender, pre.block)
        read_after = _allowance(w3, token, owner, spender, post.block)
        # If the allowance cannot be read (not an ERC-20, or allowance() reverts), an
        # Approval was still emitted for the agent, so fail closed: count it as unlimited.
        before = read_before if read_before is not None and read_after is not None else 0
        after = read_after if read_after is not None else UNKNOWN_ALLOWANCE
        if after > before:
            ev.approvals.append(
                NewApproval(_hex(log["transactionHash"]), token, owner, spender, before, after)
            )
    for log in _logs(w3, start, end, [APPROVAL_FOR_ALL_TOPIC, wallet_topics]):
        if _int(log["data"]) != 0:
            topics = log["topics"]
            ev.approvals.append(
                NewApproval(
                    _hex(log["transactionHash"]),
                    Web3.to_checksum_address(log["address"]),
                    _addr(topics[1]),
                    _addr(topics[2]),
                    0,
                    1,
                )
            )

    # EIP-3009 settlements: AuthorizationUsed by an agent wallet, and the transfer it paid.
    for log in _logs(w3, start, end, [AUTHORIZATION_USED_TOPIC, wallet_topics]):
        token = Web3.to_checksum_address(log["address"])
        payer = _addr(log["topics"][1])
        tx_hash = _hex(log["transactionHash"])
        receipt = w3.eth.get_transaction_receipt(log["transactionHash"])
        for tlog in receipt["logs"]:
            t = tlog["topics"]
            if (
                len(t) == 3
                and _hex(t[0]) == TRANSFER_TOPIC
                and Web3.to_checksum_address(tlog["address"]) == token
                and _addr(t[1]) == payer
            ):
                ev.settlements.append(
                    Settlement(tx_hash, token, payer, _addr(t[2]), _int(tlog["data"]))
                )
    return ev


def _allowance(w3: Web3, token: str, owner: str, spender: str, block: int) -> int | None:
    """``allowance(owner, spender)`` at `block`, or None if the contract cannot answer."""
    try:
        value: int = (
            usdc_contract(w3, token)
            .functions.allowance(owner, spender)
            .call(block_identifier=block)
        )
    except Exception:  # unknown token shape
        return None
    return value
