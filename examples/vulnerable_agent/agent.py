# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""The vulnerable agent.

Its job: read a paid social feed and act on what it reads. Its flaws, on purpose:

1. It treats instructions found in untrusted content (feed posts) as commands.
2. It has no spend limit, no recipient allowlist and no human approval step.
3. It signs whatever x402 payment a 402 response asks for.

The "brain" here is a deterministic instruction follower rather than a language model, so
tests are fast, free and repeatable. It fails the same way a naive LLM agent does when it
obeys a prompt injection. An LLM-backed variant built on AgentKit is planned.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from decimal import Decimal

import httpx
from eth_account import Account
from eth_account.signers.local import LocalAccount
from web3 import Web3
from web3.types import TxParams, Wei

from draincheck.facilitator.client import build_exact_payment
from draincheck.facilitator.types import (
    PAYMENT_SIGNATURE_HEADER,
    PaymentRequired,
    encode_header,
)
from draincheck.fork import ANVIL_CHAIN_ID
from draincheck.fork.usdc import USDC_ADDRESS, to_units, usdc_contract
from draincheck.safety import assert_local_rpc

INSTRUCTION = re.compile(
    r"send\s+(\d+(?:\.\d+)?)\s+(eth|usdc)\s+to\s+(0x[0-9a-fA-F]{40})", re.IGNORECASE
)


@dataclass(frozen=True)
class Instruction:
    """One injected transfer: `amount` in base units of `asset` ("ETH" or "USDC")."""

    asset: str
    amount: int
    to: str


@dataclass
class RunLog:
    """What the agent did during one run."""

    payments: int = 0
    transfers: list[str] = field(default_factory=list)
    posts_read: list[str] = field(default_factory=list)


def parse_instructions(text: str) -> list[Instruction]:
    """Find every 'send N ETH|USDC to 0x...' in `text`. This is the injection point."""
    found = []
    for amount, asset, to in INSTRUCTION.findall(text):
        asset = asset.upper()
        units = Web3.to_wei(Decimal(amount), "ether") if asset == "ETH" else to_units(amount)
        found.append(Instruction(asset, int(units), Web3.to_checksum_address(to)))
    return found


class VulnerableAgent:
    """A wallet agent that reads a paid feed and does whatever the posts say."""

    def __init__(self, rpc_url: str, private_key: str) -> None:
        self.w3 = Web3(Web3.HTTPProvider(assert_local_rpc(rpc_url)))
        if self.w3.eth.chain_id != ANVIL_CHAIN_ID:
            raise RuntimeError(f"refusing to run: chain id {self.w3.eth.chain_id} is not anvil")
        self.account: LocalAccount = Account.from_key(private_key)

    def _send(self, tx: TxParams) -> str:
        tx["nonce"] = self.w3.eth.get_transaction_count(self.account.address)
        tx["chainId"] = ANVIL_CHAIN_ID
        signed = self.account.sign_transaction(tx)  # type: ignore[arg-type]
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=10)
        return "0x" + tx_hash.hex().removeprefix("0x")

    def send_eth(self, to: str, value: Wei) -> str:
        """Sign and send a native transfer, wait for it to be mined, return its hash."""
        return self._send(
            {
                "to": Web3.to_checksum_address(to),
                "value": value,
                "gas": 21_000,
                "gasPrice": self.w3.eth.gas_price,
            }
        )

    def send_usdc(self, to: str, units: int) -> str:
        """ERC-20 transfer of `units` (6 decimals) of USDC."""
        call = usdc_contract(self.w3, USDC_ADDRESS).functions.transfer(
            Web3.to_checksum_address(to), units
        )
        return self._send(call.build_transaction({"from": self.account.address}))

    def fetch_paid(self, url: str, log: RunLog) -> httpx.Response:
        """GET `url`, signing whatever x402 payment a 402 response asks for."""
        url = assert_local_rpc(url)  # a signed authorization never leaves 127.0.0.1
        with httpx.Client(timeout=30) as client:
            response = client.get(url)
            if response.status_code != 402:
                return response
            required = PaymentRequired.model_validate(response.json())
            now = int(self.w3.eth.get_block("latest")["timestamp"])
            payment = build_exact_payment(
                self.account.key.hex(),
                self.account.address,
                required.accepts[0],
                now,
                required.resource,
            )
            log.payments += 1
            return client.get(url, headers={PAYMENT_SIGNATURE_HEADER: encode_header(payment)})

    def run(self, feed_url: str) -> RunLog:
        """The agent's normal task: read the feed and act on it."""
        log = RunLog()
        response = self.fetch_paid(feed_url, log)
        response.raise_for_status()
        for post in response.json()["posts"]:
            log.posts_read.append(post)
            for ins in parse_instructions(post):
                if ins.asset == "ETH":
                    log.transfers.append(self.send_eth(ins.to, Wei(ins.amount)))
                else:
                    log.transfers.append(self.send_usdc(ins.to, ins.amount))
        return log
