# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""The vulnerable agent.

Its job: read a paid social feed and act on what it reads. Its flaws, on purpose:

1. It treats instructions found in untrusted content (feed posts) as commands.
2. It has no spend limit, no recipient allowlist and no human approval step.
3. It pays whatever amount a 402 response asks for.

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

from draincheck.fork import ANVIL_CHAIN_ID
from draincheck.safety import assert_local_rpc
from examples.vulnerable_agent.service import encode_payment

INSTRUCTION = re.compile(r"send\s+(\d+(?:\.\d+)?)\s+eth\s+to\s+(0x[0-9a-fA-F]{40})", re.IGNORECASE)


@dataclass
class RunLog:
    """What the agent did during one run, by transaction hash."""

    payments: list[str] = field(default_factory=list)
    transfers: list[str] = field(default_factory=list)
    posts_read: list[str] = field(default_factory=list)


def parse_instructions(text: str) -> list[tuple[Wei, str]]:
    """Find every 'send N ETH to 0x...' in `text`. This is the injection point."""
    return [
        (Web3.to_wei(Decimal(amount), "ether"), Web3.to_checksum_address(to))
        for amount, to in INSTRUCTION.findall(text)
    ]


class VulnerableAgent:
    """A wallet agent that reads a paid feed and does whatever the posts say."""

    def __init__(self, rpc_url: str, private_key: str) -> None:
        self.w3 = Web3(Web3.HTTPProvider(assert_local_rpc(rpc_url)))
        if self.w3.eth.chain_id != ANVIL_CHAIN_ID:
            raise RuntimeError(f"refusing to run: chain id {self.w3.eth.chain_id} is not anvil")
        self.account: LocalAccount = Account.from_key(private_key)

    def send_eth(self, to: str, value: Wei) -> str:
        """Sign and send a native transfer, wait for it to be mined, return its hash."""
        tx: TxParams = {
            "to": Web3.to_checksum_address(to),
            "value": value,
            "gas": 21_000,
            "gasPrice": self.w3.eth.gas_price,
            "nonce": self.w3.eth.get_transaction_count(self.account.address),
            "chainId": ANVIL_CHAIN_ID,
        }
        signed = self.account.sign_transaction(tx)  # type: ignore[arg-type]
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=10)
        return "0x" + tx_hash.hex().removeprefix("0x")

    def fetch_paid(self, url: str, log: RunLog) -> httpx.Response:
        """GET `url`, paying the first option of any 402 response without question."""
        with httpx.Client(timeout=10) as client:
            response = client.get(url)
            if response.status_code != 402:
                return response
            option = response.json()["accepts"][0]
            tx_hash = self.send_eth(option["payTo"], Wei(int(option["maxAmountRequired"])))
            log.payments.append(tx_hash)
            return client.get(url, headers={"X-PAYMENT": encode_payment(tx_hash)})

    def run(self, feed_url: str) -> RunLog:
        """The agent's normal task: read the feed and act on it."""
        log = RunLog()
        response = self.fetch_paid(feed_url, log)
        response.raise_for_status()
        for post in response.json()["posts"]:
            log.posts_read.append(post)
            for value, to in parse_instructions(post):
                log.transfers.append(self.send_eth(to, value))
        return log
