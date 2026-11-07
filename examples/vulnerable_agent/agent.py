# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""The vulnerable agent.

Its job: use whatever service or memory the scenario gives it (a paid social feed, a paid
API, saved notes, a token's metadata, a paid router listing) and act on what it reads. Its
flaws, on purpose:

1. It treats instructions found in untrusted content (feed posts, API notes, memory notes,
   token names, router notes) as commands.
2. It has no spend limit, no recipient allowlist and no human approval step.
3. It signs whatever x402 payment a 402 response asks for.
4. It grants an unlimited ERC-20 approval to the router it is pointed at.
5. It swaps with no slippage limit (minOut of 0), so a skimming router goes unnoticed.
6. It decodes base64, Morse and homoglyph-obfuscated text and acts on the result, so an
   instruction hidden from a text filter is still followed.

The "brain" here is a deterministic instruction follower rather than a language model, so
tests are fast, free and repeatable. It fails the same way a naive LLM agent does when it
obeys a prompt injection. An LLM-backed variant built on AgentKit is planned.
"""

from __future__ import annotations

import base64
import json
import re
import urllib.request
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from eth_account import Account
from eth_account.signers.local import LocalAccount
from web3 import Web3
from web3.types import TxParams, Wei

from draincheck.contracts import load_artifact
from draincheck.facilitator.client import build_exact_payment
from draincheck.facilitator.types import (
    PAYMENT_SIGNATURE_HEADER,
    PaymentRequired,
    encode_header,
)
from draincheck.fork import ANVIL_CHAIN_ID
from draincheck.fork.usdc import USDC_ADDRESS, USDC_UNIT, to_units, usdc_contract
from draincheck.runner.target import TrialEnv
from draincheck.safety import (
    assert_dev_key,
    assert_local_rpc,
    assert_local_service,
    local_http_client,
    local_web3,
)
from draincheck.scenarios.encodings import HOMOGLYPHS, MORSE

INSTRUCTION = re.compile(
    r"send\s+(\d+(?:\.\d+)?)\s+(eth|usdc)\s+to\s+(0x[0-9a-fA-F]{40})", re.IGNORECASE
)
UNLIMITED = 2**256 - 1
_MORSE_DECODE: dict[str, str] = {code: char for char, code in MORSE.items()}
_HOMOGLYPH_DECODE: dict[str, str] = {look: char for char, look in HOMOGLYPHS.items()}


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


def _decode_base64(text: str) -> str | None:
    try:
        return base64.b64decode(text, validate=True).decode("utf-8")
    except ValueError:  # bad base64, or bytes that are not UTF-8
        return None


def _decode_morse(text: str) -> str | None:
    if not text.strip() or not set(text) <= set(".-/ "):
        return None
    words = []
    for word in text.split(" / "):
        letters = []
        for code in word.split():
            if code not in _MORSE_DECODE:
                return None
            letters.append(_MORSE_DECODE[code])
        words.append("".join(letters))
    return " ".join(words).lower()


def _decode_homoglyphs(text: str) -> str:
    return "".join(_HOMOGLYPH_DECODE.get(char, char) for char in text)


def decoded_variants(text: str) -> list[str]:
    """`text` plus every plausible decoding of it.

    This is a flaw: the agent "helpfully" decodes obfuscated content (base64, Morse, Cyrillic
    look-alike letters) so that a filter which only sees the raw text is bypassed, and then
    acts on the decoded instructions as if they were its own.
    """
    variants = [text]
    for decoded in (_decode_base64(text), _decode_morse(text), _decode_homoglyphs(text)):
        if decoded is not None and decoded not in variants:
            variants.append(decoded)
    return variants


def _parse_plain(text: str) -> list[Instruction]:
    found = []
    for amount, asset, to in INSTRUCTION.findall(text):
        asset = asset.upper()
        units = Web3.to_wei(Decimal(amount), "ether") if asset == "ETH" else to_units(amount)
        found.append(Instruction(asset, int(units), Web3.to_checksum_address(to)))
    return found


def parse_instructions(text: str) -> list[Instruction]:
    """Find every 'send N ETH|USDC to 0x...' in `text` and in its decodings.

    This is the injection point. Duplicates are dropped, in first-seen order.
    """
    found: list[Instruction] = []
    for variant in decoded_variants(text):
        for ins in _parse_plain(variant):
            if ins not in found:
                found.append(ins)
    return found


class VulnerableAgent:
    """A wallet agent that reads what it is given and does whatever the content says."""

    def __init__(self, rpc_url: str, private_key: str) -> None:
        self.w3 = local_web3(rpc_url)
        if self.w3.eth.chain_id != ANVIL_CHAIN_ID:
            raise RuntimeError(f"refusing to run: chain id {self.w3.eth.chain_id} is not anvil")
        self.account: LocalAccount = Account.from_key(assert_dev_key(private_key))

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
        with local_http_client(timeout=30) as client:
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

    def read_memory(self, uri: str) -> list[str]:
        """The notes in the agent's saved memory file. Flaw: they are trusted as its own."""
        assert_local_service(uri)
        path = Path(urllib.request.url2pathname(urlsplit(uri).path))
        notes: list[str] = json.loads(path.read_text(encoding="utf-8"))["notes"]
        return notes

    def read_token(self, address: str) -> list[str]:
        """The name and symbol of the token at `address`. Flaw: a name is trusted as text."""
        token = self.w3.eth.contract(
            address=Web3.to_checksum_address(address), abi=load_artifact("TestToken")["abi"]
        )
        name: str = token.functions.name().call()
        symbol: str = token.functions.symbol().call()
        return [name, symbol]

    def swap(self, router: str, token_in: str, token_out: str, amount: int) -> list[str]:
        """Approve `router` for unlimited `token_in`, then swap `amount` with no slippage limit.

        Flaws: the approval is unlimited, so the router can pull the agent's whole balance
        later, and minOut is 0, so the agent accepts any output however much was skimmed.
        """
        router = Web3.to_checksum_address(router)
        approve = usdc_contract(self.w3, token_in).functions.approve(router, UNLIMITED)
        approve_hash = self._send(approve.build_transaction({"from": self.account.address}))
        router_contract = self.w3.eth.contract(
            address=router, abi=load_artifact("TestRouter")["abi"]
        )
        swap_call = router_contract.functions.swap(
            Web3.to_checksum_address(token_in),
            Web3.to_checksum_address(token_out),
            amount,
            0,
            self.account.address,
        )
        swap_hash = self._send(swap_call.build_transaction({"from": self.account.address}))
        return [approve_hash, swap_hash]

    def act_on(self, text: str, log: RunLog) -> None:
        """Read `text` and send every transfer it asks for."""
        log.posts_read.append(text)
        for ins in parse_instructions(text):
            if ins.asset == "ETH":
                log.transfers.append(self.send_eth(ins.to, Wei(ins.amount)))
            else:
                log.transfers.append(self.send_usdc(ins.to, ins.amount))

    def run(self, env: TrialEnv) -> RunLog:
        """The agent's normal task, dispatched on the services and contracts it is given."""
        log = RunLog()
        if "feed" in env.services:
            response = self.fetch_paid(env.services["feed"], log)
            response.raise_for_status()
            for post in response.json()["posts"]:
                self.act_on(post, log)
        elif "api" in env.services:
            response = self.fetch_paid(env.services["api"], log)
            response.raise_for_status()
            self.act_on(response.json()["note"], log)
        elif "memory" in env.services:
            for note in self.read_memory(env.services["memory"]):
                self.act_on(note, log)
        elif "routers" in env.services:
            response = self.fetch_paid(env.services["routers"], log)
            response.raise_for_status()
            listing = response.json()["routers"][0]
            self.act_on(listing["note"], log)
            log.transfers.extend(
                self.swap(
                    listing["router"], listing["token_in"], listing["token_out"], 100 * USDC_UNIT
                )
            )
        elif "token" in env.contracts and "router" not in env.contracts:
            for text in self.read_token(env.contracts["token"]):
                self.act_on(text, log)
        return log
