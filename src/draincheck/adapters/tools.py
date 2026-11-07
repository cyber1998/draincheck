# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""The agent's wallet inside the sandbox: honest primitives every adapter can expose.

An LLM agent gets these as tools (see :mod:`draincheck.adapters.langgraph`); the demo agent
calls them directly. They do what they say and nothing else: whether a transfer, an
approval or a swap is a good idea is the agent's decision, and the oracle judges it.
Every client is local and the key is always one of anvil's dev keys.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any
from urllib.parse import urlsplit

import httpx
from eth_account import Account
from eth_account.signers.local import LocalAccount
from web3 import Web3
from web3.contract import Contract
from web3.types import TxParams, Wei

from draincheck.contracts import load_artifact
from draincheck.facilitator.client import build_exact_payment
from draincheck.facilitator.types import PAYMENT_SIGNATURE_HEADER, PaymentRequired, encode_header
from draincheck.fork.anvil import ANVIL_CHAIN_ID
from draincheck.safety import (
    assert_dev_key,
    assert_local_rpc,
    assert_local_service,
    local_http_client,
    local_web3,
)

UNLIMITED = 2**256 - 1


class SandboxWallet:
    """One agent account on the local node, plus readers for the trial's local services."""

    def __init__(self, rpc_url: str, private_key: str) -> None:
        self.w3 = local_web3(rpc_url)
        if self.w3.eth.chain_id != ANVIL_CHAIN_ID:
            raise RuntimeError(f"refusing to run: chain id {self.w3.eth.chain_id} is not anvil")
        self.account: LocalAccount = Account.from_key(assert_dev_key(private_key))
        self.payments = 0  # x402 payments signed so far

    @property
    def address(self) -> str:
        return str(self.account.address)

    # ---- reading ----

    def get_paid(self, url: str) -> httpx.Response:
        """GET a local `url`, signing the x402 payment a 402 response asks for."""
        url = assert_local_rpc(url)  # a signed authorization never leaves 127.0.0.1
        with local_http_client(timeout=30) as client:
            response = client.get(url)
            if response.status_code != 402:
                return response
            required = PaymentRequired.model_validate(response.json())
            now = int(self.w3.eth.get_block("latest")["timestamp"])
            payment = build_exact_payment(
                self.account.key.hex(), self.address, required.accepts[0], now, required.resource
            )
            self.payments += 1
            return client.get(url, headers={PAYMENT_SIGNATURE_HEADER: encode_header(payment)})

    def read(self, url: str) -> Any:
        """The JSON at a local service URL: an HTTP service (paid if it asks) or a file."""
        if urlsplit(url).scheme == "file":
            path = urllib.request.url2pathname(urlsplit(assert_local_service(url)).path)
            with open(path, encoding="utf-8") as file:
                return json.load(file)
        response = self.get_paid(url)
        response.raise_for_status()
        return response.json()

    def token_metadata(self, token: str) -> tuple[str, str]:
        """The (name, symbol) a token reports. Both are attacker-controlled text."""
        contract = self._token(token)
        return str(contract.functions.name().call()), str(contract.functions.symbol().call())

    def decimals(self, token: str) -> int:
        """How many decimals `token` reports (base units per whole token = 10**decimals)."""
        return int(self._token(token).functions.decimals().call())

    def balance(self, token: str | None = None) -> int:
        """The agent's balance in base units: native ETH, or `token`."""
        if token is None:
            return int(self.w3.eth.get_balance(self.account.address))
        return int(self._token(token).functions.balanceOf(self.account.address).call())

    # ---- acting ----

    def send_eth(self, to: str, wei: int) -> str:
        """A native transfer; returns the transaction hash once mined."""
        return self._send(
            {
                "to": Web3.to_checksum_address(to),
                "value": Wei(wei),
                "gas": 21_000,
                "gasPrice": self.w3.eth.gas_price,
            }
        )

    def transfer(self, token: str, to: str, units: int) -> str:
        """An ERC-20 transfer of `units` base units of `token`."""
        call = self._token(token).functions.transfer(Web3.to_checksum_address(to), units)
        return self._send(call.build_transaction({"from": self.account.address}))

    def approve(self, token: str, spender: str, units: int) -> str:
        """Let `spender` move up to `units` of `token` (``UNLIMITED`` for no limit)."""
        call = self._token(token).functions.approve(Web3.to_checksum_address(spender), units)
        return self._send(call.build_transaction({"from": self.account.address}))

    def swap(self, router: str, token_in: str, token_out: str, amount: int, min_out: int) -> str:
        """Swap through `router` (the sandbox router's interface). Needs an approval first."""
        contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(router), abi=load_artifact("TestRouter")["abi"]
        )
        call = contract.functions.swap(
            Web3.to_checksum_address(token_in),
            Web3.to_checksum_address(token_out),
            amount,
            min_out,
            self.account.address,
        )
        return self._send(call.build_transaction({"from": self.account.address}))

    # ---- internals ----

    def _token(self, token: str) -> Contract:
        # TestToken's ABI is a plain ERC-20 plus metadata setters; it reads USDC too.
        return self.w3.eth.contract(
            address=Web3.to_checksum_address(token), abi=load_artifact("TestToken")["abi"]
        )

    def _send(self, tx: TxParams) -> str:
        tx["nonce"] = self.w3.eth.get_transaction_count(self.account.address)
        tx["chainId"] = ANVIL_CHAIN_ID
        signed = self.account.sign_transaction(tx)  # type: ignore[arg-type]
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=10)
        return "0x" + tx_hash.hex().removeprefix("0x")
