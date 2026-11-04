# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""A local pay-per-request social feed, shaped like an x402 service.

Requests without payment get HTTP 402 and a list of accepted payment options. The client
pays on the local chain and retries with an `X-PAYMENT` header naming the transaction.

This is a simplified stand-in: real x402 "exact" payments are signed EIP-3009
authorizations settled by a facilitator. Phase 1 replaces this with a mock facilitator
that speaks the real protocol.
"""

from __future__ import annotations

import base64
import binascii
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import uvicorn
from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from web3 import Web3
from web3.exceptions import TransactionNotFound

from draincheck.safety import assert_local_rpc

NETWORK = "anvil-local"


def payment_required(resource: str, pay_to: str, price_wei: int) -> dict[str, Any]:
    """The body of a 402 response: what the client must pay, and to whom."""
    return {
        "x402Version": 1,
        "error": "payment required",
        "accepts": [
            {
                "scheme": "exact",
                "network": NETWORK,
                "asset": "native",
                "maxAmountRequired": str(price_wei),
                "payTo": pay_to,
                "resource": resource,
                "description": "One read of the social feed",
            }
        ],
    }


def encode_payment(tx_hash: str) -> str:
    """Build an X-PAYMENT header value for a payment transaction."""
    return base64.b64encode(json.dumps({"txHash": tx_hash}).encode()).decode()


def create_app(rpc_url: str, pay_to: str, price_wei: int, posts: list[str]) -> FastAPI:
    """Create the feed service. `posts` is the content served after payment."""
    w3 = Web3(Web3.HTTPProvider(assert_local_rpc(rpc_url)))
    pay_to = Web3.to_checksum_address(pay_to)
    used_tx_hashes: set[str] = set()
    lock = threading.Lock()
    app = FastAPI(title="Draincheck demo feed")

    def reject(request: Request, reason: str) -> JSONResponse:
        body = payment_required(str(request.url), pay_to, price_wei)
        body["error"] = reason
        return JSONResponse(status_code=402, content=body)

    @app.get("/feed")
    def feed(request: Request, x_payment: str | None = Header(default=None)) -> JSONResponse:
        if x_payment is None:
            return reject(request, "payment required")
        try:
            tx_hash = str(json.loads(base64.b64decode(x_payment, validate=True))["txHash"]).lower()
        except (binascii.Error, ValueError, KeyError, TypeError):
            return reject(request, "malformed X-PAYMENT header")
        with lock:
            if tx_hash in used_tx_hashes:
                return reject(request, "payment already used")
            try:
                tx = w3.eth.get_transaction(tx_hash)  # type: ignore[arg-type]
                receipt = w3.eth.get_transaction_receipt(tx_hash)  # type: ignore[arg-type]
            except (TransactionNotFound, ValueError):
                return reject(request, "payment transaction not found")
            to = tx.get("to")
            if (
                receipt["status"] != 1
                or to is None
                or Web3.to_checksum_address(to) != pay_to
                or tx["value"] < price_wei
            ):
                return reject(request, "payment does not match the quote")
            used_tx_hashes.add(tx_hash)
        return JSONResponse(content={"posts": posts}, headers={"X-PAYMENT-RESPONSE": tx_hash})

    return app


@contextmanager
def serve_in_thread(app: FastAPI, port: int) -> Iterator[str]:
    """Run `app` on 127.0.0.1:`port` in a background thread; yield its base URL."""
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        while not server.started:
            if not thread.is_alive():
                raise RuntimeError("demo service failed to start")
            threading.Event().wait(0.05)
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
