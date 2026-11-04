# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Mock x402 facilitator for the local chain: ``/supported``, ``/verify`` and ``/settle``.

Supports the ``exact`` scheme with EIP-3009 ``transferWithAuthorization``, following the
v2 spec (specs/schemes/exact/scheme_exact_evm.md) and the reference facilitator's check
order and error strings. Settlement transactions are sent from an anvil dev account.

It only ever talks to the local node: the RPC URL goes through ``assert_local_rpc``, and
the network it accepts is ``eip155:31337``.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

import uvicorn
from eth_account import Account
from eth_account.signers.local import LocalAccount
from fastapi import FastAPI
from web3 import Web3
from web3.exceptions import ContractLogicError

from draincheck.facilitator.eip3009 import (
    Authorization,
    domain,
    recover_signer,
    split_signature,
)
from draincheck.facilitator.types import (
    FacilitatorRequest,
    PaymentRequirements,
    SettleResponse,
    VerifyResponse,
)
from draincheck.fork.anvil import ANVIL_CHAIN_ID
from draincheck.fork.usdc import usdc_contract
from draincheck.safety import assert_local_rpc

NETWORK = f"eip155:{ANVIL_CHAIN_ID}"
# Anvil dev account 8. Public key material; holds nothing on any real network.
FACILITATOR_KEY = "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97"
# A payment must stay valid for at least this long after verification (reference value).
VALID_BEFORE_MARGIN_SECONDS = 6
_SECP256K1_HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0


class Invalid(Exception):
    """A payment failed a check; `reason` is an x402 invalidReason string."""

    def __init__(self, reason: str, message: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.message = message or reason


@dataclass(frozen=True)
class CheckedExact:
    auth: Authorization
    signature: str
    token: str


class Facilitator:
    """Verification and settlement logic, independent of HTTP."""

    def __init__(self, rpc_url: str, signer_key: str = FACILITATOR_KEY) -> None:
        self.w3 = Web3(Web3.HTTPProvider(assert_local_rpc(rpc_url)))
        if self.w3.eth.chain_id != ANVIL_CHAIN_ID:
            raise RuntimeError(f"refusing to run: chain id {self.w3.eth.chain_id} is not anvil")
        self.signer: LocalAccount = Account.from_key(signer_key)
        self._lock = threading.Lock()

    def now(self) -> int:
        """Chain time, so tests can move it with evm_increaseTime."""
        return int(self.w3.eth.get_block("latest")["timestamp"])

    # ---- exact / EIP-3009 ----

    def check_exact(self, req: FacilitatorRequest) -> CheckedExact:
        reqs = req.payment_requirements
        payload = req.payment_payload
        if req.x402_version != 2 or payload.x402_version != 2:
            raise Invalid("invalid_x402_version")
        if payload.accepted.scheme != "exact" or reqs.scheme != "exact":
            raise Invalid("unsupported_scheme")
        if payload.accepted.network != NETWORK or reqs.network != NETWORK:
            raise Invalid("network_mismatch")
        if not _same_requirements(payload.accepted, reqs):
            raise Invalid("invalid_payment_requirements", "accepted does not match requirements")
        name, version = reqs.extra.get("name"), reqs.extra.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise Invalid("missing_eip712_domain")
        try:
            auth = Authorization.from_wire(payload.payload["authorization"])
            signature = str(payload.payload["signature"])
            token = Web3.to_checksum_address(reqs.asset)
            pay_to = Web3.to_checksum_address(reqs.pay_to)
            amount = int(reqs.amount)
            v, _r, s = split_signature(signature)
        except (KeyError, TypeError, ValueError) as err:
            raise Invalid("invalid_exact_evm_payload", str(err)) from err

        contract = usdc_contract(self.w3, token)
        try:
            if contract.functions.name().call() != name:
                raise Invalid("invalid_exact_evm_token_name_mismatch")
            if contract.functions.version().call() != version:
                raise Invalid("invalid_exact_evm_token_version_mismatch")
        except (ContractLogicError, ValueError) as err:
            raise Invalid("invalid_exact_evm_eip3009_not_supported", str(err)) from err

        if auth.to != pay_to:
            raise Invalid("invalid_exact_evm_payload_recipient_mismatch")
        if auth.value != amount:
            raise Invalid(
                "invalid_exact_evm_payload_authorization_value_mismatch",
                f"authorized {auth.value}, required exactly {amount}",
            )
        now = self.now()
        if auth.valid_before < now + VALID_BEFORE_MARGIN_SECONDS:
            raise Invalid("invalid_exact_evm_payload_authorization_valid_before")
        if auth.valid_after > now:
            raise Invalid("invalid_exact_evm_payload_authorization_valid_after")
        if int.from_bytes(s, "big") > _SECP256K1_HALF_N or v not in (27, 28):
            raise Invalid("invalid_exact_evm_non_canonical_signature")
        eip712 = domain(ANVIL_CHAIN_ID, token, name, version)
        try:
            signer = recover_signer(auth, signature, eip712)
        except Exception as err:  # malformed signature bytes
            raise Invalid("invalid_exact_evm_failed_to_verify_signature", str(err)) from err
        if signer != auth.from_:
            raise Invalid("invalid_exact_evm_payload_signature")
        if contract.functions.balanceOf(auth.from_).call() < auth.value:
            raise Invalid("invalid_exact_evm_insufficient_balance")
        if contract.functions.authorizationState(auth.from_, bytes.fromhex(auth.nonce[2:])).call():
            raise Invalid("invalid_exact_evm_nonce_already_used")
        try:
            self._transfer_call(token, auth, signature).call({"from": self.signer.address})
        except (ContractLogicError, ValueError) as err:
            raise Invalid("invalid_exact_evm_transaction_simulation_failed", str(err)) from err
        return CheckedExact(auth, signature, token)

    def _transfer_call(self, token: str, auth: Authorization, signature: str) -> Any:
        v, r, s = split_signature(signature)
        fn = usdc_contract(self.w3, token).get_function_by_signature(
            "transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)"
        )
        return fn(
            auth.from_,
            auth.to,
            auth.value,
            auth.valid_after,
            auth.valid_before,
            bytes.fromhex(auth.nonce[2:]),
            v,
            r,
            s,
        )

    def verify(self, req: FacilitatorRequest) -> VerifyResponse:
        try:
            checked = self.check_exact(req)
        except Invalid as err:
            return VerifyResponse(
                is_valid=False,
                invalid_reason=err.reason,
                invalid_message=err.message,
                payer=_payer(req),
            )
        return VerifyResponse(is_valid=True, payer=checked.auth.from_)

    def settle(self, req: FacilitatorRequest) -> SettleResponse:
        with self._lock:  # one settlement at a time, so a replay cannot race the first
            try:
                checked = self.check_exact(req)
            except Invalid as err:
                return SettleResponse(
                    success=False,
                    error_reason=err.reason,
                    error_message=err.message,
                    payer=_payer(req),
                    network=NETWORK,
                )
            call = self._transfer_call(checked.token, checked.auth, checked.signature)
            tx = call.build_transaction(
                {
                    "from": self.signer.address,
                    "nonce": self.w3.eth.get_transaction_count(self.signer.address),
                    "chainId": ANVIL_CHAIN_ID,
                }
            )
            signed = self.signer.sign_transaction(tx)
            tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=10)
            tx_hex = "0x" + bytes(tx_hash).hex()
            if receipt["status"] != 1:
                return SettleResponse(
                    success=False,
                    error_reason="transaction_failed",
                    payer=checked.auth.from_,
                    transaction=tx_hex,
                    network=NETWORK,
                )
            return SettleResponse(
                success=True,
                payer=checked.auth.from_,
                transaction=tx_hex,
                network=NETWORK,
                amount=str(checked.auth.value),
            )


def _same_requirements(a: PaymentRequirements, b: PaymentRequirements) -> bool:
    return (
        a.scheme == b.scheme
        and a.network == b.network
        and a.amount == b.amount
        and a.asset.lower() == b.asset.lower()
        and a.pay_to.lower() == b.pay_to.lower()
    )


def _payer(req: FacilitatorRequest) -> str | None:
    auth = req.payment_payload.payload.get("authorization")
    if isinstance(auth, dict) and isinstance(auth.get("from"), str):
        return str(auth["from"])
    return None


def create_facilitator_app(facilitator: Facilitator) -> FastAPI:
    """The HTTP face of `facilitator`."""
    app = FastAPI(title="Draincheck mock x402 facilitator")

    @app.get("/supported")
    def supported() -> dict[str, Any]:
        return {
            "kinds": [{"x402Version": 2, "scheme": "exact", "network": NETWORK}],
            "extensions": [],
            "signers": {"eip155:*": [facilitator.signer.address]},
        }

    @app.post("/verify")
    def verify(req: FacilitatorRequest) -> dict[str, Any]:
        return facilitator.verify(req).wire()

    @app.post("/settle")
    def settle(req: FacilitatorRequest) -> dict[str, Any]:
        return facilitator.settle(req).wire()

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
                raise RuntimeError("local service failed to start")
            threading.Event().wait(0.05)
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
