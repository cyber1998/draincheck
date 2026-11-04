# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Test USDC on a local chain: funding, permit and EIP-3009 on the compiled contract."""

from __future__ import annotations

import pytest
from eth_abi.abi import encode
from eth_account import Account
from eth_utils.crypto import keccak
from web3 import Web3
from web3.exceptions import ContractLogicError

from draincheck.facilitator.eip3009 import (
    Authorization,
    domain,
    random_nonce,
    sign_authorization,
    split_signature,
)
from draincheck.fork import AnvilProcess
from draincheck.fork.accounts import (
    AGENT_ADDRESS,
    AGENT_KEY,
    ATTACKER_ADDRESS,
    FACILITATOR_ADDRESS,
    SERVICE_ADDRESS,
)
from draincheck.fork.anvil import ANVIL_CHAIN_ID
from draincheck.fork.usdc import (
    USDC_ADDRESS,
    USDC_EIP712_NAME,
    USDC_EIP712_VERSION,
    USDC_UNIT,
    ensure_usdc,
    fund_usdc,
    usdc_balance,
    usdc_contract,
)
from draincheck.safety import assert_local_rpc


def _w3(anvil: AnvilProcess) -> Web3:
    return Web3(Web3.HTTPProvider(assert_local_rpc(anvil.rpc_url)))


def _now(w3: Web3) -> int:
    return int(w3.eth.get_block("latest")["timestamp"])


@pytest.mark.anvil
def test_fund_usdc_installs_code_and_sets_balance(anvil: AnvilProcess) -> None:
    w3 = _w3(anvil)
    units = fund_usdc(anvil, AGENT_ADDRESS, 1000)
    assert units == 1000 * USDC_UNIT
    assert len(w3.eth.get_code(USDC_ADDRESS)) > 0
    assert usdc_balance(anvil, AGENT_ADDRESS) == 1000 * USDC_UNIT

    # Funding sets the balance; it does not add to it.
    fund_usdc(anvil, AGENT_ADDRESS, 5)
    assert usdc_balance(anvil, AGENT_ADDRESS) == 5 * USDC_UNIT


@pytest.mark.anvil
def test_token_metadata_matches_usdc(anvil: AnvilProcess) -> None:
    w3 = _w3(anvil)
    ensure_usdc(anvil)
    usdc = usdc_contract(w3)
    assert usdc.functions.name().call() == USDC_EIP712_NAME
    assert usdc.functions.version().call() == USDC_EIP712_VERSION
    assert usdc.functions.decimals().call() == 6


@pytest.mark.anvil
def test_domain_separator_matches_python_domain(anvil: AnvilProcess) -> None:
    w3 = _w3(anvil)
    ensure_usdc(anvil)
    type_hash = keccak(
        text="EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    )
    expected = keccak(
        encode(
            ["bytes32", "bytes32", "bytes32", "uint256", "address"],
            [
                type_hash,
                keccak(text=USDC_EIP712_NAME),
                keccak(text=USDC_EIP712_VERSION),
                ANVIL_CHAIN_ID,
                USDC_ADDRESS,
            ],
        )
    )
    on_chain: bytes = usdc_contract(w3).functions.DOMAIN_SEPARATOR().call()
    assert bytes(on_chain) == bytes(expected)


@pytest.mark.anvil
def test_transfer_with_authorization_on_chain(anvil: AnvilProcess) -> None:
    w3 = _w3(anvil)
    fund_usdc(anvil, AGENT_ADDRESS, 100)
    usdc = usdc_contract(w3)
    auth = Authorization(
        from_=AGENT_ADDRESS,
        to=SERVICE_ADDRESS,
        value=7 * USDC_UNIT,
        valid_after=0,
        valid_before=_now(w3) + 3600,
        nonce=random_nonce(),
    )
    v, r, s = split_signature(sign_authorization(AGENT_KEY, auth))
    nonce_bytes = bytes.fromhex(auth.nonce[2:])
    transfer = usdc.get_function_by_signature(
        "transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)"
    )
    args = (
        auth.from_,
        auth.to,
        auth.value,
        auth.valid_after,
        auth.valid_before,
        nonce_bytes,
        v,
        r,
        s,
    )

    tx_hash = transfer(*args).transact({"from": FACILITATOR_ADDRESS})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    assert receipt["status"] == 1
    assert usdc_balance(anvil, SERVICE_ADDRESS) == 7 * USDC_UNIT
    assert usdc.functions.authorizationState(AGENT_ADDRESS, nonce_bytes).call() is True

    # The same authorization cannot be spent twice.
    with pytest.raises(ContractLogicError):
        transfer(*args).call({"from": FACILITATOR_ADDRESS})


@pytest.mark.anvil
def test_transfer_with_authorization_rejects_wrong_signer(anvil: AnvilProcess) -> None:
    w3 = _w3(anvil)
    fund_usdc(anvil, AGENT_ADDRESS, 100)
    usdc = usdc_contract(w3)
    auth = Authorization(
        from_=AGENT_ADDRESS,
        to=SERVICE_ADDRESS,
        value=7 * USDC_UNIT,
        valid_after=0,
        valid_before=_now(w3) + 3600,
        nonce=random_nonce(),
    )
    v, r, s = split_signature(sign_authorization(AGENT_KEY, auth))
    transfer = usdc.get_function_by_signature(
        "transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)"
    )
    # Signed for 7 units, submitted for 8: the signature no longer matches the message.
    tampered = (
        auth.from_,
        auth.to,
        8 * USDC_UNIT,
        auth.valid_after,
        auth.valid_before,
        bytes.fromhex(auth.nonce[2:]),
        v,
        r,
        s,
    )
    with pytest.raises(ContractLogicError):
        transfer(*tampered).call({"from": FACILITATOR_ADDRESS})
    assert usdc_balance(anvil, SERVICE_ADDRESS) == 0


@pytest.mark.anvil
def test_permit_sets_allowance(anvil: AnvilProcess) -> None:
    w3 = _w3(anvil)
    fund_usdc(anvil, AGENT_ADDRESS, 100)
    usdc = usdc_contract(w3)
    nonce: int = usdc.functions.nonces(AGENT_ADDRESS).call()
    deadline = _now(w3) + 3600
    signed = Account.sign_typed_data(
        AGENT_KEY,
        domain_data=domain(),
        message_types={
            "Permit": [
                {"name": "owner", "type": "address"},
                {"name": "spender", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "nonce", "type": "uint256"},
                {"name": "deadline", "type": "uint256"},
            ]
        },
        message_data={
            "owner": AGENT_ADDRESS,
            "spender": ATTACKER_ADDRESS,
            "value": 50 * USDC_UNIT,
            "nonce": nonce,
            "deadline": deadline,
        },
    )
    signature = "0x" + bytes(signed.signature).hex()
    v, r, s = split_signature(signature)
    permit = usdc.get_function_by_signature(
        "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)"
    )
    tx_hash = permit(AGENT_ADDRESS, ATTACKER_ADDRESS, 50 * USDC_UNIT, deadline, v, r, s).transact(
        {"from": FACILITATOR_ADDRESS}
    )
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    assert receipt["status"] == 1
    assert usdc.functions.allowance(AGENT_ADDRESS, ATTACKER_ADDRESS).call() == 50 * USDC_UNIT
    assert usdc.functions.nonces(AGENT_ADDRESS).call() == nonce + 1
