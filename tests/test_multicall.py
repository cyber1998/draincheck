# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""The sandbox Multicall3: installed on local chains only, with aggregate3's semantics."""

from __future__ import annotations

import pytest
from web3.exceptions import ContractLogicError

from draincheck.contracts import load_artifact
from draincheck.fork import AnvilProcess
from draincheck.fork.accounts import AGENT_ADDRESS
from draincheck.fork.multicall import MULTICALL3_ADDRESS, ensure_multicall3
from draincheck.fork.usdc import USDC_ADDRESS, ensure_usdc, fund_usdc, usdc_contract


@pytest.mark.anvil
def test_installed_on_a_local_chain_once(anvil: AnvilProcess) -> None:
    assert ensure_multicall3(anvil) is True
    assert len(anvil.w3.eth.get_code(MULTICALL3_ADDRESS)) > 0
    assert ensure_multicall3(anvil) is False  # already there


@pytest.mark.anvil
def test_never_installed_on_a_fork(anvil: AnvilProcess, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(AnvilProcess, "is_fork", property(lambda self: True))
    assert ensure_multicall3(anvil) is False
    assert len(anvil.w3.eth.get_code(MULTICALL3_ADDRESS)) == 0


@pytest.mark.anvil
def test_aggregate3_reads_token_details(anvil: AnvilProcess) -> None:
    ensure_usdc(anvil)
    fund_usdc(anvil, AGENT_ADDRESS, 7)
    ensure_multicall3(anvil)
    usdc = usdc_contract(anvil.w3)
    multicall = anvil.w3.eth.contract(
        address=MULTICALL3_ADDRESS, abi=load_artifact("SandboxMulticall3")["abi"]
    )
    calls = [
        (USDC_ADDRESS, False, usdc.encode_abi("decimals", [])),
        (USDC_ADDRESS, False, usdc.encode_abi("balanceOf", [AGENT_ADDRESS])),
        (AGENT_ADDRESS, True, b"\x12\x34"),  # an account, not a contract: succeeds, no data
    ]
    results = multicall.functions.aggregate3(calls).call()
    assert [success for success, _ in results] == [True, True, True]
    assert int.from_bytes(results[0][1], "big") == 6
    assert int.from_bytes(results[1][1], "big") == 7 * 10**6


@pytest.mark.anvil
def test_a_failing_call_reverts_unless_allowed(anvil: AnvilProcess) -> None:
    ensure_usdc(anvil)
    ensure_multicall3(anvil)
    usdc = usdc_contract(anvil.w3)
    multicall = anvil.w3.eth.contract(
        address=MULTICALL3_ADDRESS, abi=load_artifact("SandboxMulticall3")["abi"]
    )
    # A transfer from the multicall contract itself, which holds no USDC, reverts.
    bad = usdc.encode_abi("transfer", [AGENT_ADDRESS, 1])
    assert multicall.functions.aggregate3([(USDC_ADDRESS, True, bad)]).call()[0][0] is False
    with pytest.raises(ContractLogicError, match="call failed"):
        multicall.functions.aggregate3([(USDC_ADDRESS, False, bad)]).call()
