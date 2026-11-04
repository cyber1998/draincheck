# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
from __future__ import annotations

import pytest
from web3 import Web3

from draincheck.fork import (
    ANVIL_CHAIN_ID,
    DEFAULT_BASE_FORK_BLOCK,
    FORK_BLOCK_ENV,
    FORK_URL_ENV,
    AnvilProcess,
    ForkNotConfiguredError,
    RPCError,
)

DEV_0 = Web3.to_checksum_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
DEV_9 = Web3.to_checksum_address("0xa0Ee7A142d267C1f36714E4a8F75612F20a79720")
# Local placeholder only; it is never contacted because these tests never start the node.
FAKE_UPSTREAM = "http://127.0.0.1:1/upstream"


@pytest.mark.anvil
def test_anvil_starts_on_loopback_with_dev_chain_id(anvil: AnvilProcess) -> None:
    assert anvil.rpc_url.startswith("http://127.0.0.1:")
    assert not anvil.is_fork
    assert Web3(Web3.HTTPProvider(anvil.rpc_url)).eth.chain_id == ANVIL_CHAIN_ID


def _send(w3: Web3, value: int) -> None:
    tx_hash = w3.eth.send_transaction({"from": DEV_0, "to": DEV_9, "value": value})  # type: ignore[typeddict-item]
    w3.eth.wait_for_transaction_receipt(tx_hash)


@pytest.mark.anvil
def test_snapshot_isolates_two_runs(anvil: AnvilProcess) -> None:
    w3 = Web3(Web3.HTTPProvider(anvil.rpc_url))
    start_balance = w3.eth.get_balance(DEV_9)
    start_block = w3.eth.block_number

    # Run 1 moves 1 ETH, run 2 moves 2 ETH. Each must start from the same state.
    seen: list[int] = []
    for run, value in enumerate([Web3.to_wei(1, "ether"), Web3.to_wei(2, "ether")]):
        with anvil.isolated():
            assert w3.eth.get_balance(DEV_9) == start_balance, f"run {run} saw leaked state"
            assert w3.eth.block_number == start_block
            _send(w3, value)
            seen.append(w3.eth.get_balance(DEV_9) - start_balance)
    assert seen == [Web3.to_wei(1, "ether"), Web3.to_wei(2, "ether")]
    assert w3.eth.get_balance(DEV_9) == start_balance
    assert w3.eth.block_number == start_block


@pytest.mark.anvil
def test_revert_is_single_use(anvil: AnvilProcess) -> None:
    snap = anvil.snapshot()
    anvil.revert(snap)
    with pytest.raises(RPCError):
        anvil.revert(snap)


def test_plain_chain_when_fork_url_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(FORK_URL_ENV, raising=False)
    node = AnvilProcess()
    assert not node.is_fork
    assert "--fork-url" not in node._argv("anvil")
    with pytest.raises(ForkNotConfiguredError):
        AnvilProcess(fork=True)


def test_fork_url_only_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(FORK_URL_ENV, FAKE_UPSTREAM)
    monkeypatch.delenv(FORK_BLOCK_ENV, raising=False)
    node = AnvilProcess()
    argv = node._argv("anvil")
    assert node.is_fork
    assert argv[argv.index("--fork-url") + 1] == FAKE_UPSTREAM
    assert argv[argv.index("--fork-block-number") + 1] == str(DEFAULT_BASE_FORK_BLOCK)
    # A fork keeps the local dev chain id so sandbox transactions cannot replay on Base.
    assert argv[argv.index("--chain-id") + 1] == str(ANVIL_CHAIN_ID)
    # The node itself still listens on loopback only.
    assert argv[argv.index("--host") + 1] == "127.0.0.1"
    assert node.rpc_url.startswith("http://127.0.0.1:")
    assert not AnvilProcess(fork=False).is_fork


def test_anvil_env_drops_upstream_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    from draincheck.fork.anvil import _anvil_env

    monkeypatch.setenv("ETH_RPC_URL", FAKE_UPSTREAM)
    monkeypatch.setenv("FOUNDRY_ETH_RPC_URL", FAKE_UPSTREAM)
    monkeypatch.setenv("ANVIL_FORK_URL", FAKE_UPSTREAM)
    monkeypatch.setenv(FORK_URL_ENV, FAKE_UPSTREAM)
    env = _anvil_env()
    assert FAKE_UPSTREAM not in env.values()
    assert "PATH" in env


def test_fork_block_pin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(FORK_URL_ENV, FAKE_UPSTREAM)
    monkeypatch.setenv(FORK_BLOCK_ENV, "123")
    assert AnvilProcess().fork_block == 123
    assert AnvilProcess(fork_block=456).fork_block == 456
    monkeypatch.setenv(FORK_BLOCK_ENV, "latest")
    with pytest.raises(ValueError, match=FORK_BLOCK_ENV):
        AnvilProcess()


@pytest.mark.fork
def test_base_fork_snapshot_isolation(base_fork: AnvilProcess) -> None:
    w3 = Web3(Web3.HTTPProvider(base_fork.rpc_url))
    assert base_fork.is_fork
    assert w3.eth.chain_id == ANVIL_CHAIN_ID
    assert w3.eth.block_number >= (base_fork.fork_block or 0)
    before = w3.eth.get_balance(DEV_9)
    with base_fork.isolated():
        _send(w3, Web3.to_wei(1, "ether"))
        assert w3.eth.get_balance(DEV_9) == before + Web3.to_wei(1, "ether")
    assert w3.eth.get_balance(DEV_9) == before
