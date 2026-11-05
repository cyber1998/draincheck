# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
from __future__ import annotations

import pytest
from web3 import Web3

from draincheck.fork import (
    ANVIL_CHAIN_ID,
    BASE_FORK_BLOCK,
    FORK_BLOCK_ENV,
    FORK_URL_ENV,
    AnvilProcess,
    RPCError,
    anvil_env,
    fork_block_from_env,
)
from draincheck.safety import local_web3

ALICE = Web3.to_checksum_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
BOB = Web3.to_checksum_address("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
# Native USDC on Base (Circle).
BASE_USDC = Web3.to_checksum_address("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")


def _send(w3: Web3, value: int) -> None:
    tx_hash = w3.eth.send_transaction({"from": ALICE, "to": BOB, "value": value})  # type: ignore[typeddict-item]
    w3.eth.wait_for_transaction_receipt(tx_hash)


@pytest.mark.anvil
def test_anvil_starts_on_loopback_with_dev_chain_id(anvil: AnvilProcess) -> None:
    assert anvil.rpc_url.startswith("http://127.0.0.1:")
    assert not anvil.is_fork
    assert local_web3(anvil.rpc_url).eth.chain_id == ANVIL_CHAIN_ID


@pytest.mark.anvil
def test_snapshot_isolates_two_runs(anvil: AnvilProcess) -> None:
    w3 = local_web3(anvil.rpc_url)
    bob_start = w3.eth.get_balance(BOB)
    nonce_start = w3.eth.get_transaction_count(ALICE)

    snap = anvil.snapshot()
    _send(w3, 10**18)
    assert w3.eth.get_balance(BOB) == bob_start + 10**18
    anvil.revert(snap)
    assert w3.eth.get_balance(BOB) == bob_start
    assert w3.eth.get_transaction_count(ALICE) == nonce_start

    # The second run starts from the same state and does not see the first.
    with anvil.isolated():
        _send(w3, 3 * 10**18)
        assert w3.eth.get_balance(BOB) == bob_start + 3 * 10**18
    assert w3.eth.get_balance(BOB) == bob_start
    assert w3.eth.get_transaction_count(ALICE) == nonce_start


@pytest.mark.anvil
def test_isolated_reverts_when_the_body_raises(anvil: AnvilProcess) -> None:
    w3 = local_web3(anvil.rpc_url)
    bob_start = w3.eth.get_balance(BOB)

    def trial() -> None:
        with anvil.isolated():
            _send(w3, 10**18)
            raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        trial()
    assert w3.eth.get_balance(BOB) == bob_start


@pytest.mark.anvil
def test_revert_of_unknown_snapshot_raises(anvil: AnvilProcess) -> None:
    snap = anvil.snapshot()
    anvil.revert(snap)
    with pytest.raises(RPCError):
        anvil.revert(snap)  # anvil deletes a snapshot once it is used


def test_fork_without_env_runs_plain_local_anvil(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(FORK_URL_ENV, raising=False)
    node = AnvilProcess(fork=True)
    assert not node.is_fork
    assert "--fork-url" not in node._argv("anvil")
    assert node._argv("anvil")[-2:] == ["--chain-id", str(ANVIL_CHAIN_ID)]


def test_fork_argv_pins_block_and_keeps_dev_chain_id(monkeypatch: pytest.MonkeyPatch) -> None:
    # Never started: only checks the argv anvil would get. The URL is a loopback placeholder.
    monkeypatch.setenv(FORK_URL_ENV, "http://127.0.0.1:1")
    monkeypatch.delenv(FORK_BLOCK_ENV, raising=False)
    node = AnvilProcess(fork=True)
    argv = node._argv("anvil")
    assert node.is_fork
    assert argv[argv.index("--chain-id") + 1] == str(ANVIL_CHAIN_ID)
    assert argv[argv.index("--fork-block-number") + 1] == str(BASE_FORK_BLOCK)
    assert not AnvilProcess(fork=False).is_fork


def test_anvil_env_drops_foundry_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ETH_RPC_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("ANVIL_IP_ADDR", "127.0.0.2")
    env = anvil_env()
    assert "ETH_RPC_URL" not in env
    assert "ANVIL_IP_ADDR" not in env
    assert "PATH" in env


def test_fork_url_must_be_http_or_ws(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(FORK_URL_ENV, "file:///etc/passwd")
    with pytest.raises(ValueError, match=FORK_URL_ENV):
        AnvilProcess(fork=True)


def test_fork_block_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(FORK_BLOCK_ENV, "12345")
    assert fork_block_from_env() == 12345
    monkeypatch.setenv(FORK_BLOCK_ENV, "-1")
    with pytest.raises(ValueError, match=FORK_BLOCK_ENV):
        fork_block_from_env()


@pytest.mark.fork
def test_fork_keeps_dev_chain_id_and_sees_base_state(forked_anvil: AnvilProcess) -> None:
    w3 = local_web3(forked_anvil.rpc_url)
    assert w3.eth.chain_id == ANVIL_CHAIN_ID
    assert forked_anvil.fork_block is not None
    assert w3.eth.block_number >= forked_anvil.fork_block
    assert len(w3.eth.get_code(BASE_USDC)) > 0


@pytest.mark.fork
def test_fork_snapshot_isolates_two_runs(forked_anvil: AnvilProcess) -> None:
    w3 = local_web3(forked_anvil.rpc_url)
    bob_start = w3.eth.get_balance(BOB)
    with forked_anvil.isolated():
        _send(w3, 10**18)
        assert w3.eth.get_balance(BOB) == bob_start + 10**18
    assert w3.eth.get_balance(BOB) == bob_start
