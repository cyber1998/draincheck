# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""A proxy in the environment must not carry local traffic off the machine.

httpx and requests (under web3) send even 127.0.0.1 traffic through HTTP_PROXY and
friends by default. Here every proxy points at a dead port: if any Draincheck client used
it, the run would fail to connect instead of reaching the local node and services.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from draincheck.fork import ANVIL_CHAIN_ID, AnvilProcess
from draincheck.runner import run_scenario
from draincheck.safety import local_http_client, local_web3
from draincheck.scenarios import load_scenario
from examples.vulnerable_agent.target import run

DEAD_PROXY = "http://127.0.0.1:9"
SCENARIO = (
    Path(__file__).resolve().parents[1]
    / "scenarios"
    / "social_post"
    / "social-post-usdc-transfer-001.yaml"
)


@pytest.fixture
def dead_proxies(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.setenv(name, DEAD_PROXY)
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    # requests turns any variable ending in "_proxy" into a proxy key, host-keyed ones too,
    # and checks those before the plain scheme key.
    monkeypatch.setenv("http://" + "127.0.0.1" + "_proxy", DEAD_PROXY)


@pytest.mark.anvil
@pytest.mark.usefixtures("dead_proxies")
def test_local_clients_ignore_proxies(anvil: AnvilProcess) -> None:
    assert local_web3(anvil.rpc_url).eth.chain_id == ANVIL_CHAIN_ID
    body = {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}
    with local_http_client(timeout=5) as client:
        assert client.post(anvil.rpc_url, json=body).status_code == 200


@pytest.mark.anvil
@pytest.mark.usefixtures("dead_proxies")
def test_a_whole_run_stays_local_with_proxies_set(anvil: AnvilProcess) -> None:
    # The node, the facilitator, the paid feed and the agent all talk over local HTTP.
    scenario = load_scenario(SCENARIO).model_copy(update={"trials": 3})
    result = run_scenario(scenario, run, anvil)
    assert result.crashed_count == 0
    assert result.breached_count == 3
