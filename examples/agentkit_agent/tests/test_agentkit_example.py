# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""The AgentKit example: an end-to-end run, and the sandbox rules AgentKit must obey."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
from coinbase_agentkit import pyth_action_provider
from draincheck.adapters.agentkit import (
    ANVIL_NETWORK_ID,
    UnsafeAgentKitError,
    agentkit_sandbox,
)
from draincheck.adapters.http import http_target
from draincheck.facilitator.server import serve_in_thread
from draincheck.fork import AnvilProcess, free_port
from draincheck.fork.accounts import AGENT_ADDRESS, AGENT_KEY
from draincheck.runner import TrialEnv, run_scenario
from draincheck.safety import NonDevKeyError
from draincheck.scenarios import load_scenario

from app import create_app

ROOT = Path(__file__).resolve().parents[3]
SCENARIOS = [
    ROOT / "scenarios" / "social_post" / "social-post-usdc-transfer-001.yaml",
    ROOT / "scenarios" / "memory" / "memory-fake-memory-001.yaml",
    ROOT / "scenarios" / "api_response" / "api-response-mcp-line-jumping-001.yaml",
]


class _FakeProvider:
    """Stands in for a provider that needs hosted credentials to construct."""

    name = "cdp_api"


def _env(anvil: AnvilProcess) -> TrialEnv:
    return TrialEnv(anvil.rpc_url, 31337, AGENT_KEY, AGENT_ADDRESS, "task")


@pytest.mark.anvil
@pytest.mark.parametrize("path", SCENARIOS, ids=lambda p: p.stem)
def test_agentkit_canary_is_breached_over_http(anvil: AnvilProcess, path: Path) -> None:
    scenario = load_scenario(path).model_copy(update={"trials": 3})
    with serve_in_thread(create_app(), free_port()) as base:
        result = run_scenario(scenario, http_target(base + "/run"), anvil)
    assert result.breached_count == 3


def test_sandbox_refuses_pyth_provider(anvil: AnvilProcess) -> None:
    with (
        pytest.raises(UnsafeAgentKitError),
        agentkit_sandbox(_env(anvil), action_providers=[pyth_action_provider()]),
    ):
        pass


def test_sandbox_refuses_provider_that_calls_hosted_api(anvil: AnvilProcess) -> None:
    with (
        pytest.raises(UnsafeAgentKitError),
        agentkit_sandbox(_env(anvil), action_providers=[_FakeProvider()]),
    ):
        pass


@pytest.mark.anvil
def test_sandbox_hides_cdp_and_rpc_env(
    anvil: AnvilProcess, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CDP_API_KEY_ID", "fake-id")
    monkeypatch.setenv("RPC_URL", "http://127.0.0.1:9")
    with agentkit_sandbox(_env(anvil)):
        assert "CDP_API_KEY_ID" not in os.environ
        assert "RPC_URL" not in os.environ
    assert os.environ["CDP_API_KEY_ID"] == "fake-id"
    assert os.environ["RPC_URL"] == "http://127.0.0.1:9"


@pytest.mark.anvil
def test_wallet_is_on_anvil_with_draincheck_client(anvil: AnvilProcess) -> None:
    with agentkit_sandbox(_env(anvil)) as kit:
        network = kit.wallet_provider.get_network()
        assert str(network.chain_id) == "31337"
        assert network.network_id == ANVIL_NETWORK_ID
        provider: Any = kit.wallet_provider.web3.provider
        assert provider._request_kwargs["allow_redirects"] is False


def test_trial_env_refuses_non_dev_key() -> None:
    with pytest.raises(NonDevKeyError):
        TrialEnv("http://127.0.0.1:8545", 31337, "0x" + "11" * 32, AGENT_ADDRESS, "task")


@pytest.mark.anvil
def test_agentkit_analytics_are_off_for_good(anvil: AnvilProcess) -> None:
    # AgentKit posts analytics to a Coinbase endpoint on every wallet setup and action, and
    # has no setting to stop it. The sandbox silences the sender itself, for every alias,
    # and never turns it back on (overlapping trials could otherwise undo it).
    import importlib

    module = importlib.import_module("coinbase_agentkit.analytics.send_analytics_event")
    import coinbase_agentkit.action_providers.action_decorator as decorator
    from draincheck.adapters.agentkit import SENDER, _no_analytics

    env = TrialEnv(anvil.rpc_url, 31337, AGENT_KEY, AGENT_ADDRESS, "task")
    with agentkit_sandbox(env) as kit:
        balance = next(a for a in kit.get_actions() if a.name.endswith("get_balance"))
        balance.invoke({})  # an action call: would post analytics if they were on
    for sender in (vars(module)[SENDER], vars(decorator)[SENDER]):
        assert sender.__code__ is _no_analytics.__code__
    balance.invoke({})  # still silent after the block; the tripwire fixture would fail


@pytest.mark.anvil
def test_a_provider_named_like_an_allowed_one_is_refused(anvil: AnvilProcess) -> None:
    from coinbase_agentkit import erc721_action_provider

    env = TrialEnv(anvil.rpc_url, 31337, AGENT_KEY, AGENT_ADDRESS, "task")

    class Impostor:
        name = "wallet"  # an allowed name, but not the wallet provider's class
        action_providers: tuple[Any, ...] = ()

    for provider in (Impostor(), erc721_action_provider()):
        with pytest.raises(UnsafeAgentKitError), agentkit_sandbox(env, [provider]):
            pass


@pytest.mark.anvil
def test_web3_provider_uri_is_hidden(anvil: AnvilProcess, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEB3_PROVIDER_URI", "http://127.0.0.1:9")
    env = TrialEnv(anvil.rpc_url, 31337, AGENT_KEY, AGENT_ADDRESS, "task")
    with agentkit_sandbox(env):
        assert "WEB3_PROVIDER_URI" not in os.environ
    assert os.environ["WEB3_PROVIDER_URI"] == "http://127.0.0.1:9"
