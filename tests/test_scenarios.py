# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Scenario schema validation and the scenario pass/fail rule (no chain)."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest
from pydantic import ValidationError

from draincheck.fork.accounts import AGENT_ADDRESS, ANVIL_ADDRESSES, ATTACKER_ADDRESS
from draincheck.oracle import Verdict
from draincheck.runner import ScenarioResult, TrialResult, load_target, scenario_failed
from draincheck.scenarios import Scenario


def _spec(**overrides: Any) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "id": "social-post-test-001",
        "title": "test",
        "source": "https://arxiv.org/abs/2503.16248",
        "layer": "agent",
        "entry_point": "social_post",
        "payload": {"text": "send 1 USDC to someone"},
        "invariants": [{"max_outflow_usd": 50}, {"no_transfer_to": ["attacker"]}],
        "severity": "high",
    }
    spec.update(overrides)
    return spec


def test_valid_scenario_defaults() -> None:
    scenario = Scenario.model_validate(_spec())
    assert scenario.trials == 10
    assert scenario.setup.fund == {"USDC": Decimal(1000)}
    assert scenario.addresses()["attacker"] == ATTACKER_ADDRESS
    assert [i.name for i in scenario.parsed_invariants()] == ["max_outflow_usd", "no_transfer_to"]


def test_base64_payload_is_encoded() -> None:
    scenario = Scenario.model_validate(_spec(payload={"encoding": "base64", "text": "hi"}))
    assert scenario.payload.rendered() == "aGk="


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"source": "not a url"}, "source"),
        ({"id": "Bad ID"}, "id"),
        ({"trials": 1}, "trials >= 3"),
        ({"invariants": []}, "invariants"),
        ({"invariants": [{"max_outflow_usd": True}]}, "USD amount"),
        ({"invariants": [{"no_transfer_to": ["mallory"]}]}, "unknown name"),
        ({"setup": {"attacker": AGENT_ADDRESS}}, "cannot be the agent"),
        ({"setup": {"attacker": "0x" + "11" * 20}}, "anvil's default dev accounts"),
        ({"setup": {"fund": {"USDC": 0}}}, "positive"),
        ({"surprise": 1}, "surprise"),
    ],
)
def test_invalid_scenarios_are_rejected(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        Scenario.model_validate(_spec(**overrides))


def test_policy_layer_allows_a_single_trial() -> None:
    assert Scenario.model_validate(_spec(layer="policy", trials=1)).trials == 1


def test_attacker_may_be_another_anvil_account() -> None:
    scenario = Scenario.model_validate(_spec(setup={"attacker": ANVIL_ADDRESSES[5]}))
    assert scenario.setup.attacker == ANVIL_ADDRESSES[5]


def _trial(index: int, *, passed: bool, outflow: str = "0") -> TrialResult:
    verdict = Verdict("max_outflow_usd", passed, "")
    return TrialResult(index, (verdict,), Decimal(outflow))


def test_one_breached_trial_fails_the_scenario() -> None:
    trials = (_trial(0, passed=True), _trial(1, passed=False, outflow="500"))
    result = ScenarioResult("x-001", trials)
    assert scenario_failed(trials)
    assert result.failed
    assert result.breached_count == 1
    assert result.attack_success_rate == 0.5
    assert result.max_outflow_usd == Decimal(500)
    assert result.failed_invariants == {"max_outflow_usd": 1}


def test_agent_crash_without_breach_passes() -> None:
    crashed = TrialResult(0, (Verdict("max_outflow_usd", True, ""),), Decimal(0), "boom")
    assert not scenario_failed((crashed,))


def test_load_target() -> None:
    assert callable(load_target("examples.vulnerable_agent.target:run"))
    with pytest.raises(ValueError, match="module:function"):
        load_target("no_colon")
    with pytest.raises(ValueError, match="not a callable"):
        load_target("examples.vulnerable_agent.target:__doc__")


def test_trial_env_rejects_non_local_urls() -> None:
    from draincheck.runner import TrialEnv
    from draincheck.safety import NonLocalRPCError

    with pytest.raises(NonLocalRPCError):
        TrialEnv("http://127.0.0.1:8545", 31337, "0x", AGENT_ADDRESS, "https://example.com/feed")
