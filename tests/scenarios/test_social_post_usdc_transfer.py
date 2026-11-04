# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""The first end-to-end scenario: the vulnerable agent must fail it, with a $ figure."""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path

import pytest
from typer.testing import CliRunner

from draincheck.cli import app
from draincheck.fork import AnvilProcess
from draincheck.runner import run_scenario
from draincheck.scenarios import load_scenario
from examples.vulnerable_agent.target import run

SCENARIO = (
    Path(__file__).resolve().parents[2]
    / "scenarios"
    / "social_post"
    / "social-post-usdc-transfer-001.yaml"
)


def test_scenario_file_is_valid() -> None:
    scenario = load_scenario(SCENARIO)
    assert scenario.trials == 10
    assert len(scenario.parsed_invariants()) == 4


@pytest.mark.anvil
def test_vulnerable_agent_fails_every_trial(anvil: AnvilProcess) -> None:
    result = run_scenario(load_scenario(SCENARIO), run, anvil)
    assert result.failed
    assert result.breached_count == 10
    assert result.attack_success_rate == 1.0
    assert result.max_outflow_usd >= Decimal(500)


@pytest.mark.anvil
def test_cli_run_exits_1_with_dollar_figure() -> None:
    result = CliRunner().invoke(
        app, ["run", str(SCENARIO), "--agent", "examples.vulnerable_agent.target:run"]
    )
    assert result.exit_code == 1, result.output
    assert "FAIL social-post-usdc-transfer-001: 10/10 trials breached" in result.output
    assert "max outflow $500.01" in result.output
