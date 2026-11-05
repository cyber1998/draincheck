# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""The CLI end to end on the first scenario: it exits 1 and reports a $ figure.

The library test (test_library.py) covers that every scenario fails the canary agent.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from draincheck.cli import app
from draincheck.fork import AnvilProcess
from draincheck.runner import TrialEnv, run_scenario
from draincheck.scenarios import load_scenario

SCENARIO = (
    Path(__file__).resolve().parents[2]
    / "scenarios"
    / "social_post"
    / "social-post-usdc-transfer-001.yaml"
)


@pytest.mark.anvil
def test_cli_run_exits_1_with_dollar_figure() -> None:
    result = CliRunner().invoke(
        app, ["run", str(SCENARIO), "--agent", "examples.vulnerable_agent.target:run"]
    )
    assert result.exit_code == 1, result.output
    assert "FAIL social-post-usdc-transfer-001: 10/10 trials breached" in result.output
    # $500 drained + $0.01 for the feed + the gas tips, which count as outflow.
    assert "max outflow $500." in result.output


@pytest.mark.anvil
def test_installed_cli_imports_agent_from_working_directory() -> None:
    # The console script, not CliRunner: pytest already puts the repo root on sys.path,
    # which hid that `draincheck run --agent examples...` could not import the agent.
    exe = Path(sys.executable).parent / "draincheck"
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    proc = subprocess.run(
        [str(exe), "run", str(SCENARIO), "--agent", "examples.vulnerable_agent.target:run"],
        cwd=SCENARIO.parents[2],
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "FAIL social-post-usdc-transfer-001" in proc.stdout


def _broken_agent(env: TrialEnv) -> None:
    raise ImportError("no module named 'my_agent'")


@pytest.mark.anvil
def test_agent_that_crashes_every_trial_fails(anvil: AnvilProcess) -> None:
    # Without this rule an agent that never ran would report PASS 0/N breached.
    result = run_scenario(load_scenario(SCENARIO), _broken_agent, anvil)
    assert result.breached_count == 0
    assert result.all_crashed
    assert result.failed
