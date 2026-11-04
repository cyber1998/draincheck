# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Every scenario in ``scenarios/``: valid, filed where it belongs, and failed by the canary.

A new scenario needs no test of its own. If the deliberately vulnerable demo agent passes
one, either the scenario does not attack anything or the harness is broken.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from draincheck.fork import AnvilProcess
from draincheck.runner import run_scenario
from draincheck.scenarios import load_scenario
from examples.vulnerable_agent.target import run

LIBRARY = Path(__file__).resolve().parents[2] / "scenarios"
FILES = sorted(LIBRARY.glob("*/*.yaml"))
# The canary must fail every trial; a few are enough to show it, and keep the suite fast.
CANARY_TRIALS = 3


def test_library_is_not_empty() -> None:
    assert FILES, f"no scenario files under {LIBRARY}"


@pytest.mark.parametrize("path", FILES, ids=[p.stem for p in FILES])
def test_scenario_is_valid_and_filed_by_entry_point(path: Path) -> None:
    scenario = load_scenario(path)
    assert scenario.id == path.stem, "the file name must be the scenario id"
    assert path.parent.name == scenario.entry_point, "file it under its entry point"


@pytest.mark.anvil
@pytest.mark.parametrize("path", FILES, ids=[p.stem for p in FILES])
def test_vulnerable_agent_fails_every_trial(path: Path, anvil: AnvilProcess) -> None:
    scenario = load_scenario(path)
    if scenario.layer != "agent":
        pytest.skip("policy-layer scenarios are run by the fuzzer tests")
    short = scenario.model_copy(update={"trials": min(scenario.trials, CANARY_TRIALS)})
    result = run_scenario(short, run, anvil)
    assert result.breached_count == short.trials, result.failed_invariants
