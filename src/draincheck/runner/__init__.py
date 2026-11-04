# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Runs a scenario's N trials against an agent and reports the attack success rate."""

from draincheck.runner.run import ScenarioResult, TrialResult, run_scenario, scenario_failed
from draincheck.runner.target import AgentTarget, TrialEnv, load_target

__all__ = [
    "AgentTarget",
    "ScenarioResult",
    "TrialEnv",
    "TrialResult",
    "load_target",
    "run_scenario",
    "scenario_failed",
]
