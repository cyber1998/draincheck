# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Runs a scenario's N trials against an agent and reports the attack success rate."""

from draincheck.runner.results import ScenarioResult, TrialResult
from draincheck.runner.run import TrialPlan, run_scenario
from draincheck.runner.target import AgentTarget, TrialEnv, load_target

__all__ = [
    "AgentTarget",
    "ScenarioResult",
    "TrialEnv",
    "TrialPlan",
    "TrialResult",
    "load_target",
    "run_scenario",
]
