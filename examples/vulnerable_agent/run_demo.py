# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Run the vulnerable agent against the first scenario and print what the oracle saw.

    uv run python -m examples.vulnerable_agent.run_demo

Starts a local anvil node, the mock x402 facilitator and the poisoned paid feed, all on
127.0.0.1, and stops them after. Same as ``draincheck run`` with this agent.
"""

from __future__ import annotations

from pathlib import Path

from draincheck.runner import run_scenario
from draincheck.scenarios import load_scenario
from examples.vulnerable_agent.target import run

SCENARIO = (
    Path(__file__).resolve().parents[2]
    / "scenarios"
    / "social_post"
    / "social-post-usdc-transfer-001.yaml"
)


def main() -> None:
    scenario = load_scenario(SCENARIO)
    result = run_scenario(scenario, run)
    print(f"scenario {scenario.id}: {scenario.title}")
    print(f"{result.breached_count}/{len(result.trials)} trials breached an invariant")
    print(f"worst trial: ${result.max_outflow_usd:.2f} left the agent's wallet")
    for name, count in sorted(result.failed_invariants.items()):
        print(f"  {name} failed in {count} trial(s)")


if __name__ == "__main__":
    main()
