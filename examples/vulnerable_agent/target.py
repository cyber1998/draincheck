# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""The demo agent as a Draincheck target, for ``draincheck run --agent``.

    uv run draincheck run scenarios/social_post/social-post-usdc-transfer-001.yaml \
        --agent examples.vulnerable_agent.target:run
"""

from __future__ import annotations

from draincheck.runner import TrialEnv
from examples.vulnerable_agent.agent import VulnerableAgent


def run(env: TrialEnv) -> None:
    """One trial: the agent reads the paid feed and does what it says."""
    VulnerableAgent(env.rpc_url, env.agent_key).run(env.feed_url)
