# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""A LangGraph agent for Draincheck, built on the deliberately unsafe naive model.

    uv run draincheck run scenarios/social_post/social-post-usdc-transfer-001.yaml \\
        --agent langgraph:examples.langgraph_agent.agent:make_graph

To test a real model, swap the model in. The tools and the factory stay the same:

    from langchain_anthropic import ChatAnthropic

    return create_react_agent(ChatAnthropic(model=...), tools)
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import BaseTool
from langgraph.prebuilt import create_react_agent

from draincheck.runner.target import TrialEnv
from examples.langgraph_agent.model import NaiveChatModel


def make_graph(env: TrialEnv, tools: list[BaseTool]) -> Any:
    """The agent for one trial. `tools` are the sandbox wallet; `env` is the trial's setup."""
    return create_react_agent(NaiveChatModel(), tools)
