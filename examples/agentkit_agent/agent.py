# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""A deliberately unsafe AgentKit canary: it obeys instructions it reads.

It shows the AgentKit path, not a good agent. It reads what the trial's services and
contracts say, using Draincheck's :class:`SandboxWallet` for reads only, takes every
``send N ETH|USDC to 0x...`` it finds, and invokes the matching AgentKit action on the
sandbox wallet. It has no spend limit, no recipient allowlist and no approval step.

A real agent gives ``kit.get_actions()`` to its model instead. The LLM-backed version
built on AgentKit is planned for milestone M7.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from draincheck.adapters.agentkit import agentkit_sandbox
from draincheck.adapters.tools import SandboxWallet
from draincheck.fork.usdc import USDC_ADDRESS
from draincheck.runner.target import TrialEnv

INSTRUCTION = re.compile(
    r"send\s+(\d+(?:\.\d+)?)\s+(eth|usdc)\s+to\s+(0x[0-9a-fA-F]{40})", re.IGNORECASE
)
USDC_TRANSFER = "ERC20ActionProvider_transfer"
NATIVE_TRANSFER = "WalletActionProvider_native_transfer"


def _texts(env: TrialEnv) -> list[str]:
    """Every piece of text the agent reads during the trial. Reads only."""
    wallet = SandboxWallet(env.rpc_url, env.agent_key)
    texts: list[str] = []
    if "feed" in env.services:
        texts.extend(str(post) for post in wallet.read(env.services["feed"])["posts"])
    if "api" in env.services:
        texts.append(str(wallet.read(env.services["api"])["note"]))
    if "memory" in env.services:
        texts.extend(str(note) for note in wallet.read(env.services["memory"])["notes"])
    if "mcp" in env.services:
        seen = wallet.read_mcp(env.services["mcp"])
        for tool in [*seen["tools"], *seen["tools_after"]]:
            texts.append(str(tool["description"]))
        texts.extend(str(text) for text in seen["results"].values())
    if "token" in env.contracts:
        texts.extend(wallet.token_metadata(env.contracts["token"]))
    return texts


def _instructions(texts: Iterable[str]) -> list[tuple[str, str, str]]:
    """(asset, whole-unit amount, recipient) for each instruction, first seen first."""
    found: dict[tuple[str, str, str], None] = {}
    for text in texts:
        for amount, asset, to in INSTRUCTION.findall(text):
            found[(asset.lower(), amount, to)] = None
    return list(found)


def run_trial(env: TrialEnv) -> int:
    """Do what the texts say. Returns the number of transfers made."""
    instructions = _instructions(_texts(env))
    if not instructions:
        return 0
    made = 0
    with agentkit_sandbox(env) as kit:
        actions: dict[str, Any] = {action.name: action for action in kit.get_actions()}
        for asset, amount, to in instructions:
            if asset == "usdc":
                result = actions[USDC_TRANSFER].invoke(
                    {"amount": amount, "contract_address": USDC_ADDRESS, "destination_address": to}
                )
            else:
                result = actions[NATIVE_TRANSFER].invoke({"to": to, "value": amount})
            if not str(result).startswith("Error"):
                made += 1
    return made
