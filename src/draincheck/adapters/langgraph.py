# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Test a LangGraph agent. Needs the extra: ``pip install 'draincheck[langgraph]'``.

    draincheck run scenario.yaml --agent langgraph:my_agent.graph:make_graph

Your factory builds the agent for one trial:

    def make_graph(env: TrialEnv, tools: list[BaseTool]) -> CompiledStateGraph: ...

`tools` are the sandbox wallet (:class:`~draincheck.adapters.tools.SandboxWallet`) as
LangChain tools: read a service, check a token or balance, send ETH or tokens, approve,
swap. Give them to your model as it would use its real wallet tools. Draincheck then runs
the graph once per trial on the trial's task and judges what happened on chain.
"""

from __future__ import annotations

import functools
import importlib
import json
from collections.abc import Callable
from decimal import Decimal, InvalidOperation
from typing import Any

from draincheck.adapters.tools import UNLIMITED, SandboxWallet
from draincheck.fork.usdc import USDC_ADDRESS
from draincheck.runner.target import AgentTarget, TrialEnv

try:
    from langchain_core.tools import BaseTool, StructuredTool, ToolException
    from langsmith import tracing_context
except ImportError as err:  # pragma: no cover - only without the extra
    raise ImportError(
        "the LangGraph adapter needs the extra: pip install 'draincheck[langgraph]'"
    ) from err

# Graph steps per trial before LangGraph stops it; a stuck agent counts as crashed.
RECURSION_LIMIT = 40


def task_message(env: TrialEnv) -> str:
    """The trial's task, plus what the agent can reach, as its first user message."""
    lines = [env.task, "", f"Your wallet address is {env.agent_address}."]
    if env.services:
        lines.append(f"Services you can read with read_service: {', '.join(env.services)}.")
    for name, address in env.contracts.items():
        lines.append(f"Contract '{name}': {address}.")
    lines.append(f"USDC is at {USDC_ADDRESS}; you may also call it 'USDC'.")
    return "\n".join(lines)


def sandbox_tools(env: TrialEnv) -> list[BaseTool]:
    """The sandbox wallet for `env` as LangChain tools. Amounts are in whole tokens."""
    wallet = SandboxWallet(env.rpc_url, env.agent_key)

    def token(name: str) -> str:
        return USDC_ADDRESS if name.strip().upper() == "USDC" else name.strip()

    def units(amount: str, decimals: int) -> int:
        try:
            value = Decimal(amount)
        except InvalidOperation as err:
            raise ValueError(f"not an amount: {amount!r}") from err
        if not value.is_finite() or value < 0:
            raise ValueError(f"not an amount: {amount!r}")
        return int(value * 10**decimals)

    def read_service(name: str) -> str:
        """Read one of your services by name (it may charge a small x402 fee)."""
        if name not in env.services:
            raise ValueError(f"no service {name!r}; you have {', '.join(env.services)}")
        if name == "mcp":  # what an MCP client sees: tool listings and results
            return json.dumps(wallet.read_mcp(env.services[name]))
        return json.dumps(wallet.read(env.services[name]))

    def token_info(token_address: str) -> str:
        """The name and symbol a token contract reports."""
        name, symbol = wallet.token_metadata(token(token_address))
        return f"name: {name}; symbol: {symbol}"

    def balance(token_address: str = "") -> str:
        """Your balance: native ETH in wei if no token is given, else the token's base units."""
        return str(wallet.balance(token(token_address) if token_address else None))

    def send_eth(to: str, amount_eth: str) -> str:
        """Send `amount_eth` ETH to `to`. Returns the transaction hash."""
        return wallet.send_eth(to, units(amount_eth, 18))

    def send_token(token_address: str, to: str, amount: str) -> str:
        """Send `amount` whole tokens (e.g. "12.5") of a token, or "USDC". Returns the hash."""
        address = token(token_address)
        return wallet.transfer(address, to, units(amount, wallet.decimals(address)))

    def approve(token_address: str, spender: str, amount: str) -> str:
        """Let `spender` move up to `amount` whole tokens of yours; "max" means no limit."""
        address = token(token_address)
        if amount.strip().lower() == "max":
            return wallet.approve(address, spender, UNLIMITED)
        return wallet.approve(address, spender, units(amount, wallet.decimals(address)))

    def swap(router: str, token_in: str, token_out: str, amount: str, min_out: str = "0") -> str:
        """Swap `amount` of token_in for token_out through `router`. Approve the router first."""
        address_in, address_out = token(token_in), token(token_out)
        return wallet.swap(
            router,
            address_in,
            address_out,
            units(amount, wallet.decimals(address_in)),
            units(min_out, wallet.decimals(address_out)),
        )

    functions: list[Callable[..., str]] = [
        read_service,
        token_info,
        balance,
        send_eth,
        send_token,
        approve,
        swap,
    ]
    return [StructuredTool.from_function(_reported(f), handle_tool_error=True) for f in functions]


def _reported(function: Callable[..., str]) -> Callable[..., str]:
    """Turn any error into a ToolException, which LangGraph hands back to the model.

    A bad amount or a reverted transaction is something the agent should see and react
    to, as with a real wallet tool; it is not the agent crashing.
    """

    @functools.wraps(function)
    def call(*args: Any, **kwargs: Any) -> str:
        try:
            return function(*args, **kwargs)
        except ToolException:
            raise
        except Exception as err:
            raise ToolException(f"{type(err).__name__}: {err}") from err

    return call


def langgraph_target(spec: str) -> AgentTarget:
    """A target from ``"package.module:factory"``; the factory builds one trial's graph."""
    module_name, sep, attr = spec.partition(":")
    if not sep or not module_name or not attr:
        raise ValueError(f"a LangGraph agent looks like 'langgraph:module:factory', got {spec!r}")
    factory = getattr(importlib.import_module(module_name), attr, None)
    if not callable(factory):
        raise ValueError(f"{spec!r} is not a callable")

    def run(env: TrialEnv) -> None:
        # LangChain would otherwise trace to a hosted service whenever LANGSMITH_TRACING or
        # LANGCHAIN_TRACING_V2 is set, posting the task, tool calls and results off the
        # machine. Tracing stays off for the whole trial, whatever the environment says.
        with tracing_context(enabled=False):
            graph: Any = factory(env, sandbox_tools(env))
            graph.invoke(
                {"messages": [("user", task_message(env))]},
                {"recursion_limit": RECURSION_LIMIT},
            )

    return run
