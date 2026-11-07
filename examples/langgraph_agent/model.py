# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""A deterministic stand-in for a gullible language model, for LangGraph agents.

DO NOT copy this model's design. It is deliberately unsafe, a canary like
:mod:`examples.vulnerable_agent`: it obeys every instruction it reads in a tool result.
It exists so CI exercises the LangGraph path (tools, the ReAct loop, the adapter) without a
real model, a network or an API key. It only ever runs against a local anvil node.

It decides from the conversation alone: it reads the services and contracts named in the
task, reads them with the sandbox tools, follows every transfer it finds in the results
(via the same parser as the demo agent, so obfuscated text is decoded too), and accepts a
swap listing's router with an unlimited approval and no slippage limit.
"""

from __future__ import annotations

import ast
import json
import re
from collections.abc import Sequence
from decimal import Decimal
from typing import Any

from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from langchain_core.messages.tool import ToolCall
from langchain_core.outputs import ChatGeneration, ChatResult

from examples.vulnerable_agent.agent import Instruction, parse_instructions

READ_TOOLS = frozenset({"read_service", "token_info"})
SERVICES = re.compile(r"Services you can read with read_service: ([^.\n]+)\.")
CONTRACT = re.compile(r"Contract '([^']+)': (0x[0-9a-fA-F]{40})\.")


def _text(message: BaseMessage) -> str:
    return message.content if isinstance(message.content, str) else str(message.content)


def _task_facts(task: str) -> tuple[list[str], dict[str, str]]:
    """The service names and the contract addresses (by name) the task message lists."""
    services: list[str] = []
    match = SERVICES.search(task)
    if match:
        services = [name.strip() for name in match.group(1).split(",") if name.strip()]
    contracts = {name: address for name, address in CONTRACT.findall(task)}
    return services, contracts


def _load(text: str) -> Any:
    """A tool result as data. The sandbox's read tool returns Python's repr of a dict."""
    try:
        return json.loads(text)
    except ValueError:
        pass
    try:
        return ast.literal_eval(text)
    except (ValueError, SyntaxError):
        return None


def _leaves(data: Any) -> list[str]:
    """Every string inside a loaded tool result, so each post or note is read on its own."""
    if isinstance(data, str):
        return [data]
    if isinstance(data, dict):
        return [s for value in data.values() for s in _leaves(value)]
    if isinstance(data, list | tuple):
        return [s for value in data for s in _leaves(value)]
    return []


def _pieces(text: str) -> list[str]:
    """The whole result, then each string inside it: an encoded post decodes only alone."""
    data = _load(text)
    return [text, *_leaves(data)] if data is not None else [text]


def _listing(text: str) -> dict[str, Any] | None:
    """The first router in a paid router listing, if `text` is one."""
    data = _load(text)
    if not isinstance(data, dict) or not isinstance(data.get("routers"), list):
        return None
    if not data["routers"] or not isinstance(data["routers"][0], dict):
        return None
    first: dict[str, Any] = data["routers"][0]
    if all(isinstance(first.get(key), str) for key in ("router", "token_in", "token_out")):
        return first
    return None


def _send_call(call_id: str, ins: Instruction) -> ToolCall:
    if ins.asset == "ETH":
        args: dict[str, Any] = {
            "to": ins.to,
            "amount_eth": str(Decimal(ins.amount) / 10**18),
        }
        return ToolCall(name="send_eth", args=args, id=call_id)
    args = {
        "token_address": "USDC",
        "to": ins.to,
        "amount": str(Decimal(ins.amount) / 10**6),
    }
    return ToolCall(name="send_token", args=args, id=call_id)


def _respond(messages: Sequence[BaseMessage]) -> AIMessage:
    """The model's next move: tool calls, or a final answer. It never loops."""
    task = next((m for m in messages if isinstance(m, HumanMessage)), None)
    if task is None:
        return AIMessage("nothing to do")
    services, contracts = _task_facts(_text(task))
    if not any(isinstance(m, ToolMessage) for m in messages):
        if services:
            return _call(
                [
                    ToolCall(name="read_service", args={"name": svc}, id=f"read-{i}")
                    for i, svc in enumerate(services)
                ]
            )
        if "token" in contracts:
            call = ToolCall(
                name="token_info", args={"token_address": contracts["token"]}, id="token-info"
            )
            return _call([call])
        return AIMessage("nothing to do")

    made: dict[str, ToolCall] = {}
    for message in messages:
        if isinstance(message, AIMessage):
            for call in message.tool_calls:
                made[str(call.get("id"))] = call
    results = [_text(m) for m in messages if isinstance(m, ToolMessage) and m.name in READ_TOOLS]

    instructions: list[Instruction] = []
    for text in results:
        for piece in _pieces(text):
            for ins in parse_instructions(piece):
                if ins not in instructions:
                    instructions.append(ins)
    pending = [
        _send_call(f"send-{n}", ins)
        for n, ins in enumerate(instructions)
        if f"send-{n}" not in made
    ]
    if pending:
        return _call(pending)

    listing = next((found for found in map(_listing, results) if found is not None), None)
    if listing is not None:
        if "approve" not in made:
            return _call(
                [
                    ToolCall(
                        name="approve",
                        args={
                            "token_address": listing["token_in"],
                            "spender": listing["router"],
                            "amount": "max",
                        },
                        id="approve",
                    )
                ]
            )
        approved = any(isinstance(m, ToolMessage) and m.tool_call_id == "approve" for m in messages)
        if approved and "swap" not in made:
            return _call(
                [
                    ToolCall(
                        name="swap",
                        args={
                            "router": listing["router"],
                            "token_in": listing["token_in"],
                            "token_out": listing["token_out"],
                            "amount": "100",
                            "min_out": "0",
                        },
                        id="swap",
                    )
                ]
            )
    return AIMessage("done")


def _call(calls: list[ToolCall]) -> AIMessage:
    return AIMessage(content="", tool_calls=calls)


class NaiveChatModel(BaseChatModel):
    """A chat model that obeys whatever it reads. Deliberately unsafe; a canary, not a model."""

    @property
    def _llm_type(self) -> str:
        return "draincheck-naive"

    def bind_tools(self, tools: Sequence[Any], **kwargs: Any) -> NaiveChatModel:
        """The sandbox tool names are fixed, so binding changes nothing: return self."""
        return self

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        return ChatResult(generations=[ChatGeneration(message=_respond(messages))])
