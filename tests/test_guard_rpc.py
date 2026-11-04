# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""The guard hook is a safety net, so test it like one: exact exit codes, both directions."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

HOOK = Path(__file__).resolve().parent.parent / ".claude" / "hooks" / "guard_rpc.py"
ANVIL_KEY_0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
NOT_AN_ANVIL_KEY = "0x" + "1f" * 32


def run_hook(payload: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(HOOK)], input=payload, capture_output=True, text=True, check=False
    )


def bash(command: str) -> str:
    return json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})


@pytest.mark.parametrize(
    "command",
    [
        "cast balance 0xabc --rpc-url https://mainnet.base.org",
        "curl https://base-mainnet.g.alchemy.com/v2/abc",
        "anvil --fork-url https://some-node.example.com",
        'curl -X POST -d \'{"method":"eth_sendRawTransaction"}\' https://node.example.com',
        f"cast send --private-key {NOT_AN_ANVIL_KEY} 0xabc",
        f"export KEY={NOT_AN_ANVIL_KEY[2:]}",
        "cast block --rpc-url wss://node.example.com",
    ],
)
def test_blocks(command: str) -> None:
    result = run_hook(bash(command))
    assert result.returncode == 2, result.stderr
    assert "guard_rpc blocked" in result.stderr


@pytest.mark.parametrize(
    "command",
    [
        "cast balance 0xabc --rpc-url http://127.0.0.1:8545",
        'anvil --fork-url "$DRAINCHECK_FORK_URL" --port 8545',
        f"cast send --private-key {ANVIL_KEY_0} 0xabc --rpc-url http://localhost:8545",
        "git push -u origin main",
        "git clone https://github.com/cyber1998/draincheck",
        "uv add httpx && curl -sSf https://pypi.org/simple/httpx/",
        "uv run pytest",
        "git log -1 --format=%H",
    ],
)
def test_allows(command: str) -> None:
    result = run_hook(bash(command))
    assert result.returncode == 0, result.stderr


def test_ignores_other_tools() -> None:
    payload = json.dumps({"tool_name": "Read", "tool_input": {"file_path": NOT_AN_ANVIL_KEY}})
    assert run_hook(payload).returncode == 0


def test_blocks_on_unparseable_input() -> None:
    assert run_hook("not json").returncode == 2
