#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""PreToolUse hook: block shell commands that could reach a real chain or leak a real key.

Reads the Claude Code tool call as JSON on stdin. Exit code 2 blocks the command and shows
the reason on stderr. Standard library only, so it runs before any environment is synced.

Blocks a Bash command when it:
  * names a known hosted RPC provider, or
  * is chain-related (runs cast/anvil/forge, uses --rpc-url or --fork-url, sends an eth_
    method, or builds a web3 provider) and names any non-local URL, or
  * contains a 64-hex-character string (private-key shaped) that is not one of anvil's
    published dev keys.

Pass upstream fork URLs through an environment variable (for example
DRAINCHECK_FORK_URL) instead of writing them into commands.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys

URL = re.compile(r"\b(?:https?|wss?)://(\[[^\]]+\]|[^\s/:'\"`)\]]+)", re.IGNORECASE)
HEX64 = re.compile(r"(?<![0-9a-fA-F])(?:0x)?([0-9a-fA-F]{64})(?![0-9a-fA-F])")
# A command is chain-related when it runs a Foundry tool, passes an RPC flag, sends a
# JSON-RPC method, or builds a web3 provider. Mere mentions of "anvil" or "rpc" in prose
# (commit messages, docs) do not count.
CHAIN_RELATED = re.compile(
    r"(?:^|[;&|(`\n]|\$\()\s*(?:\w+=\S*\s+)*(?:\S*/)?(?:cast|anvil|forge|chisel)\b"
    r"|--(?:rpc-url|fork-url|rpc)\b|\beth_[a-zA-Z]+|\b(?:HTTPProvider|WebsocketProvider)\b",
    re.IGNORECASE,
)
RPC_PROVIDERS = re.compile(
    r"alchemy\.com|infura\.io|quiknode\.pro|quicknode|ankr\.com|llamarpc|publicnode|drpc\.org|"
    r"chainstack|blastapi|getblock|tenderly\.co|base\.org|coinbase\.com|cloudflare-eth|"
    r"blockpi|nodereal|1rpc\.io|onfinality",
    re.IGNORECASE,
)

# Anvil's default mnemonic ("test test ... junk"), accounts 0-9. Public; hold nothing real.
ANVIL_DEV_KEYS = frozenset(
    {
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
        "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
        "7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
        "47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
        "8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
        "92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
        "4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
        "dbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
        "2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
    }
)


def is_local(host: str) -> bool:
    host = host.strip("[]").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check(command: str) -> str | None:
    """Return a reason to block `command`, or None to allow it."""
    chain_related = bool(CHAIN_RELATED.search(command))
    for match in URL.finditer(command):
        host = match.group(1)
        if is_local(host):
            continue
        if RPC_PROVIDERS.search(host):
            return f"command names a hosted RPC provider ({host}); Draincheck stays local"
        if chain_related:
            return f"chain command points at a non-local host ({host}); use 127.0.0.1 / anvil"
    for match in HEX64.finditer(command):
        if match.group(1).lower() not in ANVIL_DEV_KEYS:
            return (
                "command contains a private-key-shaped 64-hex string that is not an anvil "
                "dev key; never put real keys in commands"
            )
    return None


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except json.JSONDecodeError:
        print("guard_rpc: could not parse hook input; blocking to be safe", file=sys.stderr)
        return 2
    if event.get("tool_name") != "Bash":
        return 0
    command = str((event.get("tool_input") or {}).get("command", ""))
    reason = check(command)
    if reason is None:
        return 0
    print(f"guard_rpc blocked this command: {reason}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
