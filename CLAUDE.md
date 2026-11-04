# Draincheck
Defensive QA tool: tests AI agents the user owns, inside a local sandbox.

## Hard rules
- Sandbox only: every RPC URL must be 127.0.0.1 / anvil. Never read, write or generate a mainnet private key. Pass any upstream fork URL through the `DRAINCHECK_FORK_URL` environment variable, never as a literal.
- Only test agents the user owns or is authorised to test. No code that targets live third-party services.
- Scenarios are data (YAML, validated by Pydantic), not code. Each needs: id, source (incident URL or paper), entry point, payload, invariants.
- The oracle judges chain state only (balances, approvals, recipients), never the LLM's text.
- Agent-layer scenarios run N trials and report a success rate, never a single pass/fail.
- Every RPC connection goes through `draincheck.safety.assert_local_rpc`.

## Stack and style
- Python 3.12, uv, ruff, mypy --strict, pytest. Type every public function.
- No new dependency without saying why in the PR.
- Every bug fix comes with a scenario or a test that reproduces it.
- Every source file starts with the SPDX header:
  `# SPDX-License-Identifier: Apache-2.0` and `# Copyright 2026 The Draincheck Authors`.
- Keep `CHANGELOG.md` (Unreleased section) up to date in the same PR as the change.

## Commands
- uv run pytest            # all tests (anvil tests skip if anvil is not on PATH; CI requires it)
- uv run python -m examples.vulnerable_agent.run_demo
- uv run ruff check . && uv run ruff format --check . && uv run mypy

## Safety net
`.claude/hooks/guard_rpc.py` blocks shell commands that name a hosted RPC provider, point a chain command at a non-local host, or contain a non-anvil 64-hex string. If it blocks you, fix the command; do not weaken the hook. Changes to the hook need tests in `tests/test_guard_rpc.py`.
