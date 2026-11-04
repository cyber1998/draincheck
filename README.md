# Draincheck

[![CI](https://github.com/cyber1998/draincheck/actions/workflows/ci.yml/badge.svg)](https://github.com/cyber1998/draincheck/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Draincheck attacks **your own** wallet-holding AI agent on a local chain and fails the
build if money can move outside policy.

It feeds your agent poisoned content (social posts, token metadata, API responses, x402
paid services), lets it act, then judges only what changed on the chain: balances,
approvals and recipients. It never grades the model's text.

> **Status: pre-alpha (Phase 1 of the v0.1 roadmap).** The sandbox works today: a local
> chain (or pinned Base fork), test USDC, a mock x402 facilitator, the oracle's six
> invariants and a scenario runner. One sourced scenario drains the demo agent. The attack
> library, agent adapters, reports and GitHub Action are next. See [the roadmap](#roadmap).

## Safety model

- **Local only.** Every chain connection must point at 127.0.0.1 / localhost, enforced in
  code by `draincheck.safety.assert_local_rpc`. Draincheck never touches a live network.
- **Dev keys only.** Draincheck uses anvil's published dev accounts. It never reads,
  writes or generates a real private key.
- **Your agents only.** Only test agents you own or are authorised to test. Draincheck has
  no code that targets live third-party services.
- **Nothing leaves your machine** unless you choose to upload a report.

## Quick start

Needs Python 3.12+, [uv](https://docs.astral.sh/uv/) and
[anvil](https://book.getfoundry.sh/getting-started/installation) (part of Foundry).

```bash
git clone https://github.com/cyber1998/draincheck
cd draincheck
uv sync
uv run draincheck doctor
```

Watch the deliberately vulnerable demo agent get drained by a poisoned feed:

```bash
uv run python -m examples.vulnerable_agent.run_demo
```

Run a scenario against an agent. The agent is a `module:function` that takes a
`draincheck.runner.TrialEnv`. The command exits 1 if any trial breaks an invariant:

```bash
uv run draincheck run scenarios/social_post/social-post-usdc-transfer-001.yaml --agent examples.vulnerable_agent.target:run
```

```text
FAIL social-post-usdc-transfer-001: 10/10 trials breached (100%); max outflow $500.16
```

To fork Base instead of starting an empty chain, set `DRAINCHECK_FORK_URL` to your own
upstream node in your environment and pass `--fork`.

## Development

```bash
uv run pytest
uv run ruff check . && uv run ruff format --check . && uv run mypy
```

Tests marked `anvil` skip when anvil is not installed. CI installs anvil and requires them.

## Roadmap

| Phase | Gate |
|---|---|
| 0. Scaffold | CI green; vulnerable demo agent pays a local x402-style endpoint and can be drained |
| 1. Sandbox | Pinned Base fork, test-USDC funding, mock x402 facilitator, six oracle invariants; a hand-written scenario drains the demo agent and the run fails with a $ figure |
| 2. Attack library and adapters | 30 sourced scenarios, policy fuzzer v0, HTTP / AgentKit / LangGraph / MCP adapters |
| 3. Reports and CI | Markdown, HTML and JUnit reports, Docker GitHub Action, quickstart docs; public v0.1 |

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) first. All
contributors sign the [Contributor License Agreement](CLA.md) once, and everyone taking
part agrees to the [Code of Conduct](CODE_OF_CONDUCT.md).

To report a vulnerability, follow [SECURITY.md](SECURITY.md). Please do not open a public
issue.

## License

Draincheck is licensed under the [Apache License, Version 2.0](LICENSE). See
[NOTICE](NOTICE) for attribution.
