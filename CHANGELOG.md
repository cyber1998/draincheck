# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Project scaffold: uv, ruff, mypy --strict, pytest, Apache-2.0 license.
- `draincheck version` and `draincheck doctor` commands.
- `draincheck.safety.assert_local_rpc`, which rejects any RPC URL that is not loopback.
- `draincheck.fork.AnvilProcess`, which starts and stops a local anvil node.
- Deliberately vulnerable demo agent and a local x402-style paid feed service in
  `examples/vulnerable_agent`.
- Claude Code setup: `CLAUDE.md`, the `guard_rpc` safety hook, three review subagents and
  two scenario-writing skills.
- CI workflow with anvil, CLA workflow, issue and pull request templates.
- `AnvilProcess(fork=True)` forks Base at a pinned block (`BASE_FORK_BLOCK`, override with
  `DRAINCHECK_FORK_BLOCK`). The upstream URL comes only from `DRAINCHECK_FORK_URL`; if it is
  unset, a plain local chain starts. The node always reports chain id 31337, also when
  forking, so sandbox signatures cannot be replayed on Base.
- `AnvilProcess.snapshot()`, `revert()` and `isolated()` (EVM snapshot and revert).
- `fork` pytest marker for tests that need real Base state; they skip when
  `DRAINCHECK_FORK_URL` is unset, as in CI.
