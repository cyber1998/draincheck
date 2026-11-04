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
- `AnvilProcess` can fork Base at a pinned block (`DEFAULT_BASE_FORK_BLOCK`, overridable
  with `DRAINCHECK_FORK_BLOCK`). It forks only when `DRAINCHECK_FORK_URL` is set, and runs
  forks with chain id 31337. New `snapshot()`, `revert()`, `isolated()` and `rpc()` helpers.
- `fork` pytest marker and `base_fork` fixture for tests that need a real Base fork. They
  skip when `DRAINCHECK_FORK_URL` is unset.
