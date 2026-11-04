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

### Fixed

- `guard_rpc` hook no longer blocks commands that only mention "anvil" or "rpc" in prose
  (for example a commit message with a link). It now treats a command as chain-related
  only when it runs a Foundry tool, passes an RPC flag, sends an `eth_` method or builds
  a web3 provider.
