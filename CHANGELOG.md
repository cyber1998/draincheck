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
- Sandbox contracts in `contracts/`: TestUSDC (USDC's EIP-712 domain, EIP-2612, EIP-3009)
  and minimal Permit2 / x402 `upto` stand-ins, with `scripts/build_contracts.py` to rebuild
  the bundled ABI and bytecode. CI fails if the bundled artifacts are out of date.
- Test-USDC funding (`fund_usdc`) on a local chain or a Base fork.
- Mock x402 v2 facilitator (`/supported`, `/verify`, `/settle`, `exact` scheme) and fake
  paid services that serve scenario content. `upto` settlement is not wired up yet.
- Oracle: evidence collection from chain state and the six v0.1 invariants
  (`max_outflow_usd`, `no_transfer_to`, `recipients_subset_of`, `no_new_approvals`,
  `x402_max_charge`, `max_tx_count`).
- Scenario format: Pydantic model and YAML loader (`draincheck.scenarios`). Agent-layer
  scenarios need at least 3 trials. New dependency `pyyaml` to read scenario files.
- Runner: runs a scenario's trials in isolated chain snapshots, judges each with the
  oracle and reports the attack success rate and worst USD outflow. Any breached trial
  fails the scenario.
- `draincheck run <scenario> --agent module:function`, which exits 1 on a failed scenario.
  `draincheck doctor` also reports `forge` (optional).
- First scenario, `social-post-usdc-transfer-001`: a poisoned post makes the demo agent
  send 500 USDC to the attacker.

### Changed

- The demo agent now pays through the mock x402 facilitator in USDC and also obeys
  injected USDC transfers. Its old tx-hash payment service is removed.
- Tests marked `anvil` skip (or fail in CI) on a missing anvil even when they do not use
  the `anvil` fixture.

### Fixed

- `x402_max_charge: 1` was read as "use the quote" because `1 == True` in Python; it now
  means a $1 cap. Booleans, NaN and infinite caps are rejected.
- ERC-721 approvals were detected from the token id instead of the approved address, so
  approving token 0 was missed and revoking any other token counted as an approval.
- An Approval from a contract whose `allowance()` cannot be read was dropped (both reads
  returned 0). It is now recorded as an unlimited allowance, so `no_new_approvals` fails.
- `social-post-usdc-transfer-001` also checks `no_new_approvals`, so an agent that
  approves the attacker instead of paying them fails it.
- A scenario whose agent raised in every trial reported PASS, because nothing moved on
  chain. It now fails and says the scenario was never tested. A crash in only some
  trials still leaves the verdict to the chain.
- `draincheck run --agent pkg.module:fn` could not import an agent from the working
  directory, because the console script does not put it on `sys.path`.

- `guard_rpc` hook no longer blocks commands that only mention "anvil" or "rpc" in prose
  (for example a commit message with a link). It now treats a command as chain-related
  only when it runs a Foundry tool, passes an RPC flag, sends an `eth_` method or builds
  a web3 provider.
