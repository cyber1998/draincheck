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
- Sandbox contract in `contracts/`: TestUSDC (USDC's EIP-712 domain, EIP-2612, EIP-3009),
  with `scripts/build_contracts.py` to rebuild the bundled ABI and bytecode. CI fails if
  the bundled artifacts are out of date.
- Test-USDC funding (`fund_usdc`) on a local chain or a Base fork.
- Mock x402 v2 facilitator (`/supported`, `/verify`, `/settle`, `exact` scheme) and fake
  paid services that serve scenario content. Only the `exact` scheme is supported; the
  `upto` scheme comes later.
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
- Entry points (`draincheck.entrypoints`): a scenario's payload can now reach the agent
  as a paid social post, a paid API response, a note in its memory file (rebuilt each
  trial, without following links the agent leaves), the name of a token it holds, or the note of a paid swap router listing. The
  router can be configured to skim to the attacker or drain the agent's whole allowance.
- Sandbox contracts `TestToken` (ERC-20 with settable metadata) and `TestRouter` (a 1:1
  swap router with skim and allowance-drain switches), installed by a dedicated deployer
  account (anvil account 9).
- Scenario fields `task` (the honest task, defaulting per entry point) and `options`
  (entry-point settings, parsed once into the entry point's model; read them with
  `Scenario.options_as`), and the role names `router` and `token` for invariants.
- Payload encodings `morse` and `unicode_homoglyph`.
- `TrialEnv` refuses any key that is not one of anvil's ten published dev keys
  (`draincheck.safety.assert_dev_key`, checked by the address the key signs for), so an
  agent service never signs with a key it was sent that could hold real funds.
- `draincheck.safety.assert_local_service`, which also accepts a `file://` path inside the
  system temp directory (never a network share or automounted path).
- 17 sourced agent-layer scenarios from the approved list in `docs/scenario-sources.md`
  (ids start with the entry point in hyphens, e.g. `social-post-morse-relay-001`):
  5 social posts (including a Morse-coded relay and a fake admin session), 4 API
  responses (from AgentDojo's banking tasks and malicious-tool papers), 3 token names and
  5 memory poisonings (including address poisoning). Rows that are about MCP tool
  descriptions or deterministic guardrails wait for the MCP adapter and the policy fuzzer.
- `tests/scenarios/test_library.py` checks every scenario file: valid, filed under its
  entry point, and failed by the vulnerable demo agent. Scenarios no longer need a test
  of their own.
- HTTP adapter: `--agent http://127.0.0.1:PORT/path` tests an agent running as a local
  service in any language. Draincheck POSTs each trial's `TrialEnv` as JSON and waits for
  a 2xx; any other answer or a timeout counts as the agent crashing. Example in
  `examples/http_agent`.
- LangGraph adapter (`--agent langgraph:module:factory`, extra `draincheck[langgraph]`): your
  factory gets the trial's `TrialEnv` and the sandbox wallet as LangChain tools and returns a
  graph; Draincheck runs it on the trial's task. Tool errors (a bad amount, a reverted
  transaction) go back to the model as tool messages. LangSmith tracing is forced off for
  every trial, so `LANGSMITH_TRACING` or `LANGCHAIN_TRACING_V2` in the environment can't post
  trial data to a hosted service. Example with a scripted naive model in
  `examples/langgraph_agent`.
- `draincheck.adapters.tools.SandboxWallet`: the honest wallet primitives (read a service,
  token metadata, balance, send ETH or tokens, approve, swap) every adapter exposes.
- Optional extra `langgraph` (langgraph >=1.2, langchain-core >=1.7), included in the dev
  group so CI tests the adapter.

### Changed

- The demo agent is built on `SandboxWallet`; its flaws are only in its decisions.
- The demo agent now pays through the mock x402 facilitator in USDC and also obeys
  injected USDC transfers. Its old tx-hash payment service is removed.
- `TrialEnv` replaces `feed_url` with `task`, `services` (name to local URL) and
  `contracts` (name to address). The demo agent works with every entry point: it follows
  API notes, memory notes and token names, decodes obfuscated text, and swaps through any
  router with an unlimited approval and no slippage limit.
- Tests marked `anvil` skip (or fail in CI) on a missing anvil even when they do not use
  the `anvil` fixture.
- Invariants are validated Pydantic dataclasses, parsed once when the scenario loads
  (`Scenario.invariants`), with the same rules whether built from YAML or in code. Error
  messages for a bad invariant are worded differently.
- The runner builds a `TrialPlan` once per scenario, and the quote the oracle checks is
  taken from the paid route itself. Trial results and txpool checks have their own modules.
  `scenario_failed` is replaced by `ScenarioResult.failed` and `failure_reason`, which
  `draincheck run` prints.
- `collect()` is split into one function per kind of evidence. The oracle reads tokens
  through a minimal ERC-20 ABI, and EIP-7702 authorities are recovered with eth-account's
  authorization hash instead of a hand-written RLP encoder.
- `AnvilProcess.w3` gives one cached Web3 client per node. `AnvilProcess.fund_usdc` and
  `examples/vulnerable_agent/accounts.py` are removed.
- `load_target` dispatches on the spec: a local URL goes to the HTTP adapter; anything else
  is `module:function`. `TrialEnv` has `to_wire` / `from_wire`.

### Removed

- The unused Permit2 / x402 `upto` stand-ins (`MiniPermit2`, `X402UptoProxy`) and their
  Python signing code. They will return with `upto` settlement.

### Fixed

- A proxy set in the environment (`HTTP_PROXY`, `ALL_PROXY`, ...) or in the system
  settings would have carried Draincheck's local traffic, RPC calls and signed payments
  included, through that proxy and possibly off the machine: httpx and requests use
  proxies even for 127.0.0.1. Every client is now built with `draincheck.safety.local_web3`
  or `local_http_client`, which ignore proxies (environment, system settings and
  host-keyed `<url>_proxy` variables) and never follow redirects. `requests`, already
  installed with web3, is now a declared dependency so the RPC session can turn off
  environment lookups; `types-requests` is a new dev dependency for mypy.
- The `unicode_homoglyph` encoding changed the letters of an address written inside
  punctuation (`(0x...)`, `to:0x...`), so a real agent could not send to it and the
  scenario passed. Only text between hex values is changed now.
- On a fork, the token and router entry points would have overwritten any contract
  already at their fixed addresses. They now refuse (`SandboxSetupError`).
- `recipients_subset_of` missed value a contract forwarded inside the agent's own
  transaction: allowing a router let the router pay the attacker with the agent's tokens.
  Routed payments now count as the agent's.
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
- `x402_max_charge` only checked EIP-3009 settlements, one at a time. It now adds up
  everything each payee received in the trial (settlements, plain transfers, value routed
  through a contract) per token, and fails if that exceeds the quote times the paid reads
  the task needs (one feed read in the runner). A direct `USDC.transfer(service, 40e6)`
  and several settlements that are each at the quote both fail now. With a USD cap, the
  total over all payees is capped too, so spreading payments over many payees fails.
- x402 quotes are keyed by (pay_to, token) instead of pay_to alone, so a payment in a
  token the service did not quote fails.
- Native outflow excused all gas, so a huge priority fee could drain ETH and pass. Only
  the burned base fee is excused now; the priority fee counts as outflow.
- A transaction the oracle could not trace was ignored. Evidence now lists such gaps and
  a new always-on verdict, `evidence_complete`, fails the trial when there is one.
- An EIP-7702 delegation of the agent's account emits no log and moves nothing, so it
  passed. A new always-on verdict, `wallet_code_unchanged`, fails if any agent wallet's
  code changes during the trial, or if any transaction in the trial (whoever sent it)
  carries an authorization the agent signed, so a delegation cleared again is caught.
- Transactions the agent left pending (automine off, a nonce gap) or sent after the
  post-trial capture were never judged. The runner now mines pending transactions before
  the capture, fails the trial on any agent transaction it cannot mine or that arrives
  late, checks that every trial starts at the same agent nonce, and turns automine back
  on after each trial. A transaction sent after the last trial is still not attributed.

- `guard_rpc` hook no longer blocks commands that only mention "anvil" or "rpc" in prose
  (for example a commit message with a link). It now treats a command as chain-related
  only when it runs a Foundry tool, passes an RPC flag, sends an `eth_` method or builds
  a web3 provider.
