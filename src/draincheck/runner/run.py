# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Run a scenario's trials against an agent and judge each one from chain state.

Per scenario: one anvil node, the scenario's entry point (which puts the payload where the
agent will find it, see :mod:`draincheck.entrypoints`) and one :class:`TrialPlan`. Per
trial: snapshot, fund the agent, capture, let the agent act, mine what it left pending,
capture again, judge with the oracle, revert. Trials never see each other's state. A
transaction the oracle could not attribute to the trial (still pending, or sent after the
capture) is an evidence gap, which fails the trial.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import ExitStack
from dataclasses import dataclass
from decimal import Decimal

from web3 import Web3

from draincheck.entrypoints import ENTRY_POINTS, SPECS, TrialInputs
from draincheck.fork.accounts import AGENT_ADDRESS, AGENT_KEY
from draincheck.fork.anvil import ANVIL_CHAIN_ID, AnvilProcess
from draincheck.fork.usdc import USDC_ADDRESS, ensure_usdc, fund_usdc
from draincheck.oracle import Context, Invariant, capture, collect, judge, outflow_usd
from draincheck.runner.results import ScenarioResult, TrialResult
from draincheck.runner.target import AgentTarget, TrialEnv
from draincheck.runner.txpool import mine_pending, unattributed_txs
from draincheck.scenarios import Scenario
from draincheck.scenarios.schema import ROLE_NAMES, Asset

AGENT = Web3.to_checksum_address(AGENT_ADDRESS)


@dataclass(frozen=True)
class TrialPlan:
    """Everything that is the same in every trial of a scenario, built once."""

    invariants: tuple[Invariant, ...]
    ctx: Context
    watched: tuple[str, ...]
    tokens: tuple[str, ...]
    fund: Mapping[Asset, Decimal]
    task: str
    services: Mapping[str, str]
    contracts: Mapping[str, str]
    reset: Callable[[], None] | None = None
    # The agent's nonce at the snapshot every trial reverts to. If a trial starts with
    # another nonce, a transaction from an earlier trial leaked in.
    base_nonce: int | None = None

    @classmethod
    def build(
        cls, scenario: Scenario, inputs: TrialInputs, base_nonce: int | None = None
    ) -> TrialPlan:
        expected = set(SPECS[scenario.entry_point].roles)
        if set(inputs.roles) != expected or set(inputs.roles) & set(ROLE_NAMES):
            # A role the schema did not check, or one that would replace "attacker".
            raise ValueError(
                f"{scenario.entry_point} returned roles {sorted(inputs.roles)}, "
                f"expected {sorted(expected)}"
            )
        addresses = {**scenario.addresses(), **inputs.roles}
        # The quotes the oracle judges against are the prices the entry point charges.
        ctx = Context(addresses=addresses, quotes=inputs.quotes, paid_reads=inputs.paid_reads)
        return cls(
            invariants=tuple(scenario.invariants),
            ctx=ctx,
            watched=tuple(sorted(set(addresses.values()))),
            tokens=(USDC_ADDRESS, *inputs.tokens),
            fund=scenario.setup.fund,
            task=scenario.honest_task,
            services=inputs.services,
            contracts=inputs.contracts,
            reset=inputs.reset,
            base_nonce=base_nonce,
        )

    def env(self, node: AnvilProcess) -> TrialEnv:
        """What the agent is handed for one trial."""
        return TrialEnv(
            node.rpc_url,
            ANVIL_CHAIN_ID,
            AGENT_KEY,
            AGENT,
            task=self.task,
            services=self.services,
            contracts=self.contracts,
        )


def _fund(node: AnvilProcess, fund: Mapping[Asset, Decimal]) -> None:
    for asset, amount in fund.items():
        if asset == "USDC":
            fund_usdc(node, AGENT, amount)
        else:
            node.rpc("anvil_setBalance", [AGENT, hex(Web3.to_wei(amount, "ether"))])


def run_trial(node: AnvilProcess, plan: TrialPlan, target: AgentTarget, index: int) -> TrialResult:
    """One isolated trial. Chain state is reverted afterwards, whatever happens."""
    w3 = node.w3
    try:
        with node.isolated():
            # An earlier trial (or caller) may have switched automine off.
            node.rpc("evm_setAutomine", [True])
            if plan.reset is not None:
                plan.reset()
            _fund(node, plan.fund)
            pre = capture(w3, plan.watched, plan.tokens)
            gaps = []
            if plan.base_nonce is not None:
                gaps += unattributed_txs(node, {AGENT: plan.base_nonce}, "before the trial")
            env = plan.env(node)
            agent_error = None
            try:
                target(env)
            except Exception as err:  # the agent crashing is data; the chain still decides
                agent_error = f"{type(err).__name__}: {err}"
            gaps += mine_pending(node, [AGENT])
            post = capture(w3, plan.watched, plan.tokens)
            evidence = collect(w3, [AGENT], pre, post)
            # Anything sent while the oracle was reading the chain is outside the window.
            gaps += unattributed_txs(node, {AGENT: post.nonces[AGENT]}, "after the capture")
            evidence.gaps.extend(gaps)
            verdicts = judge(list(plan.invariants), evidence, plan.ctx)
            total, _ = outflow_usd(evidence, plan.ctx.pricing)
    finally:
        # evm_revert keeps the mining mode, so leave automine on for whoever is next.
        node.rpc("evm_setAutomine", [True])
    return TrialResult(index, tuple(verdicts), total, agent_error)


def run_scenario(
    scenario: Scenario,
    target: AgentTarget,
    node: AnvilProcess | None = None,
    *,
    fork: bool = False,
) -> ScenarioResult:
    """Run every trial of `scenario` against `target`.

    Starts an empty local anvil node unless `node` is given. With ``fork=True`` it forks
    Base through ``DRAINCHECK_FORK_URL`` (and falls back to an empty chain if it is unset).
    """
    with ExitStack() as stack:
        if node is None:
            node = stack.enter_context(AnvilProcess(fork=fork))
        ensure_usdc(node)
        inputs = ENTRY_POINTS[scenario.entry_point](node, scenario, stack)
        base_nonce = node.w3.eth.get_transaction_count(AGENT, "pending")
        plan = TrialPlan.build(scenario, inputs, base_nonce)
        trials = tuple(run_trial(node, plan, target, i) for i in range(scenario.trials))
    return ScenarioResult(scenario.id, trials)
