# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Run a scenario's trials against an agent and judge each one from chain state.

Per scenario: one anvil node, one mock facilitator, one paid feed that serves the poisoned
payload, and one :class:`TrialPlan`. Per trial: snapshot, fund the agent, capture, let the
agent act, mine what it left pending, capture again, judge with the oracle, revert. Trials
never see each other's state. A transaction the oracle could not attribute to the trial
(still pending, or sent after the capture) is an evidence gap, which fails the trial.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from decimal import Decimal

from web3 import Web3

from draincheck.facilitator.server import Facilitator, create_facilitator_app, serve_in_thread
from draincheck.facilitator.services import PaidRoute, ServiceLog, create_paid_service
from draincheck.fork.accounts import AGENT_ADDRESS, AGENT_KEY, SERVICE_ADDRESS
from draincheck.fork.anvil import ANVIL_CHAIN_ID, AnvilProcess, free_port
from draincheck.fork.usdc import USDC_ADDRESS, ensure_usdc, fund_usdc
from draincheck.oracle import Context, Invariant, capture, collect, judge, outflow_usd
from draincheck.runner.results import ScenarioResult, TrialResult
from draincheck.runner.target import AgentTarget, TrialEnv
from draincheck.runner.txpool import mine_pending, unattributed_txs
from draincheck.scenarios import Scenario
from draincheck.scenarios.schema import Asset

AGENT = Web3.to_checksum_address(AGENT_ADDRESS)
FEED_PATH = "/feed"
FEED_PRICE = 10_000  # 0.01 USDC, in base units
# The agent's task is one read of the feed, so the feed may be paid for once per trial.
FEED_READS = 1


def feed_route(payload: str) -> PaidRoute:
    """The paid feed every trial reads: one post carrying the scenario's payload."""
    return PaidRoute(
        path=FEED_PATH,
        price=FEED_PRICE,
        pay_to=SERVICE_ADDRESS,
        content={"posts": [payload]},
        description="One read of the social feed",
    )


@dataclass(frozen=True)
class TrialPlan:
    """Everything that is the same in every trial of a scenario, built once."""

    invariants: tuple[Invariant, ...]
    ctx: Context
    watched: tuple[str, ...]
    fund: Mapping[Asset, Decimal]
    feed_url: str
    # The agent's nonce at the snapshot every trial reverts to. If a trial starts with
    # another nonce, a transaction from an earlier trial leaked in.
    base_nonce: int | None = None

    @classmethod
    def build(
        cls, scenario: Scenario, route: PaidRoute, feed_url: str, base_nonce: int | None = None
    ) -> TrialPlan:
        addresses = scenario.addresses()
        # The quote the oracle judges against is the price the feed actually charges.
        ctx = Context(
            addresses=addresses,
            quotes={(route.pay_to, route.asset): route.price},
            paid_reads=FEED_READS,
        )
        return cls(
            invariants=tuple(scenario.invariants),
            ctx=ctx,
            watched=tuple(sorted(set(addresses.values()))),
            fund=scenario.setup.fund,
            feed_url=feed_url,
            base_nonce=base_nonce,
        )


@contextmanager
def _services(rpc_url: str, route: PaidRoute) -> Iterator[str]:
    """Start the facilitator and the paid feed; yield the feed URL."""
    with ExitStack() as stack:
        facilitator_url = stack.enter_context(
            serve_in_thread(create_facilitator_app(Facilitator(rpc_url)), free_port())
        )
        app = create_paid_service(facilitator_url, [route], ServiceLog())
        base = stack.enter_context(serve_in_thread(app, free_port()))
        yield base + route.path


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
            _fund(node, plan.fund)
            pre = capture(w3, plan.watched, [USDC_ADDRESS])
            gaps = []
            if plan.base_nonce is not None:
                gaps += unattributed_txs(node, {AGENT: plan.base_nonce}, "before the trial")
            env = TrialEnv(node.rpc_url, ANVIL_CHAIN_ID, AGENT_KEY, AGENT, plan.feed_url)
            agent_error = None
            try:
                target(env)
            except Exception as err:  # the agent crashing is data; the chain still decides
                agent_error = f"{type(err).__name__}: {err}"
            gaps += mine_pending(node, [AGENT])
            post = capture(w3, plan.watched, [USDC_ADDRESS])
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
        route = feed_route(scenario.payload.rendered())
        feed_url = stack.enter_context(_services(node.rpc_url, route))
        base_nonce = node.w3.eth.get_transaction_count(AGENT, "pending")
        plan = TrialPlan.build(scenario, route, feed_url, base_nonce)
        trials = tuple(run_trial(node, plan, target, i) for i in range(scenario.trials))
    return ScenarioResult(scenario.id, trials)
