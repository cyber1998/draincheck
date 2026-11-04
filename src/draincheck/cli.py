# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Command-line interface."""

from __future__ import annotations

import platform
import shutil
import sys
from pathlib import Path
from typing import Annotated

import typer

from draincheck import __version__
from draincheck.fork import find_anvil

app = typer.Typer(
    help="Attack your own wallet-holding AI agent on a local chain and judge the chain state.",
    no_args_is_help=True,
)


@app.command()
def version() -> None:
    """Print the Draincheck version."""
    typer.echo(__version__)


@app.command()
def doctor() -> None:
    """Check that the local toolchain Draincheck needs is installed."""
    ok = True
    py_ok = sys.version_info >= (3, 12)
    ok &= py_ok
    typer.echo(f"{'ok ' if py_ok else 'BAD'}  python {platform.python_version()} (need >= 3.12)")
    anvil = find_anvil()
    ok &= anvil is not None
    typer.echo(f"{'ok ' if anvil else 'BAD'}  anvil {anvil or 'not found on PATH'}")
    forge = shutil.which("forge")
    # Only needed to rebuild the bundled contracts after editing contracts/src.
    typer.echo(f"{'ok ' if forge else '-- '}  forge {forge or 'not found (optional)'}")
    if not ok:
        raise typer.Exit(code=1)


@app.command()
def run(
    scenario: Annotated[
        Path, typer.Argument(exists=True, dir_okay=False, help="Scenario YAML file.")
    ],
    agent: Annotated[
        str,
        typer.Option(help="Your agent, as 'package.module:function'. Runs as trusted code."),
    ],
    fork: Annotated[
        bool, typer.Option(help="Fork Base through DRAINCHECK_FORK_URL instead of an empty chain.")
    ] = False,
) -> None:
    """Run a scenario's trials against your agent. Exits 1 if the scenario fails."""
    from draincheck.runner import load_target, run_scenario
    from draincheck.scenarios import load_scenario

    spec = load_scenario(scenario)
    result = run_scenario(spec, load_target(agent), fork=fork)
    total = len(result.trials)
    for trial in result.trials:
        for verdict in trial.verdicts:
            if not verdict.passed:
                typer.echo(f"  trial {trial.index + 1}: {verdict.invariant}: {verdict.detail}")
        if trial.agent_error:
            typer.echo(f"  trial {trial.index + 1}: agent raised {trial.agent_error}")
    status = "FAIL" if result.failed else "PASS"
    typer.echo(
        f"{status} {spec.id}: {result.breached_count}/{total} trials breached "
        f"({result.attack_success_rate:.0%}); max outflow ${result.max_outflow_usd:.2f}"
    )
    if result.failed:
        raise typer.Exit(code=1)


if __name__ == "__main__":  # pragma: no cover
    app()
