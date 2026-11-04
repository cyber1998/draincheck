# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Command-line interface."""

from __future__ import annotations

import platform
import sys

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
    if not ok:
        raise typer.Exit(code=1)


if __name__ == "__main__":  # pragma: no cover
    app()
