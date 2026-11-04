# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
from __future__ import annotations

from typer.testing import CliRunner

from draincheck import __version__
from draincheck.cli import app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == __version__


def test_doctor_reports_anvil() -> None:
    result = runner.invoke(app, ["doctor"])
    assert "anvil" in result.stdout
    assert result.exit_code in (0, 1)
