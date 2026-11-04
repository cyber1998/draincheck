# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Draincheck: attack your own wallet-holding AI agent on a local chain, then judge the result."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("draincheck")
except PackageNotFoundError:  # pragma: no cover - running from a source tree without install
    __version__ = "0.0.0"

__all__ = ["__version__"]
