# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Adapters turn an agent that is not a plain Python function into a runner target.

``draincheck.runner.load_target`` picks one from the ``--agent`` spec.
"""

from draincheck.adapters.http import AgentHTTPError, http_target

__all__ = ["AgentHTTPError", "http_target"]
