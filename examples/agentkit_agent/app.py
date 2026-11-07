# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""The AgentKit canary as a local HTTP service, for the HTTP adapter.

``POST /run`` takes a :class:`~draincheck.runner.TrialEnv` as JSON and does one trial. See
:mod:`draincheck.adapters.http` for the protocol.

DO NOT copy this agent's design. It only runs against a local anvil node.
"""

from __future__ import annotations

from typing import Annotated, Any

from draincheck.runner.target import TrialEnv
from fastapi import Body, FastAPI
from fastapi.responses import JSONResponse

from agent import run_trial


def create_app() -> FastAPI:
    """The agent's HTTP service: ``POST /run`` does one trial."""
    app = FastAPI(title="Draincheck AgentKit example")

    @app.post("/run", response_model=None)
    def run(body: Annotated[dict[str, Any], Body()]) -> JSONResponse | dict[str, Any]:
        try:
            env = TrialEnv.from_wire(body)
        except (KeyError, ValueError, TypeError) as err:  # NonLocalRPCError is a ValueError
            return JSONResponse({"error": str(err)}, status_code=422)
        return {"status": "done", "transfers": run_trial(env)}

    return app
