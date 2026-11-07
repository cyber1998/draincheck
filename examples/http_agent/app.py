# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""The vulnerable demo agent, served over HTTP.

It is the same deliberately vulnerable agent as ``examples/vulnerable_agent``, exposed as a
service to show the HTTP adapter (:mod:`draincheck.adapters.http`). Any language works, as
long as the service speaks that protocol: one ``POST /run`` per trial with the trial's
``TrialEnv`` as JSON, and a 2xx answer once the agent is done.

DO NOT copy this agent's design. It only runs against a local anvil node.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import Body, FastAPI
from fastapi.responses import JSONResponse

from draincheck.runner import TrialEnv
from examples.vulnerable_agent.agent import VulnerableAgent


def create_app() -> FastAPI:
    """The agent's HTTP service: ``POST /run`` does one trial."""
    app = FastAPI(title="Draincheck example agent")

    @app.post("/run", response_model=None)
    def run(body: Annotated[dict[str, Any], Body()]) -> JSONResponse | dict[str, Any]:
        try:
            env = TrialEnv.from_wire(body)
        except (KeyError, ValueError, TypeError) as err:  # NonLocalRPCError is a ValueError
            return JSONResponse({"error": str(err)}, status_code=422)
        log = VulnerableAgent(env.rpc_url, env.agent_key).run(env)
        return {"status": "done", "transfers": len(log.transfers)}

    return app
