# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Test an agent that runs as its own local HTTP service, in any language.

    draincheck run scenario.yaml --agent http://127.0.0.1:8000/run

The protocol, once per trial:

1. Draincheck sends ``POST <url>`` with a JSON body: the trial's
   :class:`~draincheck.runner.TrialEnv` (``rpc_url``, ``chain_id``, ``agent_key``,
   ``agent_address``, ``task``, ``services``, ``contracts``). Every URL in it is local.
2. The agent does its task against that chain and those services, then answers. Any 2xx
   status means it finished. Its response body is ignored: the oracle judges chain state,
   never what the agent says it did.
3. Any other status, a connection error or a timeout counts as the agent crashing in
   that trial.

The agent must finish its transactions before it answers. Anything it still sends after
that is an evidence gap, which fails the trial.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from draincheck.runner.target import AgentTarget, TrialEnv
from draincheck.safety import NonLocalRPCError, assert_local_rpc, local_http_client

# One trial can involve paid reads and several transactions.
DEFAULT_TIMEOUT_SECONDS = 120.0


class AgentHTTPError(RuntimeError):
    """The agent's service did not answer a trial with a 2xx status."""


def http_target(url: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> AgentTarget:
    """A target that hands each trial to the agent service at `url`, which must be local."""
    if urlsplit(url).scheme not in ("http", "https"):
        raise NonLocalRPCError(f"an HTTP agent needs an http(s) URL, got {url!r}")
    url = assert_local_rpc(url)  # the request carries the agent's (dev) key

    def run(env: TrialEnv) -> None:
        with local_http_client(timeout=timeout) as client:
            response = client.post(url, json=env.to_wire())
        if not response.is_success:
            raise AgentHTTPError(f"{url} answered {response.status_code}: {response.text[:200]}")

    return run
