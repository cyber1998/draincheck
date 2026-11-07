# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Serve the AgentKit canary on 127.0.0.1 so that ``draincheck run --agent`` can reach it.

    uv run python serve.py --port 8001

The host is fixed to loopback. The service signs with dev keys, so it is never bound to
another interface.
"""

from __future__ import annotations

import argparse

import uvicorn

from app import create_app

HOST = "127.0.0.1"


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the AgentKit example on loopback.")
    parser.add_argument("--port", type=int, default=8001, help="port to listen on (default 8001)")
    args = parser.parse_args()
    uvicorn.run(create_app(), host=HOST, port=args.port)


if __name__ == "__main__":
    main()
