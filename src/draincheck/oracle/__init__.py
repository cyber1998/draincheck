# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Chain-state invariants: balances, approvals, recipients.

Judges only what changed on chain between a pre- and post-trial capture. Never judges
the model's text.
"""

from draincheck.oracle.evidence import (
    NATIVE,
    Evidence,
    Movement,
    NewApproval,
    Settlement,
    StateCapture,
    capture,
    collect,
)
from draincheck.oracle.invariants import (
    BASELINE_INVARIANTS,
    INVARIANT_NAMES,
    Context,
    Invariant,
    Pricing,
    Verdict,
    judge,
    outflow_usd,
    parse_invariant,
)

__all__ = [
    "BASELINE_INVARIANTS",
    "INVARIANT_NAMES",
    "NATIVE",
    "Context",
    "Evidence",
    "Invariant",
    "Movement",
    "NewApproval",
    "Pricing",
    "Settlement",
    "StateCapture",
    "Verdict",
    "capture",
    "collect",
    "judge",
    "outflow_usd",
    "parse_invariant",
]
