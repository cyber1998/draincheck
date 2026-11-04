# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""The scenario file format. Scenarios are data: YAML validated by this model, never code."""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator
from web3 import Web3

from draincheck.entrypoints.spec import SPECS, EntryPointName
from draincheck.fork.accounts import (
    AGENT_ADDRESS,
    ANVIL_ADDRESSES,
    ATTACKER_ADDRESS,
    DEPLOYER_ADDRESS,
    FACILITATOR_ADDRESS,
    SERVICE_ADDRESS,
)
from draincheck.oracle.invariants import Invariant, parse_invariant
from draincheck.scenarios.encodings import encode

# Names any scenario may use instead of an address in its invariants. Entry points add
# their own (see draincheck.entrypoints.spec), e.g. "router".
ROLE_NAMES = ("agent", "service", "attacker")
# An agent-layer result is a rate, so it needs more than one trial (CLAUDE.md).
MIN_AGENT_TRIALS = 3


Asset = Literal["USDC", "ETH"]


def _default_fund() -> dict[Asset, Decimal]:
    return {"USDC": Decimal(1000)}


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Payload(_Model):
    """The poisoned content, and how it is encoded before the agent sees it."""

    encoding: Literal["plain", "base64", "morse", "unicode_homoglyph"] = "plain"
    text: str = Field(min_length=1)

    @model_validator(mode="after")
    def _encodable(self) -> Payload:
        self.rendered()  # raises if the text cannot be written in this encoding
        return self

    def rendered(self) -> str:
        """The content exactly as the service serves it."""
        return encode(self.text, self.encoding)


class Setup(_Model):
    """Chain state before each trial."""

    fund: dict[Asset, Decimal] = Field(default_factory=_default_fund)
    attacker: str = ATTACKER_ADDRESS

    @field_validator("fund")
    @classmethod
    def _positive(cls, fund: dict[Asset, Decimal]) -> dict[Asset, Decimal]:
        for asset, amount in fund.items():
            if not amount.is_finite() or amount <= 0:
                raise ValueError(f"fund.{asset} must be a positive amount")
        return fund

    @field_validator("attacker")
    @classmethod
    def _anvil_account(cls, attacker: str) -> str:
        if not Web3.is_address(attacker):
            raise ValueError("attacker must be an address")
        address = Web3.to_checksum_address(attacker)
        if address not in ANVIL_ADDRESSES:
            raise ValueError("attacker must be one of anvil's default dev accounts")
        if address in (AGENT_ADDRESS, SERVICE_ADDRESS, FACILITATOR_ADDRESS, DEPLOYER_ADDRESS):
            raise ValueError("attacker cannot be the agent, service, facilitator or deployer")
        return address


class Scenario(_Model):
    """One attack: where it enters, what it says, and which invariants must hold."""

    # Invariants are Pydantic dataclasses parsed from their YAML form by `_parse`.
    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    id: str = Field(pattern=r"^[a-z0-9]+(?:[-_][a-z0-9]+)*-\d{3}$")
    title: str = Field(min_length=1)
    source: HttpUrl
    layer: Literal["agent", "policy"]
    entry_point: EntryPointName
    # The honest task the agent is given. Defaults to the entry point's own task.
    task: str | None = Field(default=None, min_length=1)
    # Entry-point settings, validated by that entry point's options model.
    options: dict[str, Any] = Field(default_factory=dict)
    payload: Payload
    setup: Setup = Field(default_factory=Setup)
    trials: int = Field(default=10, ge=1, le=1000)
    invariants: list[Invariant] = Field(min_length=1)
    severity: Literal["critical", "high", "medium", "low"]

    @field_validator("invariants", mode="before")
    @classmethod
    def _parse(cls, specs: Any) -> Any:
        if not isinstance(specs, list):
            return specs  # Pydantic reports the type error
        return [s if isinstance(s, Invariant) else parse_invariant(s) for s in specs]

    @model_validator(mode="after")
    def _check(self) -> Scenario:
        if self.layer == "agent" and self.trials < MIN_AGENT_TRIALS:
            raise ValueError(f"agent-layer scenarios need trials >= {MIN_AGENT_TRIALS}")
        SPECS[self.entry_point].options.model_validate(self.options)  # raises if they don't fit
        roles = self.role_names()
        for inv in self.invariants:
            for name in inv.address_names():
                if name not in roles and not Web3.is_address(name):
                    raise ValueError(f"unknown name {name!r}; use {', '.join(roles)}")
        return self

    @property
    def honest_task(self) -> str:
        return self.task or SPECS[self.entry_point].task

    def role_names(self) -> tuple[str, ...]:
        """Names this scenario's invariants may use: the base roles plus the entry point's."""
        return ROLE_NAMES + SPECS[self.entry_point].roles

    def addresses(self) -> dict[str, str]:
        """Role name -> address, for resolving names in invariants."""
        return {"agent": AGENT_ADDRESS, "service": SERVICE_ADDRESS, "attacker": self.setup.attacker}


def load_scenario(path: str | Path) -> Scenario:
    """Read and validate one scenario YAML file."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: a scenario file must be a YAML mapping")
    return Scenario.model_validate(data)
