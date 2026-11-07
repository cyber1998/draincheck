# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Run a Coinbase AgentKit agent against the sandbox, safely.

AgentKit's releases pin web3 < 8 and LangChain 0.3, so an AgentKit agent runs in its own
environment and Draincheck tests it through the HTTP adapter (see
``examples/agentkit_agent``). Inside that service, build AgentKit with
:func:`agentkit_sandbox` instead of by hand:

    with agentkit_sandbox(env) as agentkit:
        ...  # give agentkit.get_actions() to your model

It enforces what the sandbox needs and AgentKit does not do by itself:

- AgentKit only knows real networks. Anvil is registered as its own network with chain id
  31337, so nothing the agent signs is valid on Base or any live chain.
- The wallet is AgentKit's local private-key provider with an anvil dev key, never a hosted
  (CDP) wallet. AgentKit falls back to a hosted wallet when none is given, and to the
  ``RPC_URL`` variable or a public RPC when no URL is; neither can happen here.
- The provider's RPC client is replaced with Draincheck's, which ignores proxies.
- Only action providers that make no outside calls are allowed (wallet, ERC-20, WETH),
  checked by their exact class. Providers that call hosted APIs, fetch URLs the model
  chooses, or resolve unchecked names (ERC-721) are refused.
- CDP credentials, ``RPC_URL`` and ``WEB3_PROVIDER_URI`` are hidden while it is open.
- AgentKit's analytics (a POST to a Coinbase endpoint on every wallet setup and action,
  with the wallet address, chain id and action names) are switched off, for the rest of
  the process. AgentKit has no setting for this, so the sender's code is replaced.
"""

from __future__ import annotations

import importlib
import os
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from typing import Any

from eth_account import Account

from draincheck.fork.anvil import ANVIL_CHAIN_ID
from draincheck.runner.target import TrialEnv
from draincheck.safety import assert_dev_key, assert_local_rpc, local_web3

ANVIL_NETWORK_ID = "draincheck-anvil"
# Action providers that only use the wallet and the local chain.
# ERC-721 is left out: its actions pass unchecked names to a Web3 with no provider,
# which would resolve ENS through WEB3_PROVIDER_URI or a default node.
LOCAL_ACTION_PROVIDERS = frozenset({"wallet", "erc20", "weth"})
# Read by AgentKit (and web3) to reach hosted wallets or a default RPC.
HIDDEN_ENV = (
    "CDP_API_KEY_ID",
    "CDP_API_KEY_SECRET",
    "CDP_WALLET_SECRET",
    "CDP_API_KEY_NAME",
    "CDP_API_KEY_PRIVATE_KEY",
    "RPC_URL",
    "NETWORK_ID",
    "WEB3_PROVIDER_URI",
)


class UnsafeAgentKitError(RuntimeError):
    """Raised when an AgentKit setup could reach something outside the sandbox."""


# AgentKit's analytics sender, imported by name into the modules that call it.
SENDER = "send_analytics_event"


def _no_analytics(event: Any) -> None:
    """Stands in for AgentKit's analytics sender: nothing leaves the machine."""


def _switch_off_analytics() -> None:
    """Make AgentKit's analytics sender do nothing, for the rest of this process.

    The function's code is replaced, so every reference to it (whatever it was imported
    as) is silenced, and overlapping trials can't turn it back on. A process that runs an
    agent under test is sandbox-only, so nothing needs the real sender back.
    """
    # The package re-exports the function under the submodule's name; load the module.
    module = importlib.import_module("coinbase_agentkit.analytics.send_analytics_event")

    sender = vars(module)[SENDER]
    if sender.__code__ is not _no_analytics.__code__:
        sender.__code__ = _no_analytics.__code__


@contextmanager
def _hidden_env(names: Sequence[str]) -> Iterator[None]:
    saved = {name: os.environ.pop(name) for name in names if name in os.environ}
    try:
        yield
    finally:
        os.environ.update(saved)


def _register_anvil(rpc_url: str) -> None:
    """Teach AgentKit the anvil chain, with only the local RPC and no real contracts."""
    from coinbase_agentkit.network import (  # type: ignore[import-not-found]
        CHAIN_ID_TO_NETWORK_ID,
        NETWORK_ID_TO_CHAIN,
    )

    template = NETWORK_ID_TO_CHAIN["base-sepolia"]
    default_rpc = template.rpc_urls["default"].model_copy(update={"http": [rpc_url]})
    NETWORK_ID_TO_CHAIN[ANVIL_NETWORK_ID] = template.model_copy(
        update={
            "id": str(ANVIL_CHAIN_ID),
            "name": "Draincheck anvil",
            "network": ANVIL_NETWORK_ID,
            "rpc_urls": {"default": default_rpc},
            "block_explorers": {},
            "contracts": {},
            "testnet": True,
        }
    )
    CHAIN_ID_TO_NETWORK_ID[str(ANVIL_CHAIN_ID)] = ANVIL_NETWORK_ID


@contextmanager
def agentkit_sandbox(env: TrialEnv, action_providers: Sequence[Any] | None = None) -> Iterator[Any]:
    """An AgentKit bound to this trial's local chain and dev key. See the module docs.

    `action_providers` defaults to the wallet and ERC-20 providers; any provider outside
    ``LOCAL_ACTION_PROVIDERS`` raises :class:`UnsafeAgentKitError`.
    """
    try:
        from coinbase_agentkit import (  # type: ignore[import-not-found]
            AgentKit,
            AgentKitConfig,
            EthAccountWalletProvider,
            EthAccountWalletProviderConfig,
            erc20_action_provider,
            wallet_action_provider,
        )
        from coinbase_agentkit.action_providers.erc20.erc20_action_provider import (  # type: ignore[import-not-found]
            ERC20ActionProvider,
        )
        from coinbase_agentkit.action_providers.wallet.wallet_action_provider import (  # type: ignore[import-not-found]
            WalletActionProvider,
        )
        from coinbase_agentkit.action_providers.weth.weth_action_provider import (  # type: ignore[import-not-found]
            WethActionProvider,
        )
        from web3.middleware import SignAndSendRawMiddlewareBuilder
    except ImportError as err:  # pragma: no cover - only outside an AgentKit environment
        raise ImportError("agentkit_sandbox needs coinbase-agentkit installed") from err

    providers = (
        list(action_providers)
        if action_providers is not None
        else [wallet_action_provider(), erc20_action_provider()]
    )
    allowed = {
        WalletActionProvider: "wallet",
        ERC20ActionProvider: "erc20",
        WethActionProvider: "weth",
    }
    for provider in providers:
        # The exact class, not the name: any provider can call itself "wallet".
        if type(provider) not in allowed or getattr(provider, "action_providers", None):
            raise UnsafeAgentKitError(
                f"action provider {type(provider).__name__} can reach outside the sandbox; "
                f"allowed: {', '.join(sorted(allowed.values()))}"
            )

    _switch_off_analytics()
    with _hidden_env(HIDDEN_ENV):
        rpc_url = assert_local_rpc(env.rpc_url)
        account = Account.from_key(assert_dev_key(env.agent_key, env.agent_address))
        _register_anvil(rpc_url)
        wallet = EthAccountWalletProvider(
            EthAccountWalletProviderConfig(
                account=account, chain_id=str(ANVIL_CHAIN_ID), rpc_url=rpc_url
            )
        )
        # AgentKit builds a client that honours proxy settings; use Draincheck's instead.
        w3 = local_web3(rpc_url)
        w3.middleware_onion.inject(SignAndSendRawMiddlewareBuilder.build(account), layer=0)
        wallet.web3 = w3
        if int(wallet.web3.eth.chain_id) != ANVIL_CHAIN_ID:
            raise UnsafeAgentKitError("the AgentKit wallet is not on the local anvil chain")
        yield AgentKit(AgentKitConfig(wallet_provider=wallet, action_providers=providers))
