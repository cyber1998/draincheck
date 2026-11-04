# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
from __future__ import annotations

import pytest
from web3 import Web3

from draincheck.fork import ANVIL_CHAIN_ID, AnvilProcess


@pytest.mark.anvil
def test_anvil_starts_on_loopback_with_dev_chain_id(anvil: AnvilProcess) -> None:
    assert anvil.rpc_url.startswith("http://127.0.0.1:")
    assert Web3(Web3.HTTPProvider(anvil.rpc_url)).eth.chain_id == ANVIL_CHAIN_ID
