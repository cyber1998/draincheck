# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Compile contracts/ with forge and write the ABI and bytecode JSON the package ships.

    uv run python scripts/build_contracts.py          # rewrite the artifact
    uv run python scripts/build_contracts.py --check  # fail if it is out of date

Only maintainers who edit the Solidity need forge. The package itself loads the
committed JSON and never compiles anything.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTRACTS = ROOT / "contracts"
PACKAGE = ROOT / "src" / "draincheck" / "contracts"
NAMES = ("TestUSDC",)


def build() -> dict[str, str]:
    forge = shutil.which("forge")
    if forge is None:
        sys.exit("forge is not on PATH")
    subprocess.run([forge, "build", "--root", str(CONTRACTS)], check=True)  # noqa: S603
    texts = {}
    for name in NAMES:
        out = json.loads((CONTRACTS / "out" / f"{name}.sol" / f"{name}.json").read_text())
        artifact = {
            "contractName": name,
            "source": f"contracts/src/{name}.sol",
            "compiler": "solc 0.8.30, optimizer 200 runs, evm cancun, no metadata hash",
            "abi": out["abi"],
            "bytecode": out["bytecode"]["object"],
            "deployedBytecode": out["deployedBytecode"]["object"],
        }
        texts[name] = json.dumps(artifact, indent=2) + "\n"
    return texts


def main() -> None:
    texts = build()
    stale = []
    for name, text in texts.items():
        path = PACKAGE / f"{name}.json"
        if "--check" in sys.argv:
            if not path.exists() or path.read_text() != text:
                stale.append(name)
            continue
        path.write_text(text)
        print(f"wrote {path.relative_to(ROOT)}")
    if stale:
        sys.exit(f"out of date: {', '.join(stale)}; run scripts/build_contracts.py")


if __name__ == "__main__":
    main()
