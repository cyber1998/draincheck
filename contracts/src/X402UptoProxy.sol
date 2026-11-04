// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Draincheck Authors
pragma solidity 0.8.30;

import {MiniPermit2} from "./MiniPermit2.sol";

/// @title X402UptoProxy
/// @notice Local stand-in for x402's `x402UptoPermit2Proxy`, for the Draincheck sandbox only.
/// @dev Same `settle` interface, witness type string and checks as the reference proxy
///      (x402-foundation/x402, contracts/evm/src/x402UptoPermit2Proxy.sol): the facilitator
///      named in the signed witness picks the final amount, up to the signed maximum, and
///      the recipient is fixed by the witness. Installed at the spec's proxy address with
///      anvil_setCode, so Permit2's address is a constant rather than an immutable.
contract X402UptoProxy {
    // Canonical Permit2 address; MiniPermit2 is installed there in the sandbox.
    MiniPermit2 public constant PERMIT2 = MiniPermit2(0x000000000022D473030F116dDEE9F6B43aC78BA3);

    string public constant WITNESS_TYPE_STRING =
        "Witness witness)TokenPermissions(address token,uint256 amount)Witness(address to,address facilitator,uint256 validAfter)";
    bytes32 public constant WITNESS_TYPEHASH = keccak256("Witness(address to,address facilitator,uint256 validAfter)");

    struct Witness {
        address to;
        address facilitator;
        uint256 validAfter;
    }

    // Slot 0: reentrancy flag (1 = unlocked or never set, 2 = locked).
    uint256 private _status;

    event Settled();

    error UnauthorizedFacilitator();
    error AmountExceedsPermitted();
    error InvalidDestination();
    error PaymentTooEarly();
    error Reentrancy();

    function settle(
        MiniPermit2.PermitTransferFrom calldata permit,
        uint256 amount,
        address owner,
        Witness calldata witness,
        bytes calldata signature
    ) external {
        if (_status == 2) revert Reentrancy();
        _status = 2;
        if (amount > permit.permitted.amount) revert AmountExceedsPermitted();
        if (msg.sender != witness.facilitator) revert UnauthorizedFacilitator();
        if (witness.to == address(0)) revert InvalidDestination();
        if (block.timestamp < witness.validAfter) revert PaymentTooEarly();
        bytes32 witnessHash = keccak256(abi.encode(WITNESS_TYPEHASH, witness.to, witness.facilitator, witness.validAfter));
        PERMIT2.permitWitnessTransferFrom(
            permit,
            MiniPermit2.SignatureTransferDetails({to: witness.to, requestedAmount: amount}),
            owner,
            witnessHash,
            WITNESS_TYPE_STRING,
            signature
        );
        _status = 1;
        emit Settled();
    }
}
