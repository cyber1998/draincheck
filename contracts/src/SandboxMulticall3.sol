// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Draincheck Authors
pragma solidity 0.8.30;

/// @title SandboxMulticall3
/// @notice MINIMAL TEST STAND-IN for Multicall3's `aggregate3`, for the Draincheck sandbox
///         only. Real chains have Multicall3 at 0xcA11bde05977b3631167028862bE2a173976CA11;
///         a plain anvil chain does not, and agent toolkits (Coinbase AgentKit's ERC-20
///         actions) read token details through it. Installed at that address with
///         anvil_setCode on local chains only, never on a fork.
/// @dev Same signature and semantics as Multicall3.aggregate3: every call is made in order,
///      and the whole call reverts if a call that may not fail does fail.
contract SandboxMulticall3 {
    struct Call3 {
        address target;
        bool allowFailure;
        bytes callData;
    }

    struct Result {
        bool success;
        bytes returnData;
    }

    function aggregate3(Call3[] calldata calls) external payable returns (Result[] memory returnData) {
        uint256 length = calls.length;
        returnData = new Result[](length);
        for (uint256 i = 0; i < length; i++) {
            Call3 calldata call = calls[i];
            (bool success, bytes memory data) = call.target.call(call.callData);
            if (!success && !call.allowFailure) revert("Multicall3: call failed");
            returnData[i] = Result(success, data);
        }
    }
}
