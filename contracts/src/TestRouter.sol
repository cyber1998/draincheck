// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Draincheck Authors
pragma solidity 0.8.30;

interface IERC20Like {
    function transfer(address to, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
}

/// @title TestRouter
/// @notice A swap router stand-in for the Draincheck sandbox only. Holds no value.
/// @dev SANDBOX ONLY. configure has no access control. With skimBps 0 and drainAllowance
///      false this is an honest 1:1 router. Turning on skimming or drainAllowance makes it a
///      deliberately vulnerable router that Draincheck scenarios use as a target. Draincheck
///      installs the runtime code with anvil_setCode, so there is no constructor.
contract TestRouter {
    error InsufficientOutput(uint256 amountOut, uint256 minOut);
    error SkimTooHigh(uint16 skimBps);
    error PullBelowAmount(uint256 pulled, uint256 amountIn);
    error TransferFailed();

    event Swapped(
        address indexed sender, address tokenIn, address tokenOut, uint256 amountIn, uint256 amountOut
    );

    address public attacker;
    uint16 public skimBps;
    bool public drainAllowance;

    /// @notice Sets the attacker address, the skim rate in basis points, and whether the
    ///         router pulls the caller's full allowance. SANDBOX ONLY: no access control.
    function configure(address attacker_, uint16 skimBps_, bool drainAllowance_) external {
        if (skimBps_ > 10_000) revert SkimTooHigh(skimBps_);
        attacker = attacker_;
        skimBps = skimBps_;
        drainAllowance = drainAllowance_;
    }

    /// @notice Swaps `amountIn` of `tokenIn` for `tokenOut` at a 1:1 base-unit rate, minus skim.
    function swap(address tokenIn, address tokenOut, uint256 amountIn, uint256 minOut, address to)
        external
        returns (uint256 amountOut)
    {
        uint256 pulled = amountIn;
        if (drainAllowance) {
            uint256 allowed = IERC20Like(tokenIn).allowance(msg.sender, address(this));
            uint256 balance = IERC20Like(tokenIn).balanceOf(msg.sender);
            pulled = allowed < balance ? allowed : balance;
            if (pulled < amountIn) revert PullBelowAmount(pulled, amountIn);
        }

        if (!IERC20Like(tokenIn).transferFrom(msg.sender, address(this), pulled)) revert TransferFailed();

        uint256 skim = amountIn * skimBps / 10_000 + (pulled - amountIn);
        if (skim > 0 && attacker != address(0)) {
            if (!IERC20Like(tokenIn).transfer(attacker, skim)) revert TransferFailed();
        }

        amountOut = amountIn - amountIn * skimBps / 10_000;
        if (amountOut < minOut) revert InsufficientOutput(amountOut, minOut);

        if (!IERC20Like(tokenOut).transfer(to, amountOut)) revert TransferFailed();

        emit Swapped(msg.sender, tokenIn, tokenOut, amountIn, amountOut);
    }
}
