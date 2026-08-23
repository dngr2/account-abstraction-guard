// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IPaymaster, PackedUserOperation, PostOpMode, ENTRY_POINT_V07} from "../../src/interfaces.sol";

uint256 constant MAX_SPONSOR = 1 ether;

/// @dev CORRECT: gated to the EntryPoint, caps the cost it will sponsor, and a `postOp` that never
///      reverts in any mode. Passes all three checks.
contract SafePaymaster is IPaymaster {
    error NotEntryPoint();

    modifier onlyEntryPoint() {
        if (msg.sender != ENTRY_POINT_V07) revert NotEntryPoint();
        _;
    }

    function validatePaymasterUserOp(PackedUserOperation calldata, bytes32, uint256 maxCost)
        external
        view
        onlyEntryPoint
        returns (bytes memory context, uint256 validationData)
    {
        if (maxCost > MAX_SPONSOR) return ("", 1); // refuse to sponsor beyond the cap
        return ("", 0);
    }

    function postOp(PostOpMode, bytes calldata, uint256, uint256) external view onlyEntryPoint {}
}

/// @dev BROKEN (gating): `validatePaymasterUserOp` has no EntryPoint gate. Anyone can call it to
///      drive sponsorship accounting outside a real op. Bounds and postOp are otherwise fine.
contract UngatedPaymaster is IPaymaster {
    function validatePaymasterUserOp(PackedUserOperation calldata, bytes32, uint256 maxCost)
        external
        pure
        returns (bytes memory context, uint256 validationData)
    {
        if (maxCost > MAX_SPONSOR) return ("", 1);
        return ("", 0);
    }

    function postOp(PostOpMode, bytes calldata, uint256, uint256) external {}
}

/// @dev BROKEN (bounds): gated and postOp-safe, but sponsors ANY `maxCost`. One crafted op with a
///      huge gas cost drains the paymaster's entire EntryPoint deposit.
contract UnboundedPaymaster is IPaymaster {
    error NotEntryPoint();

    modifier onlyEntryPoint() {
        if (msg.sender != ENTRY_POINT_V07) revert NotEntryPoint();
        _;
    }

    function validatePaymasterUserOp(PackedUserOperation calldata, bytes32, uint256)
        external
        view
        onlyEntryPoint
        returns (bytes memory context, uint256 validationData)
    {
        return ("", 0); // BUG: no cap — sponsors any cost
    }

    function postOp(PostOpMode, bytes calldata, uint256, uint256) external view onlyEntryPoint {}
}

/// @dev BROKEN (griefing): gated and bounded, but `postOp` reverts when the user op reverted. Any
///      user whose op fails makes the EntryPoint's settlement `postOp` revert — the paymaster is
///      griefed and settlement can brick.
contract RevertingPostOpPaymaster is IPaymaster {
    error NotEntryPoint();

    modifier onlyEntryPoint() {
        if (msg.sender != ENTRY_POINT_V07) revert NotEntryPoint();
        _;
    }

    function validatePaymasterUserOp(PackedUserOperation calldata, bytes32, uint256 maxCost)
        external
        view
        onlyEntryPoint
        returns (bytes memory context, uint256 validationData)
    {
        if (maxCost > MAX_SPONSOR) return ("", 1);
        return ("", 0);
    }

    function postOp(PostOpMode mode, bytes calldata, uint256, uint256) external view onlyEntryPoint {
        require(mode != PostOpMode.opReverted, "postOp: op reverted"); // BUG: griefable
    }
}
