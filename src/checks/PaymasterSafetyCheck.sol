// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {IPaymaster, PackedUserOperation, PostOpMode, ENTRY_POINT_V07, SIG_VALIDATION_SUCCESS} from "../interfaces.sol";

/// @title PaymasterSafetyCheck — the three ways an ERC-4337 paymaster gets drained or griefed
/// @notice A paymaster pays gas for other people's user ops. Three implementation mistakes turn that
///         into a loss:
///           1. `validatePaymasterUserOp` not gated to the EntryPoint — anyone drives sponsorship
///              logic directly, outside a real op.
///           2. `validatePaymasterUserOp` sponsors an unbounded `maxCost` — one crafted op drains the
///              paymaster's whole EntryPoint deposit.
///           3. `postOp` reverts — because the EntryPoint calls it to settle after execution, a
///              paymaster whose `postOp` can revert (especially in `opReverted` mode) is griefed by
///              any user op that fails, and can brick settlement.
///         None of these is caught by the compiler or a happy-path test where the owner sponsors
///         their own well-formed op. This check drives each property directly against your paymaster.
///
///         Extend it and call {assertPaymasterSafe}. It reports the specific offender.
abstract contract PaymasterSafetyCheck is Test {
    function assertPaymasterSafe(IPaymaster pm) internal {
        (bool safe, string memory offender) = scanPaymaster(pm);
        assertTrue(safe, offender);
    }

    /// @dev Non-asserting predicate: true iff the paymaster is gated, bounded, and has a
    ///      non-reverting `postOp`. On failure, `offender` names which property broke.
    function scanPaymaster(IPaymaster pm) internal returns (bool safe, string memory offender) {
        PackedUserOperation memory op;
        op.sender = makeAddr("ig_account");
        bytes32 hash = keccak256("ig_userOpHash");
        uint256 modest = 0.01 ether;

        // --- 1. gated to the EntryPoint (caller-differential) ---
        // Sanity: the EntryPoint itself can validate a modest op.
        vm.prank(ENTRY_POINT_V07);
        (bytes memory ctx,) = pm.validatePaymasterUserOp(op, hash, modest);
        // A stranger must NOT be able to drive validation.
        vm.prank(makeAddr("ig_stranger"));
        (bool okStranger,) =
            address(pm).call(abi.encodeCall(IPaymaster.validatePaymasterUserOp, (op, hash, modest)));
        if (okStranger) {
            return (false, "UNGATED validatePaymasterUserOp: any caller can drive it (not restricted to the EntryPoint)");
        }

        // --- 2. bounds what it sponsors ---
        // Offer an absurd maxCost as the EntryPoint; a safe paymaster refuses (reverts, or returns a
        // non-success validationData). Unconditional success means it will sponsor any cost.
        uint256 huge = 100 ether;
        vm.prank(ENTRY_POINT_V07);
        (bool okHuge, bytes memory ret) =
            address(pm).call(abi.encodeCall(IPaymaster.validatePaymasterUserOp, (op, hash, huge)));
        if (okHuge) {
            (, uint256 vd) = abi.decode(ret, (bytes, uint256));
            if (vd == SIG_VALIDATION_SUCCESS) {
                return (false, "UNBOUNDED validatePaymasterUserOp: sponsors an arbitrarily large maxCost (deposit-drain)");
            }
        }

        // --- 3. postOp must never revert ---
        vm.prank(ENTRY_POINT_V07);
        (bool okSucceeded,) =
            address(pm).call(abi.encodeCall(IPaymaster.postOp, (PostOpMode.opSucceeded, ctx, modest, 1 gwei)));
        if (!okSucceeded) {
            return (false, "REVERTING postOp: reverts in opSucceeded mode (bricks EntryPoint settlement)");
        }
        vm.prank(ENTRY_POINT_V07);
        (bool okReverted,) =
            address(pm).call(abi.encodeCall(IPaymaster.postOp, (PostOpMode.opReverted, ctx, modest, 1 gwei)));
        if (!okReverted) {
            return (false, "REVERTING postOp: reverts in opReverted mode (a failed user op griefs the paymaster)");
        }

        return (true, "");
    }
}
