// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {PaymasterSafetyCheck} from "../src/checks/PaymasterSafetyCheck.sol";
import {IPaymaster, PackedUserOperation, PostOpMode, ENTRY_POINT_V07} from "../src/interfaces.sol";
import {
    SafePaymaster,
    UngatedPaymaster,
    UnboundedPaymaster,
    RevertingPostOpPaymaster
} from "./reference/RefPaymasters.sol";

contract PaymasterSafetyCheckTest is PaymasterSafetyCheck {
    function test_safePaymaster_passesTheCheck() public {
        SafePaymaster pm = new SafePaymaster();
        assertPaymasterSafe(IPaymaster(address(pm)));

        (bool safe,) = scanPaymaster(IPaymaster(address(pm)));
        assertTrue(safe, "safe paymaster should scan clean");
    }

    function test_check_catchesUngatedPaymaster() public {
        UngatedPaymaster pm = new UngatedPaymaster();
        (bool safe, string memory offender) = scanPaymaster(IPaymaster(address(pm)));
        assertFalse(safe, "check must flag the ungated paymaster");
        assertEq(
            offender,
            "UNGATED validatePaymasterUserOp: any caller can drive it (not restricted to the EntryPoint)",
            "offender should be the gating"
        );
    }

    function test_check_catchesUnboundedPaymaster() public {
        UnboundedPaymaster pm = new UnboundedPaymaster();
        (bool safe, string memory offender) = scanPaymaster(IPaymaster(address(pm)));
        assertFalse(safe, "check must flag the unbounded paymaster");
        assertEq(
            offender,
            "UNBOUNDED validatePaymasterUserOp: sponsors an arbitrarily large maxCost (deposit-drain)",
            "offender should be the bound"
        );
    }

    function test_check_catchesRevertingPostOp() public {
        RevertingPostOpPaymaster pm = new RevertingPostOpPaymaster();
        (bool safe, string memory offender) = scanPaymaster(IPaymaster(address(pm)));
        assertFalse(safe, "check must flag the reverting-postOp paymaster");
        assertEq(
            offender,
            "REVERTING postOp: reverts in opReverted mode (a failed user op griefs the paymaster)",
            "offender should be postOp"
        );
    }
}

/// Concrete exploits behind each flag.
contract PaymasterSafetyDemo is Test {
    function test_ungated_strangerDrivesValidation() public {
        UngatedPaymaster pm = new UngatedPaymaster();
        PackedUserOperation memory op;
        // A stranger (not the EntryPoint) validates an op the paymaster would sponsor.
        vm.prank(makeAddr("stranger"));
        (, uint256 vd) = pm.validatePaymasterUserOp(op, keccak256("x"), 0.01 ether);
        assertEq(vd, 0, "ungated paymaster validates for a non-EntryPoint caller");
    }

    function test_unbounded_sponsorsWholeDeposit() public {
        UnboundedPaymaster pm = new UnboundedPaymaster();
        PackedUserOperation memory op;
        vm.prank(ENTRY_POINT_V07);
        (, uint256 vd) = pm.validatePaymasterUserOp(op, keccak256("x"), 100 ether);
        assertEq(vd, 0, "unbounded paymaster sponsors a 100 ETH maxCost (drains its deposit)");
    }

    function test_revertingPostOp_griefedByFailedOp() public {
        RevertingPostOpPaymaster pm = new RevertingPostOpPaymaster();
        vm.prank(ENTRY_POINT_V07);
        vm.expectRevert(bytes("postOp: op reverted"));
        pm.postOp(PostOpMode.opReverted, "", 0.01 ether, 1 gwei);
    }
}
