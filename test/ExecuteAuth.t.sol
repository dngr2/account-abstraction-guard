// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {ExecuteAuthCheck} from "../src/checks/ExecuteAuthCheck.sol";
import {IExecutable, ENTRY_POINT_V07} from "../src/interfaces.sol";
import {GoodAccount, UngatedExecAccount} from "./reference/RefAccounts.sol";

contract ExecuteAuthCheckTest is ExecuteAuthCheck {
    address owner = makeAddr("owner");

    function test_gatedAccount_passesTheCheck() public {
        GoodAccount a = new GoodAccount(owner);
        assertExecuteGated(IExecutable(address(a)));

        (bool gated,) = scanExecute(IExecutable(address(a)));
        assertTrue(gated, "gated account should scan as gated");
    }

    function test_check_catchesUngatedExecute() public {
        UngatedExecAccount a = new UngatedExecAccount(owner);
        (bool gated, string memory offender) = scanExecute(IExecutable(address(a)));
        assertFalse(gated, "check must flag the ungated account");
        assertEq(
            offender,
            "UNGUARDED execute: a stranger ran an arbitrary call through the account (drain)",
            "offender should be execute"
        );
    }
}

/// Concrete drain: a stranger empties an ungated account's ETH via execute; the gated account
/// rejects them but lets the EntryPoint through.
contract ExecuteAuthDemo is Test {
    address owner = makeAddr("owner");
    address attacker = makeAddr("attacker");

    function test_ungated_strangerDrainsAccount() public {
        UngatedExecAccount a = new UngatedExecAccount(owner);
        vm.deal(address(a), 10 ether);

        vm.prank(attacker); // NOT the EntryPoint or owner
        a.execute(attacker, 10 ether, "");

        assertEq(attacker.balance, 10 ether, "attacker drained the account");
        assertEq(address(a).balance, 0);
    }

    function test_gated_strangerRejected_entryPointAllowed() public {
        GoodAccount a = new GoodAccount(owner);
        vm.deal(address(a), 10 ether);

        vm.prank(attacker);
        vm.expectRevert(bytes("not authorized"));
        a.execute(attacker, 10 ether, "");

        // the EntryPoint is allowed to execute
        vm.prank(ENTRY_POINT_V07);
        a.execute(attacker, 1 ether, "");
        assertEq(attacker.balance, 1 ether, "EntryPoint execute is accepted");
    }
}
