// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {IExecutable, ENTRY_POINT_V07} from "../interfaces.sol";

/// @dev A trivial target used to observe whether an arbitrary call actually executed.
contract Probe {
    bool public poked;

    function poke() external {
        poked = true;
    }
}

/// @title ExecuteAuthCheck — a smart account's execute() must be gated to the EntryPoint (or owner)
/// @notice The catastrophic ERC-4337 account footgun: `execute(target, value, data)` runs an
///         arbitrary call FROM the account. If it isn't restricted to the EntryPoint (or the
///         account owner), anyone calls it directly and drains the account — transfer its ETH/tokens
///         or approve themselves. The account still validates UserOps correctly through the
///         EntryPoint; the direct, ungated `execute` path is the bug, and nothing in the compiler or
///         a happy-path test surfaces it.
///
///         Same access-control class as v4-hookguard (`onlyPoolManager`) and
///         superchain-interop-guard (`onlyBridge`); here the authorized callers are the EntryPoint
///         and the owner. The check verifies EFFECT: it runs an arbitrary call as a stranger through
///         the account and asserts it did not execute.
abstract contract ExecuteAuthCheck is Test {
    address internal constant ENTRY_POINT = ENTRY_POINT_V07;

    function assertExecuteGated(IExecutable account) internal {
        (bool gated, string memory offender) = scanExecute(account);
        assertTrue(gated, offender);
    }

    function scanExecute(IExecutable account) internal returns (bool gated, string memory offender) {
        // A stranger (this test contract) tries to run an arbitrary call through the account.
        Probe p = new Probe();
        (bool ok,) = address(account).call(abi.encodeCall(IExecutable.execute, (address(p), 0, abi.encodeCall(Probe.poke, ()))));
        if (ok && p.poked()) {
            return (false, "UNGUARDED execute: a stranger ran an arbitrary call through the account (drain)");
        }

        // Sanity: the EntryPoint itself CAN execute through the account.
        Probe p2 = new Probe();
        vm.prank(ENTRY_POINT);
        account.execute(address(p2), 0, abi.encodeCall(Probe.poke, ()));
        require(p2.poked(), "SETUP: EntryPoint cannot execute through the account");

        return (true, "");
    }
}
