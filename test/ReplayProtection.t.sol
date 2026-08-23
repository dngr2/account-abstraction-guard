// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {ReplayProtectionCheck, IRelayExecutable} from "../src/checks/ReplayProtectionCheck.sol";
import {Counter, ReplayGuardedAccount, ReplayableAccount} from "./reference/RefRelayAccounts.sol";

contract ReplayProtectionCheckTest is ReplayProtectionCheck {
    function test_guardedAccount_passesTheCheck() public {
        (address owner, uint256 key) = makeAddrAndKey("owner");
        ReplayGuardedAccount account = new ReplayGuardedAccount(owner);
        Counter counter = new Counter();

        assertNoReplay(IRelayExecutable(address(account)), key, address(counter));
        assertEq(counter.count(), 1, "guarded account runs the op exactly once");
    }

    function test_check_catchesReplayableAccount() public {
        (address owner, uint256 key) = makeAddrAndKey("owner");
        ReplayableAccount account = new ReplayableAccount(owner);
        Counter counter = new Counter();

        (bool ok, string memory offender) = scanReplay(IRelayExecutable(address(account)), key, address(counter));
        assertFalse(ok, "check must flag the replayable account");
        assertEq(
            offender,
            "REPLAYABLE: the same signed operation executed twice (the relayed path does not consume a nonce)",
            "offender should be replay"
        );
        assertEq(counter.count(), 2, "replayable account ran the same signed op twice");
    }
}

/// Concrete impact: one owner signature, executed twice by a relayer.
contract ReplayDemo is Test {
    function test_replayable_signedOnce_executedTwice() public {
        (address owner, uint256 key) = makeAddrAndKey("owner");
        ReplayableAccount account = new ReplayableAccount(owner);
        Counter counter = new Counter();

        bytes memory data = abi.encodeWithSignature("increment()");
        bytes32 digest = keccak256(abi.encode(address(counter), uint256(0), data, uint256(0), address(account), block.chainid));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        account.executeWithSig(address(counter), 0, data, 0, sig);
        account.executeWithSig(address(counter), 0, data, 0, sig); // same payload, relayed again
        assertEq(counter.count(), 2, "owner signed once; the relayer ran it twice");
    }
}
