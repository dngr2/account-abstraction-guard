// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {UserOpSignatureCheck} from "../src/checks/UserOpSignatureCheck.sol";
import {IAccount, PackedUserOperation, ENTRY_POINT_V07} from "../src/interfaces.sol";
import {GoodAccount, NoSigAccount} from "./reference/RefAccounts.sol";

contract UserOpSignatureCheckTest is UserOpSignatureCheck {
    function test_sigCheckingAccount_passesTheCheck() public {
        (address owner, uint256 key) = makeAddrAndKey("owner");
        GoodAccount a = new GoodAccount(owner);
        assertValidatesSignature(IAccount(address(a)), key);

        (bool ok,) = scanSignature(IAccount(address(a)), key);
        assertTrue(ok, "sig-checking account should scan as validating");
    }

    function test_check_catchesNoSigAccount() public {
        (address owner, uint256 key) = makeAddrAndKey("owner");
        NoSigAccount a = new NoSigAccount(owner);
        (bool ok, string memory offender) = scanSignature(IAccount(address(a)), key);
        assertFalse(ok, "check must flag the no-signature account");
        assertEq(
            offender,
            "UNVALIDATED signature: validateUserOp accepts a tampered signature (account takeover)",
            "offender should be the signature"
        );
    }
}

/// Concrete takeover: a random/forged signature validates on the no-sig account, so a bundler would
/// execute an attacker's UserOp; the sig-checking account rejects it.
contract UserOpSignatureDemo is Test {
    function test_noSig_forgedSignatureValidates() public {
        (address owner,) = makeAddrAndKey("owner");
        NoSigAccount a = new NoSigAccount(owner);

        PackedUserOperation memory op;
        op.sender = address(a);
        op.signature = hex"deadbeef"; // not a real signature at all

        vm.prank(ENTRY_POINT_V07);
        uint256 vd = a.validateUserOp(op, keccak256("anything"), 0);
        assertEq(vd, 0, "no-sig account validates a forged UserOp (takeover)");
    }

    function test_good_forgedSignatureRejected() public {
        (address owner, uint256 key) = makeAddrAndKey("owner");
        GoodAccount a = new GoodAccount(owner);

        bytes32 h = keccak256("anything");
        // sign with a DIFFERENT key (an attacker, not the owner)
        (, uint256 attackerKey) = makeAddrAndKey("attacker");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attackerKey, h);

        PackedUserOperation memory op;
        op.sender = address(a);
        op.signature = abi.encodePacked(r, s, v);

        vm.prank(ENTRY_POINT_V07);
        uint256 vd = a.validateUserOp(op, h, 0);
        assertEq(vd, 1, "good account rejects a non-owner signature");
    }
}
