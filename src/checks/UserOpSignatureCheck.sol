// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {IAccount, PackedUserOperation, SIG_VALIDATION_FAILED, ENTRY_POINT_V07} from "../interfaces.sol";

/// @title UserOpSignatureCheck — validateUserOp must actually reject a wrong signature
/// @notice The account-takeover footgun: an ERC-4337 account whose `validateUserOp` returns success
///         (validationData == 0) without truly checking the signature over `userOpHash`. Any bundler
///         then executes ANY UserOp for that account — arbitrary calldata, full control. It passes a
///         happy-path test (the owner's own op validates); only a *wrong* signature exposes it.
///
///         The check signs a UserOp with the owner key (must validate), then tampers one byte of the
///         signature and asserts the account now returns SIG_VALIDATION_FAILED. An account that
///         ignores the signature returns 0 for both and is flagged.
abstract contract UserOpSignatureCheck is Test {

    /// @param account   the ERC-4337 account under test
    /// @param ownerKey  the private key whose address the account treats as owner
    function assertValidatesSignature(IAccount account, uint256 ownerKey) internal {
        (bool validates, string memory offender) = scanSignature(account, ownerKey);
        assertTrue(validates, offender);
    }

    function scanSignature(IAccount account, uint256 ownerKey) internal returns (bool, string memory) {
        bytes32 userOpHash = keccak256("account-abstraction-guard.userOpHash");

        PackedUserOperation memory op;
        op.sender = address(account);

        // --- valid signature must validate (returns 0) ---
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        op.signature = abi.encodePacked(r, s, v);
        vm.prank(ENTRY_POINT_V07);
        uint256 okData = account.validateUserOp(op, userOpHash, 0);
        require(okData == 0, "SETUP: account rejects its own owner's valid signature");

        // --- tampered signature must fail (returns SIG_VALIDATION_FAILED) ---
        bytes memory bad = op.signature;
        bad[0] = bad[0] ^ bytes1(0x01); // flip one bit of r
        op.signature = bad;
        vm.prank(ENTRY_POINT_V07);
        uint256 badData = account.validateUserOp(op, userOpHash, 0);
        if (badData != SIG_VALIDATION_FAILED) {
            return (false, "UNVALIDATED signature: validateUserOp accepts a tampered signature (account takeover)");
        }

        return (true, "");
    }
}
