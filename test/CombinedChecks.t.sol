// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ExecuteAuthCheck} from "../src/checks/ExecuteAuthCheck.sol";
import {UserOpSignatureCheck} from "../src/checks/UserOpSignatureCheck.sol";
import {IExecutable, IAccount} from "../src/interfaces.sol";
import {GoodAccount} from "./reference/RefAccounts.sol";

/// Regression: a single security suite may inherit multiple checks at once (exactly what
/// `guard-scaffold aa-account` emits). This must compile and run — the checks must not collide on
/// shared symbols.
contract CombinedChecksTest is ExecuteAuthCheck, UserOpSignatureCheck {
    function test_bothChecksInOneContract() public {
        (address owner, uint256 key) = makeAddrAndKey("owner");
        GoodAccount account = new GoodAccount(owner);

        assertExecuteGated(IExecutable(address(account)));
        assertValidatesSignature(IAccount(address(account)), key);
    }
}
