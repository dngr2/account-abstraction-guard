// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {SessionKeyScopeCheck, ISessionExecutable} from "../src/checks/SessionKeyScopeCheck.sol";
import {Allowed, Forbidden, ScopedSessionAccount, UnscopedSessionAccount} from "./reference/RefSessionAccounts.sol";

contract SessionKeyScopeCheckTest is SessionKeyScopeCheck {
    function test_scopedAccount_passesTheCheck() public {
        (address key, uint256 pk) = makeAddrAndKey("session");
        Allowed allowed = new Allowed();
        Forbidden forbidden = new Forbidden();
        ScopedSessionAccount account = new ScopedSessionAccount(key, address(allowed), Allowed.poke.selector);

        assertSessionKeyScoped(
            ISessionExecutable(address(account)),
            pk,
            address(allowed),
            abi.encodeCall(Allowed.poke, ()),
            address(forbidden),
            abi.encodeCall(Forbidden.rug, ())
        );

        assertTrue(allowed.poked(), "in-scope call ran");
        assertFalse(forbidden.rugged(), "out-of-scope call was blocked");
    }

    function test_check_catchesUnscopedAccount() public {
        (address key, uint256 pk) = makeAddrAndKey("session");
        Allowed allowed = new Allowed();
        Forbidden forbidden = new Forbidden();
        UnscopedSessionAccount account = new UnscopedSessionAccount(key, address(allowed), Allowed.poke.selector);

        (bool ok, string memory offender) = scanSessionScope(
            ISessionExecutable(address(account)),
            pk,
            address(allowed),
            abi.encodeCall(Allowed.poke, ()),
            address(forbidden),
            abi.encodeCall(Forbidden.rug, ())
        );

        assertFalse(ok, "check must flag the unscoped session key");
        assertEq(
            offender,
            "session key executed an OUT-OF-SCOPE call - target/selector scope not enforced",
            "offender should be scope"
        );
        assertTrue(forbidden.rugged(), "unscoped session key reached the forbidden target");
    }
}
