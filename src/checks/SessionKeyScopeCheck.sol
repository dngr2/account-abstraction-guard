// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";

/// @notice A session-key / ERC-7702-delegate execution path: a secondary key, granted a LIMITED
///         permission (only certain targets/selectors), signs an operation the account executes.
interface ISessionExecutable {
    function executeAsSession(address target, uint256 value, bytes calldata data, uint256 nonce, bytes calldata signature)
        external;
}

/// @title SessionKeyScopeCheck — a session key must be confined to its granted scope
/// @notice The session-key / 7702-delegate footgun. A session key (or a 7702 delegate's scoped
///         signer) is handed out precisely because it is NOT the owner: it may spend on one target,
///         call one function, up to a cap, until an expiry. If the account verifies the session key's
///         signature but does not enforce the scope, the "limited" key is really the master key —
///         it can call any target and any function, i.e. drain the account. The grant looks correct
///         and the intended action works; only an out-of-scope call exposes it, and a happy-path test
///         never makes one.
///
///         The check drives the account with the session key twice: once with the in-scope call
///         (which must work) and once with an out-of-scope call (which must be rejected). Pass the
///         session key, the in-scope (target, calldata) it is allowed, and an out-of-scope
///         (target, calldata) it must not be able to make.
abstract contract SessionKeyScopeCheck is Test {
    function assertSessionKeyScoped(
        ISessionExecutable account,
        uint256 sessionKeyPk,
        address inScopeTarget,
        bytes memory inScopeData,
        address outOfScopeTarget,
        bytes memory outOfScopeData
    ) internal {
        (bool ok, string memory offender) =
            scanSessionScope(account, sessionKeyPk, inScopeTarget, inScopeData, outOfScopeTarget, outOfScopeData);
        assertTrue(ok, offender);
    }

    /// @dev Non-asserting predicate: true iff the in-scope call works and the out-of-scope call is
    ///      rejected. Reverts on setup failure (the in-scope call not going through).
    function scanSessionScope(
        ISessionExecutable account,
        uint256 sessionKeyPk,
        address inScopeTarget,
        bytes memory inScopeData,
        address outOfScopeTarget,
        bytes memory outOfScopeData
    ) internal returns (bool, string memory) {
        bool inRan = _sessionExec(account, sessionKeyPk, inScopeTarget, inScopeData, 0);
        require(inRan, "SETUP: the in-scope session call was rejected");

        bool outRan = _sessionExec(account, sessionKeyPk, outOfScopeTarget, outOfScopeData, 1);
        if (outRan) {
            return (false, "session key executed an OUT-OF-SCOPE call - target/selector scope not enforced");
        }
        return (true, "");
    }

    function _sessionExec(ISessionExecutable account, uint256 pk, address target, bytes memory data, uint256 nonce)
        private
        returns (bool executed)
    {
        bytes32 digest = keccak256(abi.encode(target, uint256(0), data, nonce, address(account), block.chainid));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);
        (executed,) =
            address(account).call(abi.encodeCall(ISessionExecutable.executeAsSession, (target, 0, data, nonce, sig)));
    }
}
