// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";

/// @notice A signature-gated, relayed execution path: a caller submits a call the account owner
///         signed off-chain, and anyone can relay it. This is the path 7702 delegates and modular
///         accounts expose for gasless/relayed actions — and the one that must carry its own replay
///         protection, because it does not go through the EntryPoint's nonce.
interface IRelayExecutable {
    function executeWithSig(address target, uint256 value, bytes calldata data, uint256 nonce, bytes calldata signature)
        external;
}

interface ICounter {
    function count() external view returns (uint256);
}

/// @title ReplayProtectionCheck — a signed, relayed operation must not be executable twice
/// @notice Replay is the classic footgun of accounts that accept off-chain-signed operations on a
///         direct path (7702 delegates, modular/relayed accounts, meta-transactions). The EntryPoint's
///         2D nonce protects the standard `validateUserOp` flow — but a direct `executeWithSig`-style
///         path bypasses it, so the account must consume a nonce (or mark the operation used) itself.
///         An account that verifies the owner's signature but never consumes the nonce lets ANY relayer
///         resubmit the same signed payload again and again: a signed "send 1 ETH" becomes "send it
///         every block". The owner signed once; a happy-path test that relays once never sees it.
///
///         The check relays a signed operation once (it must take effect), then relays the identical
///         payload again, and asserts the second time has no effect. Pass the owner key that signs and
///         a simple counter target whose state reveals whether the op ran twice.
abstract contract ReplayProtectionCheck is Test {
    function assertNoReplay(IRelayExecutable account, uint256 ownerKey, address counter) internal {
        (bool ok, string memory offender) = scanReplay(account, ownerKey, counter);
        assertTrue(ok, offender);
    }

    /// @dev Non-asserting predicate: true iff the same signed operation cannot execute twice.
    function scanReplay(IRelayExecutable account, uint256 ownerKey, address counter)
        internal
        returns (bool, string memory)
    {
        bytes memory data = abi.encodeWithSignature("increment()");
        uint256 nonce = 0;

        bytes32 digest = keccak256(abi.encode(counter, uint256(0), data, nonce, address(account), block.chainid));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        uint256 startCount = ICounter(counter).count();
        account.executeWithSig(counter, 0, data, nonce, sig);
        uint256 afterFirst = ICounter(counter).count();
        require(afterFirst > startCount, "SETUP: the first signed execution had no effect");

        // Relay the identical signed payload a second time.
        (bool relayed,) = address(account).call(
            abi.encodeCall(IRelayExecutable.executeWithSig, (counter, 0, data, nonce, sig))
        );
        if (relayed && ICounter(counter).count() > afterFirst) {
            return (false, "REPLAYABLE: the same signed operation executed twice (the relayed path does not consume a nonce)");
        }
        return (true, "");
    }
}
