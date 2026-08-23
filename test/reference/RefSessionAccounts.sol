// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @dev The one thing the session key is allowed to do.
contract Allowed {
    bool public poked;

    function poke() external {
        poked = true;
    }
}

/// @dev Something the session key must never be able to reach.
contract Forbidden {
    bool public rugged;

    function rug() external {
        rugged = true;
    }
}

/// @dev Shared: a session key with a scope of (allowed target, allowed selector). Digest binds the
///      call, account, and chain id and is signed by the session key. The only difference between the
///      two references is whether the scope is enforced.
abstract contract SessionAccountBase {
    address public immutable sessionKey;
    address public immutable allowedTarget;
    bytes4 public immutable allowedSelector;

    constructor(address _sessionKey, address _allowedTarget, bytes4 _allowedSelector) {
        sessionKey = _sessionKey;
        allowedTarget = _allowedTarget;
        allowedSelector = _allowedSelector;
    }

    function _digest(address target, uint256 value, bytes calldata data, uint256 nonce)
        internal
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(target, value, data, nonce, address(this), block.chainid));
    }

    function _recover(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        require(signature.length == 65, "bad signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        return ecrecover(digest, v, r, s);
    }
}

/// @dev CORRECT: enforces the session key's scope — only the allowed target and selector.
contract ScopedSessionAccount is SessionAccountBase {
    constructor(address k, address t, bytes4 s) SessionAccountBase(k, t, s) {}

    function executeAsSession(address target, uint256 value, bytes calldata data, uint256 nonce, bytes calldata signature)
        external
    {
        require(_recover(_digest(target, value, data, nonce), signature) == sessionKey, "not session key");
        require(target == allowedTarget, "target out of scope");
        require(data.length >= 4 && bytes4(data[:4]) == allowedSelector, "selector out of scope");
        (bool ok,) = target.call{value: value}(data);
        require(ok, "call failed");
    }
}

/// @dev BROKEN: verifies the session key's signature but never checks the scope. The "limited" key
///      can call any target and any function — it is really the master key.
contract UnscopedSessionAccount is SessionAccountBase {
    constructor(address k, address t, bytes4 s) SessionAccountBase(k, t, s) {}

    function executeAsSession(address target, uint256 value, bytes calldata data, uint256 nonce, bytes calldata signature)
        external
    {
        require(_recover(_digest(target, value, data, nonce), signature) == sessionKey, "not session key");
        // BUG: no scope enforcement — target/selector are never checked.
        (bool ok,) = target.call{value: value}(data);
        require(ok, "call failed");
    }
}
