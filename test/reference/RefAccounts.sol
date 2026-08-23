// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {PackedUserOperation, ENTRY_POINT_V07} from "../../src/interfaces.sol";

abstract contract AccountBase {
    address public immutable owner;
    address internal constant ENTRY_POINT = ENTRY_POINT_V07;

    constructor(address _owner) {
        owner = _owner;
    }

    receive() external payable {}

    function _recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        return ecrecover(hash, v, r, s);
    }
}

/// @dev CORRECT: execute is gated to the EntryPoint or owner, and validateUserOp checks the signature.
contract GoodAccount is AccountBase {
    constructor(address _owner) AccountBase(_owner) {}

    function execute(address target, uint256 value, bytes calldata data) external {
        require(msg.sender == ENTRY_POINT || msg.sender == owner, "not authorized");
        (bool ok,) = target.call{value: value}(data);
        require(ok, "call failed");
    }

    function validateUserOp(PackedUserOperation calldata op, bytes32 userOpHash, uint256)
        external
        view
        returns (uint256)
    {
        return _recover(userOpHash, op.signature) == owner ? 0 : 1;
    }
}

/// @dev BROKEN: execute has no caller gate. Anyone runs arbitrary calls from the account → drain.
contract UngatedExecAccount is AccountBase {
    constructor(address _owner) AccountBase(_owner) {}

    function execute(address target, uint256 value, bytes calldata data) external {
        (bool ok,) = target.call{value: value}(data); // BUG: no msg.sender check
        require(ok, "call failed");
    }

    function validateUserOp(PackedUserOperation calldata op, bytes32 userOpHash, uint256)
        external
        view
        returns (uint256)
    {
        return _recover(userOpHash, op.signature) == owner ? 0 : 1;
    }
}

/// @dev BROKEN: validateUserOp returns success without checking the signature. Any UserOp validates
///      for this account → takeover.
contract NoSigAccount is AccountBase {
    constructor(address _owner) AccountBase(_owner) {}

    function execute(address target, uint256 value, bytes calldata data) external {
        require(msg.sender == ENTRY_POINT || msg.sender == owner, "not authorized");
        (bool ok,) = target.call{value: value}(data);
        require(ok, "call failed");
    }

    function validateUserOp(PackedUserOperation calldata, bytes32, uint256) external pure returns (uint256) {
        return 0; // BUG: always "valid", signature never checked
    }
}
