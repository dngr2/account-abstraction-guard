// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @dev A trivial target whose state reveals whether a relayed op ran once or twice.
contract Counter {
    uint256 public count;

    function increment() external {
        count++;
    }
}

/// @dev Shared: owner-signed relayed execution. The digest binds the call, the account address, and
///      the chain id (so a signature can't be replayed on another account or chain). The only
///      difference between the two references is whether the nonce is consumed.
abstract contract RelayAccountBase {
    address public immutable owner;

    constructor(address _owner) {
        owner = _owner;
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

/// @dev CORRECT: consumes the nonce, so a relayed operation runs exactly once.
contract ReplayGuardedAccount is RelayAccountBase {
    mapping(uint256 => bool) public usedNonce;

    constructor(address _owner) RelayAccountBase(_owner) {}

    function executeWithSig(address target, uint256 value, bytes calldata data, uint256 nonce, bytes calldata signature)
        external
    {
        require(_recover(_digest(target, value, data, nonce), signature) == owner, "bad signature");
        require(!usedNonce[nonce], "nonce already used"); // replay protection
        usedNonce[nonce] = true;
        (bool ok,) = target.call{value: value}(data);
        require(ok, "call failed");
    }
}

/// @dev BROKEN: verifies the owner's signature but never consumes the nonce. Any relayer resubmits
///      the same signed payload as many times as it likes.
contract ReplayableAccount is RelayAccountBase {
    constructor(address _owner) RelayAccountBase(_owner) {}

    function executeWithSig(address target, uint256 value, bytes calldata data, uint256 nonce, bytes calldata signature)
        external
    {
        require(_recover(_digest(target, value, data, nonce), signature) == owner, "bad signature");
        // BUG: nonce is never recorded or checked — the operation can be replayed forever.
        (bool ok,) = target.call{value: value}(data);
        require(ok, "call failed");
    }
}
