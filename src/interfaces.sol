// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @notice ERC-4337 v0.7 UserOperation (packed form).
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

/// @notice The ERC-4337 account validation entrypoint. Returns validationData: 0 on a valid
///         signature, SIG_VALIDATION_FAILED (1) on an invalid one (higher bits pack time bounds).
interface IAccount {
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        returns (uint256 validationData);
}

/// @notice The account's execution surface — the function that runs arbitrary calls from the
///         account. This is the drain vector if it is not caller-gated.
interface IExecutable {
    function execute(address target, uint256 value, bytes calldata data) external;
}

uint256 constant SIG_VALIDATION_FAILED = 1;
uint256 constant SIG_VALIDATION_SUCCESS = 0;

/// @dev Canonical ERC-4337 v0.7 EntryPoint singleton.
address constant ENTRY_POINT_V07 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
