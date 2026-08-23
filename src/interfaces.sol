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

/// @notice How the EntryPoint tells a paymaster's `postOp` the user op turned out. `opReverted`
///         means the account's call reverted — a paymaster must still settle without reverting.
enum PostOpMode {
    opSucceeded,
    opReverted,
    postOpReverted
}

/// @notice The ERC-4337 v0.7 paymaster surface. The EntryPoint calls `validatePaymasterUserOp` to
///         decide whether to sponsor (returning a `context` handed back to `postOp`), then `postOp`
///         after execution to settle. Both must be restricted to the EntryPoint; `validate` must
///         bound what it agrees to sponsor; `postOp` must never revert.
interface IPaymaster {
    function validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
        external
        returns (bytes memory context, uint256 validationData);

    function postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost, uint256 actualUserOpGasPrice)
        external;
}

uint256 constant SIG_VALIDATION_FAILED = 1;
uint256 constant SIG_VALIDATION_SUCCESS = 0;

/// @dev Canonical ERC-4337 v0.7 EntryPoint singleton.
address constant ENTRY_POINT_V07 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
