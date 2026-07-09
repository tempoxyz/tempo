// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Deposit, DepositType, EncryptedDeposit } from "../interfaces/IZone.sol";

/// @title DepositQueueLib
/// @notice Library for managing the deposit queue hash chain
/// @dev The Tempo portal only tracks `currentDepositQueueHash` (where new deposits land).
///      The zone tracks its own `processedDepositQueueHash` in EVM state, and the proof
///      validates deposit processing by reading `currentDepositQueueHash` from Tempo state.
///
///      The queue supports both regular and encrypted deposits. The hash chain includes
///      a type discriminator to distinguish between them:
///      - Regular:   keccak256(abi.encode(DepositType.Regular, deposit, prevHash))
///      - Encrypted: keccak256(abi.encode(DepositType.Encrypted, encryptedDeposit, prevHash))
library DepositQueueLib {

    /// @notice Enqueue a regular deposit into the queue
    /// @dev Hash chain: newHash = keccak256(abi.encode(DepositType.Regular, deposit, prevHash))
    /// @param currentHash The current head of the deposit queue
    /// @param depositData The deposit to enqueue
    /// @return newHash The new head of the deposit queue
    function enqueue(
        bytes32 currentHash,
        Deposit memory depositData
    )
        internal
        pure
        returns (bytes32 newHash)
    {
        newHash = keccak256(abi.encode(DepositType.Regular, depositData, currentHash));
    }

    /// @notice Enqueue an encrypted deposit into the queue
    /// @dev Hash chain: newHash = keccak256(abi.encode(DepositType.Encrypted, encryptedDeposit, prevHash))
    /// @param currentHash The current head of the deposit queue
    /// @param encryptedDepositData The encrypted deposit to enqueue
    /// @return newHash The new head of the deposit queue
    function enqueueEncrypted(
        bytes32 currentHash,
        EncryptedDeposit memory encryptedDepositData
    )
        internal
        pure
        returns (bytes32 newHash)
    {
        newHash = keccak256(abi.encode(DepositType.Encrypted, encryptedDepositData, currentHash));
    }

}
