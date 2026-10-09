// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Deposit, DepositType, WithdrawalBounceBackDeposit } from "../interfaces/IZone.sol";

/// @title DepositQueueLib
/// @notice Library for managing the deposit queue hash chain
/// @dev The Tempo portal only tracks `currentDepositQueueHash` (where new deposits land).
///      The zone tracks its own `processedDepositQueueHash` in EVM state, and the proof
///      validates deposit processing by reading `currentDepositQueueHash` from Tempo state.
///
///      The queue supports user deposits and internal withdrawal bounce-backs. The hash
///      chain includes a type discriminator to distinguish between them:
///      - WithdrawalBounceBack: keccak256(abi.encode(DepositType.WithdrawalBounceBack, bounceBack, prevHash))
///      - Deposit:              keccak256(abi.encode(DepositType.Deposit, deposit, prevHash))
library DepositQueueLib {

    /// @notice Enqueue an internal withdrawal bounce-back into the queue
    /// @dev Hash chain: newHash = keccak256(abi.encode(DepositType.WithdrawalBounceBack, deposit, prevHash))
    /// @param currentHash The current head of the deposit queue
    /// @param depositData The deposit to enqueue
    /// @return newHash The new head of the deposit queue
    function enqueue(
        bytes32 currentHash,
        WithdrawalBounceBackDeposit memory depositData
    )
        internal
        pure
        returns (bytes32 newHash)
    {
        newHash = keccak256(abi.encode(DepositType.WithdrawalBounceBack, depositData, currentHash));
    }

    /// @notice Enqueue a user deposit
    /// @dev Hash chain: newHash = keccak256(abi.encode(DepositType.Deposit, deposit, prevHash))
    /// @param currentHash The current head of the deposit queue
    /// @param depositData The deposit to enqueue
    /// @return newHash The new head of the deposit queue
    function enqueueDeposit(
        bytes32 currentHash,
        Deposit memory depositData
    )
        internal
        pure
        returns (bytes32 newHash)
    {
        newHash = keccak256(abi.encode(DepositType.Deposit, depositData, currentHash));
    }

}
