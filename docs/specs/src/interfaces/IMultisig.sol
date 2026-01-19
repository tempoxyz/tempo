// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @title The interface for Multisig wallets
/// @notice M-of-N multisig wallet with on-chain confirmations
interface IMultisig {
    // ============ Events ============

    /// @notice A new transaction has been proposed
    event TransactionProposed(
        uint256 indexed txId,
        address indexed proposer,
        address indexed to,
        uint256 value,
        bytes data
    );

    /// @notice An owner has confirmed a transaction
    event TransactionConfirmed(uint256 indexed txId, address indexed owner, uint8 confirmationCount);

    /// @notice An owner has revoked their confirmation
    event ConfirmationRevoked(uint256 indexed txId, address indexed owner, uint8 confirmationCount);

    /// @notice A transaction has been executed
    event TransactionExecuted(uint256 indexed txId, address indexed executor);

    /// @notice A transaction has been cancelled
    event TransactionCancelled(uint256 indexed txId, address indexed canceller);

    /// @notice An owner was added to the multisig
    event OwnerAdded(address indexed owner);

    /// @notice An owner was removed from the multisig
    event OwnerRemoved(address indexed owner);

    /// @notice An owner was replaced with another address
    event OwnerReplaced(address indexed oldOwner, address indexed newOwner);

    /// @notice The confirmation threshold was changed
    event ThresholdChanged(uint8 oldThreshold, uint8 newThreshold);

    // ============ Errors ============

    /// @notice Caller is not an owner
    error NotOwner(address caller);

    /// @notice Caller is not the multisig itself (management functions require self-call)
    error NotMultisig();

    /// @notice Transaction does not exist
    error TransactionNotFound(uint256 txId);

    /// @notice Transaction already executed
    error TransactionAlreadyExecuted(uint256 txId);

    /// @notice Transaction has been cancelled
    error TransactionIsCancelled(uint256 txId);

    /// @notice Owner has already confirmed this transaction
    error AlreadyConfirmed(uint256 txId, address owner);

    /// @notice Owner has not confirmed this transaction
    error NotConfirmed(uint256 txId, address owner);

    /// @notice Transaction execution failed
    error ExecutionFailed(uint256 txId, bytes returnData);

    /// @notice Transaction does not have enough confirmations to execute
    error ThresholdNotMet(uint256 txId, uint8 confirmations, uint8 required);

    /// @notice Value must be zero (reserved for future use)
    error ValueNotZero();

    /// @notice Reentrancy detected
    error ReentrancyGuard();

    /// @notice The address is already an owner
    error AlreadyOwner(address owner);

    /// @notice Cannot remove: would make threshold > owner count
    error ThresholdExceedsOwners(uint8 threshold, uint8 newOwnerCount);

    /// @notice Cannot have zero owners
    error CannotRemoveLastOwner();

    /// @notice Invalid threshold (zero, or greater than owner count)
    error InvalidThreshold(uint8 threshold, uint8 ownerCount);

    /// @notice Zero address provided
    error ZeroAddressOwner();

    /// @notice Too many owners
    error TooManyOwners(uint8 count, uint8 max);

    // ============ View Functions ============

    /// @notice Returns the list of owners
    function owners() external view returns (address[] memory);

    /// @notice Returns whether an address is a current owner
    function isOwner(address addr) external view returns (bool);

    /// @notice Returns the confirmation threshold
    function threshold() external view returns (uint8);

    /// @notice Returns the current transaction count (next txId)
    function transactionCount() external view returns (uint256);

    /// @notice Returns transaction details
    function getTransaction(uint256 txId)
        external
        view
        returns (
            address to,
            uint256 value,
            bytes memory data,
            bool executed,
            bool cancelled,
            uint8 confirmations
        );

    /// @notice Returns whether an owner has confirmed a transaction
    function isConfirmedBy(uint256 txId, address owner) external view returns (bool);

    /// @notice Returns addresses that have confirmed a transaction
    function getConfirmations(uint256 txId) external view returns (address[] memory);

    /// @notice Returns the number of valid confirmations for a transaction
    /// @dev Only counts confirmations from current owners
    function getValidConfirmationCount(uint256 txId) external view returns (uint8);

    /// @notice Returns the pending txId for a proposal, or type(uint256).max if none
    function getPendingTxId(address to, uint256 value, bytes calldata data)
        external
        view
        returns (uint256);

    // ============ Transaction Functions ============

    /// @notice Proposes a new transaction or confirms an existing pending one
    /// @dev If no pending tx with same (to, value, data) exists, creates one.
    ///      If pending tx exists, adds confirmation. Auto-executes when threshold met.
    /// @param to Target address
    /// @param value Reserved for future use (must be 0)
    /// @param data Calldata for the transaction
    /// @return txId The ID of the transaction (new or existing)
    function propose(address to, uint256 value, bytes calldata data)
        external
        returns (uint256 txId);

    /// @notice Executes a transaction that has reached threshold confirmations
    /// @dev Allows execution even if caller already confirmed (fixes liveness after threshold changes)
    function execute(uint256 txId) external;

    /// @notice Revokes a confirmation for a pending transaction
    function revoke(uint256 txId) external;

    /// @notice Votes to cancel a pending transaction (requires threshold votes)
    function cancel(uint256 txId) external;

    // ============ Owner Management (self-call only) ============

    /// @notice Adds a new owner to the multisig
    /// @dev Only callable via self-call (executed transaction targeting this contract)
    function addOwner(address owner) external;

    /// @notice Removes an owner from the multisig
    /// @dev Only callable via self-call
    function removeOwner(address owner) external;

    /// @notice Replaces an existing owner with a new address
    /// @dev Only callable via self-call. Atomic swap.
    function replaceOwner(address oldOwner, address newOwner) external;

    /// @notice Changes the confirmation threshold
    /// @dev Only callable via self-call
    function changeThreshold(uint8 newThreshold) external;
}
