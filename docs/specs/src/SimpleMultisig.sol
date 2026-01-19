// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @title Simple M-of-N Multisig Wallet
/// @notice Minimal multisig with propose/revoke/cancel/execute interface and auto-execution
/// @dev Single-file implementation prioritizing simplicity over features
contract SimpleMultisig {
    // ============ Constants ============

    uint8 public constant MAX_OWNERS = 50;

    /// @dev Magic bytes stored at the start of runtime code for identification
    /// @dev "MSIG" = 0x4d534947
    bytes4 public constant MULTISIG_MAGIC = 0x4d534947;

    // ============ Storage ============

    /// @dev Sorted array of owner addresses
    address[] internal _owners;

    /// @dev Mapping for O(1) owner lookup
    mapping(address => bool) internal _isOwner;

    /// @dev Owner epoch - incremented when an address loses owner status
    /// @dev Used to invalidate old confirmations if same address is re-added
    mapping(address => uint64) internal _ownerEpoch;

    /// @dev Confirmation threshold
    uint8 internal _threshold;

    /// @dev Transaction counter
    uint256 internal _transactionCount;

    /// @dev Reentrancy guard
    bool internal _locked;

    /// @dev Transaction storage
    struct Transaction {
        address to;
        uint256 value; // Reserved for future use (must be 0)
        bytes data;
        bool executed;
        bool cancelled;
    }

    mapping(uint256 => Transaction) internal _transactions;

    /// @dev Confirmations: txId => owner => epoch when confirmed (0 = not confirmed)
    mapping(uint256 => mapping(address => uint64)) internal _confirmations;

    /// @dev Cancellation votes: txId => owner => epoch when voted (0 = not voted)
    mapping(uint256 => mapping(address => uint64)) internal _cancellationVotes;

    /// @dev Proposal hash => pending txId + 1 (0 means no pending tx)
    mapping(bytes32 => uint256) internal _pendingProposals;

    // ============ Events ============

    event TransactionProposed(
        uint256 indexed txId, address indexed proposer, address indexed to, uint256 value, bytes data
    );
    event TransactionConfirmed(uint256 indexed txId, address indexed owner, uint8 confirmationCount);
    event ConfirmationRevoked(uint256 indexed txId, address indexed owner, uint8 confirmationCount);
    event TransactionExecuted(uint256 indexed txId, address indexed executor);
    event TransactionCancelled(uint256 indexed txId, address indexed canceller);
    event OwnerAdded(address indexed owner);
    event OwnerRemoved(address indexed owner);
    event OwnerReplaced(address indexed oldOwner, address indexed newOwner);
    event ThresholdChanged(uint8 oldThreshold, uint8 newThreshold);

    // ============ Errors ============

    error NotOwner(address caller);
    error NotMultisig();
    error TransactionNotFound(uint256 txId);
    error TransactionAlreadyExecuted(uint256 txId);
    error TransactionIsCancelled(uint256 txId);
    error AlreadyConfirmed(uint256 txId, address owner);
    error NotConfirmed(uint256 txId, address owner);
    error ExecutionFailed(uint256 txId, bytes returnData);
    error ReentrancyGuard();
    error AlreadyOwner(address owner);
    error ThresholdExceedsOwners(uint8 threshold, uint8 newOwnerCount);
    error CannotRemoveLastOwner();
    error InvalidThreshold(uint8 threshold, uint8 ownerCount);
    error ZeroAddressOwner();
    error TooManyOwners(uint8 count, uint8 max);
    error DuplicateOwner(address owner);
    error NoOwners();
    error ThresholdNotMet(uint256 txId, uint8 confirmations, uint8 required);
    error ValueNotZero(); // value must be 0 until future hard fork

    // ============ Modifiers ============

    modifier onlyOwner() {
        if (!_isOwner[msg.sender]) revert NotOwner(msg.sender);
        _;
    }

    modifier onlyMultisig() {
        if (msg.sender != address(this)) revert NotMultisig();
        _;
    }

    modifier nonReentrant() {
        if (_locked) revert ReentrancyGuard();
        _locked = true;
        _;
        _locked = false;
    }

    modifier txExists(uint256 txId) {
        if (txId >= _transactionCount) revert TransactionNotFound(txId);
        _;
    }

    modifier notExecuted(uint256 txId) {
        if (_transactions[txId].executed) revert TransactionAlreadyExecuted(txId);
        _;
    }

    modifier notCancelled(uint256 txId) {
        if (_transactions[txId].cancelled) revert TransactionIsCancelled(txId);
        _;
    }

    // ============ Constructor ============

    /// @notice Initializes the multisig with owners and threshold
    /// @param owners_ Array of owner addresses (will be sorted)
    /// @param threshold_ Number of required confirmations
    constructor(address[] memory owners_, uint8 threshold_) {
        if (owners_.length == 0) revert NoOwners();
        if (owners_.length > MAX_OWNERS) revert TooManyOwners(uint8(owners_.length), MAX_OWNERS);
        if (threshold_ == 0 || threshold_ > owners_.length) {
            revert InvalidThreshold(threshold_, uint8(owners_.length));
        }

        address[] memory sorted = _sortOwners(owners_);
        for (uint256 i = 0; i < sorted.length; i++) {
            address owner = sorted[i];
            if (owner == address(0)) revert ZeroAddressOwner();
            if (_isOwner[owner]) revert DuplicateOwner(owner);
            _isOwner[owner] = true;
            _ownerEpoch[owner] = 1; // Start at epoch 1 (0 means never confirmed)
            _owners.push(owner);
        }

        _threshold = threshold_;
    }

    // ============ View Functions ============

    function owners() external view returns (address[] memory) {
        return _owners;
    }

    function isOwner(address addr) external view returns (bool) {
        return _isOwner[addr];
    }

    function threshold() external view returns (uint8) {
        return _threshold;
    }

    function transactionCount() external view returns (uint256) {
        return _transactionCount;
    }

    function getTransaction(uint256 txId)
        external
        view
        txExists(txId)
        returns (address to, uint256 value, bytes memory data, bool executed, bool cancelled, uint8 confirmations)
    {
        Transaction storage txn = _transactions[txId];
        return (txn.to, txn.value, txn.data, txn.executed, txn.cancelled, _countValidConfirmations(txId));
    }

    function isConfirmedBy(uint256 txId, address owner) external view txExists(txId) returns (bool) {
        return _isValidConfirmation(txId, owner);
    }

    function getConfirmations(uint256 txId) external view txExists(txId) returns (address[] memory) {
        uint8 count = _countValidConfirmations(txId);
        address[] memory confirmers = new address[](count);
        uint256 idx = 0;
        for (uint256 i = 0; i < _owners.length && idx < count; i++) {
            if (_isValidConfirmation(txId, _owners[i])) {
                confirmers[idx++] = _owners[i];
            }
        }
        return confirmers;
    }

    function getValidConfirmationCount(uint256 txId) public view txExists(txId) returns (uint8) {
        return _countValidConfirmations(txId);
    }

    function getPendingTxId(address to, uint256 value, bytes calldata data)
        external
        view
        returns (uint256)
    {
        bytes32 hash = _proposalHash(to, value, data);
        uint256 stored = _pendingProposals[hash];
        if (stored == 0) return type(uint256).max;
        return stored - 1;
    }

    // ============ Transaction Functions ============

    /// @notice Proposes a new transaction or confirms an existing pending one
    /// @dev Auto-executes when threshold is met
    /// @param to Target address
    /// @param value Reserved for future use (must be 0)
    /// @param data Calldata for the transaction
    /// @return txId The ID of the transaction (new or existing)
    function propose(address to, uint256 value, bytes calldata data)
        external
        onlyOwner
        nonReentrant
        returns (uint256 txId)
    {
        if (value != 0) revert ValueNotZero();

        bytes32 proposalHash = _proposalHash(to, value, data);
        uint256 stored = _pendingProposals[proposalHash];

        if (stored == 0) {
            // New proposal
            txId = _transactionCount++;
            _transactions[txId] =
                Transaction({to: to, value: value, data: data, executed: false, cancelled: false});
            _pendingProposals[proposalHash] = txId + 1;

            emit TransactionProposed(txId, msg.sender, to, value, data);
        } else {
            // Existing proposal
            txId = stored - 1;
            Transaction storage txn = _transactions[txId];
            if (txn.executed) revert TransactionAlreadyExecuted(txId);
            if (txn.cancelled) revert TransactionIsCancelled(txId);
        }

        // Add confirmation if not already confirmed (with current epoch)
        if (_isValidConfirmation(txId, msg.sender)) revert AlreadyConfirmed(txId, msg.sender);
        _confirmations[txId][msg.sender] = _ownerEpoch[msg.sender];

        uint8 validConfirmations = _countValidConfirmations(txId);
        emit TransactionConfirmed(txId, msg.sender, validConfirmations);

        // Auto-execute if threshold met
        if (validConfirmations >= _threshold) {
            _execute(txId);
        }
    }

    /// @notice Executes a transaction that has reached threshold confirmations
    /// @dev Allows execution even if caller already confirmed (fixes liveness issue)
    function execute(uint256 txId)
        external
        onlyOwner
        nonReentrant
        txExists(txId)
        notExecuted(txId)
        notCancelled(txId)
    {
        uint8 validConfirmations = _countValidConfirmations(txId);
        if (validConfirmations < _threshold) {
            revert ThresholdNotMet(txId, validConfirmations, _threshold);
        }
        _execute(txId);
    }

    /// @notice Revokes a confirmation for a pending transaction
    function revoke(uint256 txId)
        external
        onlyOwner
        nonReentrant
        txExists(txId)
        notExecuted(txId)
        notCancelled(txId)
    {
        if (!_isValidConfirmation(txId, msg.sender)) revert NotConfirmed(txId, msg.sender);
        _confirmations[txId][msg.sender] = 0;

        emit ConfirmationRevoked(txId, msg.sender, _countValidConfirmations(txId));
    }

    /// @notice Votes to cancel a pending transaction (requires threshold votes)
    function cancel(uint256 txId)
        external
        onlyOwner
        nonReentrant
        txExists(txId)
        notExecuted(txId)
        notCancelled(txId)
    {
        _cancellationVotes[txId][msg.sender] = _ownerEpoch[msg.sender];

        if (_countValidCancellationVotes(txId) >= _threshold) {
            Transaction storage txn = _transactions[txId];
            txn.cancelled = true;

            // Clear pending proposal
            _pendingProposals[_proposalHash(txn.to, txn.value, txn.data)] = 0;

            emit TransactionCancelled(txId, msg.sender);
        }
    }

    // ============ Owner Management (self-call only) ============

    function addOwner(address owner) external onlyMultisig {
        if (owner == address(0)) revert ZeroAddressOwner();
        if (_isOwner[owner]) revert AlreadyOwner(owner);
        if (_owners.length >= MAX_OWNERS) revert TooManyOwners(uint8(_owners.length + 1), MAX_OWNERS);

        _insertOwnerSorted(owner);
        _isOwner[owner] = true;
        // Increment epoch so any old confirmations from previous ownership are invalid
        _ownerEpoch[owner]++;

        emit OwnerAdded(owner);
    }

    function removeOwner(address owner) external onlyMultisig {
        if (!_isOwner[owner]) revert NotOwner(owner);
        if (_owners.length == 1) revert CannotRemoveLastOwner();
        if (_threshold > _owners.length - 1) {
            revert ThresholdExceedsOwners(_threshold, uint8(_owners.length - 1));
        }

        _isOwner[owner] = false;
        _removeOwnerFromArray(owner);
        // Increment epoch so confirmations become invalid if re-added
        _ownerEpoch[owner]++;

        emit OwnerRemoved(owner);
    }

    function replaceOwner(address oldOwner, address newOwner) external onlyMultisig {
        if (!_isOwner[oldOwner]) revert NotOwner(oldOwner);
        if (newOwner == address(0)) revert ZeroAddressOwner();
        if (_isOwner[newOwner]) revert AlreadyOwner(newOwner);

        _isOwner[oldOwner] = false;
        _isOwner[newOwner] = true;
        // Increment old owner's epoch
        _ownerEpoch[oldOwner]++;
        // Increment new owner's epoch so any old confirmations are invalid
        _ownerEpoch[newOwner]++;

        _removeOwnerFromArray(oldOwner);
        _insertOwnerSorted(newOwner);

        emit OwnerReplaced(oldOwner, newOwner);
    }

    function changeThreshold(uint8 newThreshold) external onlyMultisig {
        if (newThreshold == 0 || newThreshold > _owners.length) {
            revert InvalidThreshold(newThreshold, uint8(_owners.length));
        }

        uint8 oldThreshold = _threshold;
        _threshold = newThreshold;

        emit ThresholdChanged(oldThreshold, newThreshold);
    }

    // ============ Internal Functions ============

    /// @dev Executes a transaction
    function _execute(uint256 txId) internal {
        Transaction storage txn = _transactions[txId];
        txn.executed = true;

        // Clear pending proposal
        _pendingProposals[_proposalHash(txn.to, txn.value, txn.data)] = 0;

        // Execute data call if present
        if (txn.data.length > 0) {
            (bool success, bytes memory returnData) = txn.to.call(txn.data);
            if (!success) revert ExecutionFailed(txId, returnData);
        }

        emit TransactionExecuted(txId, msg.sender);
    }

    /// @dev Computes proposal hash for deduplication
    function _proposalHash(address to, uint256 value, bytes memory data) internal pure returns (bytes32) {
        return keccak256(abi.encode(to, value, data));
    }

    /// @dev Checks if an owner's confirmation is valid (matches current epoch)
    function _isValidConfirmation(uint256 txId, address owner) internal view returns (bool) {
        uint64 confirmedEpoch = _confirmations[txId][owner];
        return confirmedEpoch != 0 && confirmedEpoch == _ownerEpoch[owner];
    }

    /// @dev Checks if an owner's cancellation vote is valid (matches current epoch)
    function _isValidCancellationVote(uint256 txId, address owner) internal view returns (bool) {
        uint64 votedEpoch = _cancellationVotes[txId][owner];
        return votedEpoch != 0 && votedEpoch == _ownerEpoch[owner];
    }

    /// @dev Counts valid confirmations from current owners only
    function _countValidConfirmations(uint256 txId) internal view returns (uint8) {
        uint8 count = 0;
        for (uint256 i = 0; i < _owners.length; i++) {
            if (_isValidConfirmation(txId, _owners[i])) count++;
        }
        return count;
    }

    /// @dev Counts valid cancellation votes from current owners only
    function _countValidCancellationVotes(uint256 txId) internal view returns (uint8) {
        uint8 count = 0;
        for (uint256 i = 0; i < _owners.length; i++) {
            if (_isValidCancellationVote(txId, _owners[i])) count++;
        }
        return count;
    }

    function _sortOwners(address[] memory owners_) internal pure returns (address[] memory) {
        uint256 n = owners_.length;
        if (n <= 1) return owners_;

        for (uint256 i = 0; i < n - 1; i++) {
            for (uint256 j = 0; j < n - i - 1; j++) {
                if (uint160(owners_[j]) > uint160(owners_[j + 1])) {
                    (owners_[j], owners_[j + 1]) = (owners_[j + 1], owners_[j]);
                }
            }
        }
        return owners_;
    }

    function _insertOwnerSorted(address owner) internal {
        uint256 i = _owners.length;
        _owners.push(owner);

        while (i > 0 && uint160(_owners[i - 1]) > uint160(owner)) {
            _owners[i] = _owners[i - 1];
            i--;
        }
        _owners[i] = owner;
    }

    function _removeOwnerFromArray(address owner) internal {
        uint256 idx = _owners.length;
        for (uint256 i = 0; i < _owners.length; i++) {
            if (_owners[i] == owner) {
                idx = i;
                break;
            }
        }

        if (idx < _owners.length) {
            for (uint256 i = idx; i < _owners.length - 1; i++) {
                _owners[i] = _owners[i + 1];
            }
            _owners.pop();
        }
    }
}
