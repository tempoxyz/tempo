// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.30;

// The compiled artifact is `crates/contracts/abi/TopOfBlockRegistry.json`. Regenerate it with
// `crates/contracts/solidity/build.sh` after changing this file.

/// @notice Single-owner access control with the OpenZeppelin v5 `Ownable` interface.
abstract contract Ownable {
    address private _owner;

    error OwnableUnauthorizedAccount(address account);
    error OwnableInvalidOwner(address owner);

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor(address initialOwner) {
        if (initialOwner == address(0)) revert OwnableInvalidOwner(address(0));
        _transferOwnership(initialOwner);
    }

    modifier onlyOwner() {
        if (msg.sender != _owner) revert OwnableUnauthorizedAccount(msg.sender);
        _;
    }

    function owner() public view returns (address) {
        return _owner;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert OwnableInvalidOwner(address(0));
        _transferOwnership(newOwner);
    }

    function renounceOwnership() external onlyOwner {
        _transferOwnership(address(0));
    }

    function _transferOwnership(address newOwner) internal {
        address previousOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(previousOwner, newOwner);
    }
}

/// @title Top-of-block operator registry (TIP-1147)
/// @notice Lists the operators that may stream transactions to the current leader, which
/// executes them before any pool transaction. Validators started with
/// `--consensus.top-of-block-registry <address>` read this contract at their latest finalized
/// block. The ordering is a proposer policy: blocks are verified like any other block.
contract TopOfBlockRegistry is Ownable {
    struct Operator {
        /// ed25519 public key of the operator's consensus identity.
        bytes32 publicKey;
        /// IP address the operator connects from, for example "203.0.113.7".
        string ip;
        /// Unix time in seconds after which submissions are refused; 0 never expires.
        uint64 expiresAt;
        /// Maximum number of maker slots the operator may hold in one block.
        uint32 maxTxsPerBlock;
        /// Maximum sum of gas limits over the operator's slots in one block.
        uint64 maxGasPerBlock;
    }

    /// @notice How long the builder waits for operators after the leader opens its lane.
    /// Zero disables the lane.
    uint64 public windowMs;

    Operator[] private _operators;
    /// Position of each operator in `_operators`, plus one.
    mapping(bytes32 => uint256) private _positions;

    event WindowSet(uint64 windowMs);
    event OperatorSet(
        bytes32 indexed publicKey,
        string ip,
        uint64 expiresAt,
        uint32 maxTxsPerBlock,
        uint64 maxGasPerBlock
    );
    event OperatorRemoved(bytes32 indexed publicKey);

    error InvalidOperator();
    error UnknownOperator(bytes32 publicKey);

    constructor(address initialOwner, uint64 windowMs_) Ownable(initialOwner) {
        windowMs = windowMs_;
        emit WindowSet(windowMs_);
    }

    function setWindowMs(uint64 windowMs_) external onlyOwner {
        windowMs = windowMs_;
        emit WindowSet(windowMs_);
    }

    /// @notice Adds an operator, or replaces the entry with the same public key.
    function setOperator(Operator calldata operator) external onlyOwner {
        if (
            operator.publicKey == bytes32(0) || bytes(operator.ip).length == 0
                || operator.maxTxsPerBlock == 0 || operator.maxGasPerBlock == 0
        ) revert InvalidOperator();

        uint256 position = _positions[operator.publicKey];
        if (position == 0) {
            _operators.push(operator);
            _positions[operator.publicKey] = _operators.length;
        } else {
            _operators[position - 1] = operator;
        }
        emit OperatorSet(
            operator.publicKey,
            operator.ip,
            operator.expiresAt,
            operator.maxTxsPerBlock,
            operator.maxGasPerBlock
        );
    }

    function removeOperator(bytes32 publicKey) external onlyOwner {
        uint256 position = _positions[publicKey];
        if (position == 0) revert UnknownOperator(publicKey);

        uint256 last = _operators.length;
        if (position != last) {
            Operator storage moved = _operators[last - 1];
            _operators[position - 1] = moved;
            _positions[moved.publicKey] = position;
        }
        _operators.pop();
        delete _positions[publicKey];
        emit OperatorRemoved(publicKey);
    }

    /// @notice All registered operators, including expired ones.
    function operators() external view returns (Operator[] memory) {
        return _operators;
    }
}
