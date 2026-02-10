// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

/// @title IValidatorConfigV2 - Validator Config V2 Precompile Interface
/// @notice Interface for managing consensus validators with append-only, delete-once semantics
/// @dev This precompile manages the set of validators that participate in consensus.
///      V2 uses an append-only design that eliminates the need for historical state access
///      during node recovery. Validators are immutable after creation and can only be deleted once.
///
///      Key differences from V1:
///      - `active` bool replaced by `addedAtHeight` and `deactivatedAtHeight`
///      - No `updateValidator` - validators are immutable after creation
///      - Requires Ed25519 signature on `addValidator` to prove key ownership
///      - Both address and public key must be unique across all validators (including deleted)
interface IValidatorConfigV2 {

    // =========================================================================
    // Errors
    // =========================================================================

    /// @notice Thrown when caller lacks authorization to perform the requested action
    error Unauthorized();

    /// @notice Thrown when trying to add a validator with an address that already exists
    error ValidatorAlreadyExists();

    /// @notice Thrown when trying to add a validator with a public key that already exists
    error PublicKeyAlreadyExists();

    /// @notice Thrown when validator is not found
    error ValidatorNotFound();

    /// @notice Thrown when trying to delete a validator that is already deleted
    error ValidatorAlreadyDeleted();

    /// @notice Thrown when public key is invalid (zero)
    error InvalidPublicKey();

    /// @notice Thrown when validator address is invalid (zero)
    error InvalidValidatorAddress();

    /// @notice Thrown when the Ed25519 signature verification fails
    error InvalidSignature();

    /// @notice Thrown when V2 is not yet initialized (writes blocked before init)
    error NotInitialized();

    /// @notice Thrown when V2 is already initialized (migration blocked after init)
    error AlreadyInitialized();

    /// @notice Thrown when migration is not complete (not all V1 validators migrated)
    error MigrationNotComplete();

    /// @notice Thrown when migration index is out of order
    error InvalidMigrationIndex();

    /// @notice Thrown when address is not in valid ip:port format
    /// @param field The field name that failed validation
    /// @param input The invalid input that was provided
    /// @param backtrace Additional error context
    error NotIpPort(string field, string input, string backtrace);

    // =========================================================================
    // Structs
    // =========================================================================

    /// @notice Validator information (V2 - append-only, delete-once)
    /// @param publicKey Ed25519 communication public key (non-zero, unique across all validators)
    /// @param validatorAddress Ethereum-style address of the validator (unique across all validators)
    /// @param ingress Address where other validators can connect (format: `<ip>:<port>`)
    /// @param egress IP address from which this validator will dial, e.g. for firewall whitelisting (format: `<ip>`)
    /// @param index Position in validators array (assigned at creation, immutable)
    /// @param addedAtHeight Block height when validator was added
    /// @param deactivatedAtHeight Block height when validator was deleted (0 = active)
    struct Validator {
        bytes32 publicKey;
        address validatorAddress;
        string ingress;
        string egress;
        uint64 index;
        uint64 addedAtHeight;
        uint64 deactivatedAtHeight;
    }

    // =========================================================================
    // State-Changing Functions
    // =========================================================================

    /// @notice Add a new validator (owner only)
    /// @dev The signature must be an Ed25519 signature over:
    ///      keccak256(abi.encodePacked("TEMPO", "_VALIDATOR_CONFIG_V2_ADD_VALIDATOR", chainId, contractAddress, validatorAddress, ingress, egress))
    ///      This proves the caller controls the private key corresponding to publicKey.
    ///      Reverts if isInitialized() returns false.
    /// @param validatorAddress The address of the new validator
    /// @param publicKey The validator's Ed25519 communication public key
    /// @param ingress The validator's inbound address `<ip>:<port>` for incoming connections
    /// @param egress The validator's outbound IP address `<ip>` for firewall whitelisting
    /// @param signature Ed25519 signature (64 bytes) proving ownership of the public key
    function addValidator(
        address validatorAddress,
        bytes32 publicKey,
        string calldata ingress,
        string calldata egress,
        bytes calldata signature
    )
        external;

    /// @notice Deactivates a validator (owner only)
    /// @dev Marks the validator as deactivated by setting deactivatedAtHeight to the current block height.
    ///      The validator's entry remains in storage for historical queries.
    ///      The public key remains reserved and cannot be reused. The address remains
    ///      reserved unless reassigned via transferValidatorOwnership.
    /// @param validatorAddress The validator address to deactivate
    function deactivateValidator(address validatorAddress) external;

    /// @notice Rotate a validator to a new identity (owner or validator only)
    /// @dev Atomically deletes the specified validator entry and adds a new one. This is equivalent
    ///      to calling deactivateValidator followed by addValidator, but executed atomically.
    ///      Can be called by the contract owner or by the validator's own address.
    ///      The same validation rules as addValidator apply:
    ///      - The new public key must not already exist
    ///      - Ingress parseable as <ip>:<port>
    ///      - Egress must be parseable as <ip>
    ///      - The signature must prove ownership of the new public key
    ///      The signature must be an Ed25519 signature over:
    ///      keccak256(abi.encodePacked("TEMPO", "_VALIDATOR_CONFIG_V2_ROTATE_VALIDATOR", chainId, contractAddress, validatorAddress, ingress, egress))
    /// @param validatorAddress The address of the validator to rotate
    /// @param publicKey The new validator's Ed25519 communication public key
    /// @param ingress The new validator's inbound address `<ip>:<port>` for incoming connections
    /// @param egress The new validator's outbound IP address `<ip>` for firewall whitelisting
    /// @param signature Ed25519 signature (64 bytes) proving ownership of the new public key
    function rotateValidator(
        address validatorAddress,
        bytes32 publicKey,
        string calldata ingress,
        string calldata egress,
        bytes calldata signature
    )
        external;

    /// @notice Update a validator's IP addresses (owner or validator only)
    /// @dev Can be called by the contract owner or by the validator's own address.
    ///      This allows validators to update their network addresses without requiring
    ///      a full rotation.
    /// @param validatorAddress The address of the validator to update
    /// @param ingress The new inbound address `<ip>:<port>` for incoming connections
    /// @param egress The new outbound IP address `<ip>` for firewall whitelisting
    function setIpAddresses(
        address validatorAddress,
        string calldata ingress,
        string calldata egress
    )
        external;

    /// @notice Transfer a validator entry to a new address (owner or validator only)
    /// @dev Can be called by the contract owner or by the validator's own address.
    ///      Updates the validator's address in the lookup maps.
    ///      Reverts if the new address already exists in the validator set.
    /// @param currentAddress The current address of the validator to transfer
    /// @param newAddress The new address to assign to the validator
    function transferValidatorOwnership(address currentAddress, address newAddress) external;

    /// @notice Transfer owner of the contract (owner only)
    /// @param newOwner The new owner address
    function transferOwnership(address newOwner) external;

    /// @notice Set the epoch at which a fresh DKG ceremony will be triggered (owner only)
    /// @param epoch The epoch in which to run the fresh DKG ceremony.
    ///        Epoch N runs the ceremony, and epoch N+1 uses the new DKG polynomial.
    function setNextFullDkgCeremony(uint64 epoch) external;

    // =========================================================================
    // View Functions
    // =========================================================================

    /// @notice Get all validators (including deleted ones) in array order
    /// @return validators Array of all validators with their information
    function getValidators() external view returns (Validator[] memory validators);

    /// @notice Get only active validators (where deactivatedAtHeight == 0)
    /// @return validators Array of active validators
    function getActiveValidators() external view returns (Validator[] memory validators);

    /// @notice Get the owner of the precompile
    /// @return The owner address
    function owner() external view returns (address);

    /// @notice Get total number of validators ever added (including deleted)
    /// @return The count of validators
    function validatorCount() external view returns (uint64);

    /// @notice Get validator information by index in the validators array
    /// @param index The index in the validators array
    /// @return The validator struct at the given index
    function validatorByIndex(uint256 index) external view returns (Validator memory);

    /// @notice Get validator information by address
    /// @param validatorAddress The validator address to look up
    /// @return The validator struct for the given address
    function validatorByAddress(address validatorAddress) external view returns (Validator memory);

    /// @notice Get validator information by public key
    /// @param publicKey The validator's public key to look up
    /// @return The validator struct for the given public key
    function validatorByPublicKey(bytes32 publicKey) external view returns (Validator memory);

    /// @notice Get the epoch at which a fresh DKG ceremony will be triggered
    /// @return The epoch number, or 0 if no fresh DKG is scheduled.
    ///         The fresh DKG ceremony runs in epoch N, and epoch N+1 uses the new DKG polynomial.
    function getNextFullDkgCeremony() external view returns (uint64);

    /// @notice Check if V2 has been initialized from V1
    /// @return True if initialized, false otherwise
    function isInitialized() external view returns (bool);

    // =========================================================================
    // Migration Functions (V1 -> V2)
    // =========================================================================

    /// @notice Migrate a single validator from V1 to V2 (owner only)
    /// @dev Can be called multiple times to migrate validators one at a time.
    ///      On first call, copies owner from V1 if V2 owner is address(0).
    ///      Active V1 validators get addedAtHeight=0 and deactivatedAtHeight=0.
    ///      Inactive V1 validators get addedAtHeight=deactivatedAtHeight=block.timestamp at migration time.
    ///      Reverts if already initialized or already migrated.
    ///      Reverts if idx != validatorsArray.length.
    ///      Reverts if `V2.isInitialized()` (no migrations after V2 is initialized).
    /// @param idx Index of the validator in V1 validators array (must equal current validatorsArray.length)
    function migrateValidator(uint64 idx) external;

    /// @notice Initialize V2 and enable reads (owner only)
    /// @dev Should only be called after all validators have been migrated via migrateValidator.
    ///      Sets initialized=true. After this call, CL reads from V2 instead of V1.
    ///      Copies nextDkgCeremony from V1.
    ///      Reverts if V2 validators count < V1 validators count (ensures all validators migrated).
    ///      Reverts if validator activity does not match between contracts:
    ///      + if `V1.active == true` then `V2.deactivatedAtHeight = 0`
    ///      + if `V1.active == false` then `V2.deactivatedAtHeight > 0`
    function initializeIfMigrated() external;

}
