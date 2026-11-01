//! ABI for the experimental Attested Key Registry precompile (attested signers PoC).

pub use IAttestedKeyRegistry::{
    IAttestedKeyRegistryErrors as AttestedKeyRegistryError,
    IAttestedKeyRegistryEvents as AttestedKeyRegistryEvent,
};

crate::sol! {
    /// Attested Key Registry: policies of approved signer-program measurements and the program
    /// keys their attestation documents registered.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IAttestedKeyRegistry {
        /// @notice Emitted when a policy is created.
        event PolicyCreated(bytes32 indexed policyId, address indexed creator, uint8 scheme, address owner, address guardian, uint64 delay, uint64 maxKeyLifetime);

        /// @notice Emitted when a measurement is proposed or listed at creation.
        event MeasurementProposed(bytes32 indexed policyId, bytes32 indexed measurement, uint64 activeAt);

        /// @notice Emitted when a measurement is removed. The policy's epoch increments in the same call.
        event MeasurementRemoved(bytes32 indexed policyId, bytes32 indexed measurement, uint64 epoch);

        /// @notice Emitted when a trust anchor is proposed or listed at creation.
        event AnchorProposed(bytes32 indexed policyId, bytes32 indexed anchor, uint64 activeAt);

        /// @notice Emitted when a trust anchor is removed.
        event AnchorRemoved(bytes32 indexed policyId, bytes32 indexed anchor);

        /// @notice Emitted when a pending measurement or anchor is cancelled.
        event ProposalCancelled(bytes32 indexed policyId, bytes32 indexed entry, bool isAnchor);

        /// @notice Emitted when every program key of a policy is revoked.
        event KeysRevoked(bytes32 indexed policyId, uint64 epoch);

        /// @notice Emitted when a policy is paused or unpaused.
        event PolicyPaused(bytes32 indexed policyId, bool paused);

        /// @notice Emitted when a delay change is made or scheduled.
        event DelayChanged(bytes32 indexed policyId, uint64 newDelay, uint64 effectiveAt);

        /// @notice Emitted when a key lifetime cap change is made or scheduled.
        event MaxKeyLifetimeChanged(bytes32 indexed policyId, uint64 newMaxKeyLifetime, uint64 effectiveAt);

        /// @notice Emitted when the guardian changes.
        event GuardianChanged(bytes32 indexed policyId, address indexed previousGuardian, address indexed newGuardian);

        /// @notice Emitted when the owner changes.
        event OwnershipTransferred(bytes32 indexed policyId, address indexed previousOwner, address indexed newOwner);

        /// @notice Emitted when a program key is registered into a slot, ending the key the slot held.
        event KeyRegistered(bytes32 indexed policyId, bytes32 indexed keyId, bytes32 indexed measurement, uint8 slot, uint64 validUntil);

        /// @notice The caller lacks the role the call requires.
        error Unauthorized();
        /// @notice The policy ID already exists.
        error PolicyExists();
        /// @notice The policy does not exist.
        error PolicyNotFound();
        /// @notice The policy is paused.
        error PolicyIsPaused();
        /// @notice The scheme is unknown or not active.
        error UnknownScheme();
        /// @notice An owner argument is the zero address.
        error ZeroAddress();
        /// @notice The delay exceeds MAX_DELAY.
        error DelayTooLong();
        /// @notice A list would exceed its maximum.
        error TooManyEntries();
        /// @notice The scheme rejects the anchor, or accepts no anchors.
        error InvalidAnchor();
        /// @notice The entry is already active or pending.
        error AlreadyListed();
        /// @notice The entry is not listed.
        error NotListed();
        /// @notice The entry is not pending.
        error NotPending();
        /// @notice The program key is not a valid uncompressed P256 point.
        error InvalidProgramKey();
        /// @notice The scheme rejected the attestation document.
        error InvalidAttestation();
        /// @notice The document relied on a trust anchor that is not active.
        error AnchorNotActive();
        /// @notice The document's measurement is not active.
        error MeasurementNotActive();
        /// @notice The document is too old, too far in the future, or expired.
        error StaleAttestation();
        /// @notice The slot is not below KEY_SLOTS.
        error InvalidSlot();
        /// @notice The key lifetime cap is zero or exceeds MAX_KEY_LIFETIME.
        error InvalidKeyLifetime();

        /// @notice Creates a policy. Initial measurements and anchors are active at once.
        /// @param salt Chosen by the caller. The ID is keccak256(abi.encode(msg.sender, salt)).
        /// @param scheme The attestation scheme.
        /// @param owner Proposes entries and changes settings. Must be non-zero.
        /// @param guardian Pauses, removes, cancels, and revokes. Zero for none.
        /// @param delay Seconds before a proposal becomes active, at most MAX_DELAY.
        /// @param maxKeyLifetime Longest registration, in seconds, in [1, MAX_KEY_LIFETIME].
        /// @param measurements Initial approved measurements.
        /// @param anchors Initial trust anchors, in the scheme's format.
        /// @return policyId The new policy's ID.
        function createPolicy(
            bytes32 salt,
            uint8 scheme,
            address owner,
            address guardian,
            uint64 delay,
            uint64 maxKeyLifetime,
            bytes32[] calldata measurements,
            bytes32[] calldata anchors
        ) external returns (bytes32 policyId);

        /// @notice Returns the policy ID for a creator and salt.
        function computePolicyId(address creator, bytes32 salt) external pure returns (bytes32);

        /// @notice Proposes a measurement, active after the delay. Owner only.
        function proposeMeasurement(bytes32 policyId, bytes32 measurement) external;

        /// @notice Proposes a trust anchor, active after the delay. Owner only.
        function proposeAnchor(bytes32 policyId, bytes32 anchor) external;

        /// @notice Cancels a pending measurement or anchor. Owner or guardian.
        function cancelProposal(bytes32 policyId, bytes32 entry, bool isAnchor) external;

        /// @notice Removes a measurement and revokes every program key. Owner or guardian.
        function removeMeasurement(bytes32 policyId, bytes32 measurement) external;

        /// @notice Removes a trust anchor. Owner or guardian.
        function removeAnchor(bytes32 policyId, bytes32 anchor) external;

        /// @notice Revokes every program key of the policy. Owner or guardian.
        function revokeKeys(bytes32 policyId) external;

        /// @notice Pauses the policy. Owner or guardian.
        function pause(bytes32 policyId) external;

        /// @notice Unpauses the policy. Owner only.
        function unpause(bytes32 policyId) external;

        /// @notice Changes the delay. Increases apply at once, decreases after the current delay. Owner only.
        function setDelay(bytes32 policyId, uint64 newDelay) external;

        /// @notice Changes the key lifetime cap. Decreases apply at once, increases after the current delay. Owner only.
        function setMaxKeyLifetime(bytes32 policyId, uint64 newMaxKeyLifetime) external;

        /// @notice Replaces the guardian. Owner only.
        function setGuardian(bytes32 policyId, address newGuardian) external;

        /// @notice Replaces the owner. Owner only.
        function transferOwnership(bytes32 policyId, address newOwner) external;

        /// @notice Registers a program key into a slot from an attestation document, ending the key the slot held. Anyone can call.
        /// @param policyId The policy.
        /// @param slot The key slot, below KEY_SLOTS. The document's binding names it.
        /// @param document The attestation document, in the scheme's format.
        /// @param programKeyX The program key's x coordinate.
        /// @param programKeyY The program key's y coordinate.
        /// @param lifetime Requested seconds until expiry, capped by the policy's maxKeyLifetime. Zero for the cap.
        /// @return validUntil When the registration expires, in seconds.
        function registerKey(bytes32 policyId, uint8 slot, bytes calldata document, bytes32 programKeyX, bytes32 programKeyY, uint64 lifetime)
            external
            returns (uint64 validUntil);

        /// @notice Returns a policy's slot 0 and settings. The owner is zero if the policy does not exist.
        function policy(bytes32 policyId)
            external
            view
            returns (address owner, address guardian, uint8 scheme, bool paused, uint64 epoch, uint64 delay, uint64 pendingDelay, uint64 pendingDelayAt, uint64 maxKeyLifetime, uint64 pendingMaxKeyLifetime, uint64 pendingMaxKeyLifetimeAt);

        /// @notice Returns a measurement's activation time, or zero if absent.
        function measurementActiveAt(bytes32 policyId, bytes32 measurement) external view returns (uint64);

        /// @notice Returns an anchor's activation time, or zero if absent.
        function anchorActiveAt(bytes32 policyId, bytes32 anchor) external view returns (uint64);

        /// @notice Returns when the slot holding a program key expires, or zero if no slot holds it as current.
        function keyValidUntil(bytes32 policyId, bytes32 programKeyX, bytes32 programKeyY) external view returns (uint64);
    }
}
