// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

// Protocol-managed ZoneFactory precompile defined by TIP-1091.
address constant ZONE_FACTORY_ADDRESS = 0x5aF2000000000000000000000000000000000000;
bytes12 constant ZONE_PORTAL_PREFIX = 0x5AD000000000000000000000;
address constant ZONE_PORTAL_IMPL_ADDRESS = 0x5AD1000000000000000000000000000000000000;
address constant ZONE_VERIFIER_ADDRESS = 0x5a56000000000000000000000000000000000000;
address constant ZONE_MESSENGER_ADDRESS = 0x5A4d000000000000000000000000000000000000;

/// @notice Mutually exclusive authorization role assigned to a Tempo account.
enum Role {
    None,
    Sequencer,
    Account,
    CallbackGateway,
    PauseGuardian
}

/// @notice Independently abdicated Portal configuration surfaces.
enum Capability {
    PausePortal,
    AccessPolicy
}

/// @title IZoneToken
/// @notice Interface for the zone's zone token (TIP-20 with mint/burn for system)
interface IZoneToken {

    function mint(address to, uint256 amount) external;

    function burn(uint256 amount) external;

    function initialize(
        address admin,
        string calldata name,
        string calldata symbol,
        string calldata currency,
        address quoteToken,
        address policyAdmin
    )
        external;

    function ISSUER_ROLE() external view returns (bytes32);

    function grantRole(bytes32 role, address account) external;

    function transfer(address to, uint256 amount) external returns (bool);

    function transferFrom(address from, address to, uint256 amount) external returns (bool);

    function balanceOf(address account) external view returns (uint256);

}

/// @notice Common types for the Zone protocol
struct ZoneInfo {
    uint32 zoneId;
    address portal;
    bool accessMode; // creation-time enforcement flag; query the portal for the current value
    bool gatewayMode; // creation-time enforcement flag; query the portal for the current value
    address admin;
    address[] sequencers;
    uint8 threshold;
    address verifier;
    string rpcUrl;
}

/// @notice Block transition for zone batch proofs
/// @dev Uses block hash instead of state root to commit to full block structure
///      (includes state root, transactions root, receipts root, etc.)
struct BlockTransition {
    bytes32 prevBlockHash;
    bytes32 nextBlockHash;
}

/// @notice Deposit queue transition inputs/outputs for batch proofs
/// @dev The proof reads currentDepositQueueHash from Tempo state to validate
///      that nextProcessedHash equals currentDepositQueueHash.
///      The deposit numbers mirror the hash chain for easy status checking:
///      a deposit with number N is confirmed once lastProcessedDepositNumber >= N.
struct DepositQueueTransition {
    bytes32 prevProcessedHash; // where proof starts (verified against zone state)
    bytes32 nextProcessedHash; // where zone processed up to (proof output)
    uint64 prevDepositNumber; // deposit counter at prevProcessedHash
    uint64 nextDepositNumber; // deposit counter at nextProcessedHash
}

/// @notice Processed prefix transition for the portal's append-only enabled-token array.
struct TokenEnablementTransition {
    uint64 prevProcessedTokenCount;
    uint64 nextProcessedTokenCount;
}

/// @notice Deposit type discriminator for the unified deposit queue
/// @dev Used in hash chain: keccak256(abi.encode(depositType, depositData, prevHash))
enum DepositType {
    WithdrawalBounceBack, // Internal withdrawal bounce-back entry
    Deposit // User deposit with hidden recipient and memo
}

struct WithdrawalBounceBackDeposit {
    address token; // TIP-20 token being deposited
    address to;
    uint128 amount;
}

/*//////////////////////////////////////////////////////////////
                              DEPOSITS
//////////////////////////////////////////////////////////////*/

/// @notice Deposit payload with recipient and memo encrypted to the sequencer
/// @dev Uses ECIES with secp256k1: ephemeral ECDH + AES-256-GCM
struct DepositPayload {
    bytes32 ephemeralPubkeyX; // Ephemeral public key X coordinate (for ECDH)
    uint8 ephemeralPubkeyYParity; // Y coordinate parity (0x02 or 0x03)
    bytes ciphertext; // AES-256-GCM encrypted (to || memo || padding)
    bytes12 nonce; // GCM nonce
    bytes16 tag; // GCM authentication tag
}

/// @notice User deposit stored in the queue
/// @dev Sender, token, amount, and key index are public; recipient and memo are encrypted.
///      The token identity is public because the portal must escrow the correct token.
///      The keyIndex specifies which encryption key the user used, allowing the prover
///      to look up the correct key for decryption even after key rotations.
struct Deposit {
    address token; // TIP-20 token being deposited (public, for escrow accounting)
    address sender; // Depositor (public, for refunds)
    uint128 amount; // Amount (public, for accounting)
    address tempoRefundRecipient; // Tempo recipient for a failed-deposit refund
    uint256 keyIndex; // Index of encryption key used (specified by depositor)
    DepositPayload encrypted; // Encrypted (to, memo)
}

/// @notice Historical record of an encryption key with its activation block
/// @dev Storage layout per entry (2 slots):
///      slot 0: x (bytes32) — full slot
///      slot 1: yParity (uint8, lowest byte) | activationBlock (uint64, next 8 bytes)
///      WARNING: Do not reorder fields. ZoneInbox._readEncryptionKey() and
///      ZoneInbox._readEncryptionKey() reads these via raw storage slot access.
struct EncryptionKeyEntry {
    bytes32 x; // X coordinate of the public key
    uint8 yParity; // Y coordinate parity (0x02 or 0x03)
    uint64 activationBlock; // Tempo block number when this key became active
}

// Grace period after key rotation during which old keys are still accepted.
// After this period, deposits using the old key are rejected.
// 1 day at 1 second block time = 86400 blocks
uint64 constant ENCRYPTION_KEY_GRACE_PERIOD = 86_400;

/*//////////////////////////////////////////////////////////////
                    UNIFIED DEPOSIT QUEUE TYPES
//////////////////////////////////////////////////////////////*/

/// @notice A deposit entry in the unified queue (for zone-side processing)
/// @dev Used by the sequencer when calling advanceTempo with mixed deposit types.
///      The depositData is ABI-encoded WithdrawalBounceBackDeposit or Deposit depending on type.
struct QueuedDeposit {
    DepositType depositType;
    bytes depositData; // abi.encode(WithdrawalBounceBackDeposit) or abi.encode(Deposit)
    bool rejected;
}

/// @notice Chaum-Pedersen proof for ECDH shared secret derivation
/// @dev Proves knowledge of privSeq such that:
///      - pubSeq = privSeq * G (sequencer's key pair)
///      - sharedSecretPoint = privSeq * ephemeralPub (ECDH computation)
///      Uses Fiat-Shamir heuristic for non-interactive proof.
struct ChaumPedersenProof {
    bytes32 s; // Response: s = r + c * privSeq (mod n)
    bytes32 c; // Challenge: c = hash(G, ephemeralPub, pubSeq, sharedSecretPoint, R1, R2)
}

/// @notice Decryption data provided by the sequencer for deposits
/// @dev Must match 1:1 with user deposits in the queue (in order of appearance).
///      Includes a Chaum-Pedersen proof to verify the shared secret was correctly derived
///      without exposing the sequencer's private key.
///      The sequencer's public key is looked up from the deposit's keyIndex on-chain,
///      so it does not need to be included here.
///      The decrypted (to, memo) are derived on-chain from the AES-GCM decryption and
///      do not need to be supplied by the sequencer.
struct DecryptionData {
    bytes32 sharedSecret; // ECDH shared secret (x-coordinate of privSeq * ephemeralPub)
    uint8 sharedSecretYParity; // Y coordinate parity of the shared secret point (0x02 or 0x03)
    ChaumPedersenProof cpProof; // Proof of correct shared secret derivation
}

/// @notice Token to be activated directly by the ZoneInbox
struct EnabledToken {
    address token;
    string name;
    string symbol;
    string currency;
}

// Default quote token for zone TIP-20 activation.
address constant PATH_USD_ADDRESS = 0x20C0000000000000000000000000000000000000;

// Maximum callback gas a withdrawal may request.
// The processor adds fixed overhead, so this value keeps the outer
// `processWithdrawals` transaction well below a 30M gas L1 block
// limit.
uint64 constant MAX_WITHDRAWAL_CALLBACK_GAS = 10_000_000;

struct Withdrawal {
    address token; // TIP-20 token being withdrawn
    bytes32 senderTag; // keccak256(abi.encodePacked(sender, txHash, fallbackNonce))
    address to; // Tempo recipient
    uint128 amount; // amount to send to recipient (excludes fee)
    bytes32 memo; // user-provided context
    uint64 gasLimit; // max gas for IWithdrawalReceiver callback (0 = no callback)
    uint64 fallbackNonce; // resolves to the zone bounce-back recipient in ZoneOutbox
    bytes callbackData; // calldata for IWithdrawalReceiver (if gasLimit > 0)
    bytes encryptedSender; // optional encrypted (sender, txHash) reveal payload
}

struct PendingWithdrawal {
    address token; // TIP-20 token being withdrawn
    address sender; // who initiated the withdrawal on the zone
    bytes32 txHash; // hash of the zone transaction that requested the withdrawal
    address to; // Tempo recipient
    uint128 amount; // amount to send to recipient (excludes fee)
    bytes32 memo; // user-provided context
    uint64 gasLimit; // max gas for IWithdrawalReceiver callback (0 = no callback)
    uint64 fallbackNonce; // resolves to the zone bounce-back recipient in ZoneOutbox
    bytes callbackData; // calldata for IWithdrawalReceiver (if gasLimit > 0)
    bytes revealTo; // optional compressed secp256k1 pubkey for sender reveal encryption
}

/*//////////////////////////////////////////////////////////////
                    ZONE SYSTEM CONTRACTS
//////////////////////////////////////////////////////////////*/

// TempoState predeploy address (0x1c00...0000)
address constant TEMPO_STATE = 0x1C00000000000000000000000000000000000000;

// ZoneInbox system contract address (0x1c00...0001)
address constant ZONE_INBOX = 0x1c00000000000000000000000000000000000001;

// ZoneOutbox system contract address (0x1c00...0002)
address constant ZONE_OUTBOX = 0x1c00000000000000000000000000000000000002;

/*//////////////////////////////////////////////////////////////
                ZONE PORTAL STORAGE SLOT CONSTANTS
//////////////////////////////////////////////////////////////*/

// ZonePortal storage layout:
//   slot 0: admin (address)
//   slot 1: zoneGasRate (uint128) + withdrawalBatchIndex (uint64) [packed]
//   slot 2: blockHash (bytes32)
//   slot 3: currentDepositQueueHash (bytes32)
//   slot 4: depositCount (uint64) + lastProcessedDepositNumber (uint64)
//           + lastSyncedTempoBlockNumber (uint64) + bouncebackGas (uint64) [packed]
//   slot 5: _encryptionKeys (EncryptionKeyEntry[])
//   slot 6: _tokenConfigs (mapping(address => TokenConfig))
//   slot 7: _enabledTokens (address[])
//   slot 8: refunds (mapping(address => mapping(address => uint128)))
//   slot 9: _withdrawalQueue.head
//   slot 10: _withdrawalQueue.tail
//   slot 11: _withdrawalQueue.slots (mapping(uint256 => bytes32))
//   slot 12: rpcUrl (string)
//   slot 13: pendingAdmin (address)
//   slot 14: _withdrawalReentrancyStatus (uint256)
//   slot 15: zoneId (uint32) + messenger (address) [packed]
//   slot 16: verifier (address) + _initialized (bool) + sequencerSetVersion (uint64)
//            + sequencerThreshold (uint8) [packed]
//   slot 17: zoneHeight (uint256)
//   slot 18: _sequencers (address[])
//   slot 19: _reservedSlot19 (available for future use)
//   slot 20: role (mapping(address => Role))
//   slot 21: _isAccessEnforced (bool) + _isGatewayEnforced (bool) [packed]
//   slot 22: maxTempoGasRate (uint128)
//   slot 23: leader (address) + leaderEpoch (uint64) [packed]
//   slot 24: leaderActivationTempoBlock (uint64) + _depositCountBlock (uint64)
//            + _depositsInCurrentBlock (uint64) + _tokenEnableCountBlock (uint64) [packed]
//   slot 25: _tokensEnabledInCurrentBlock (uint64) + pauseExpiry (uint64) [packed]
//   slot 26: tokenEnablementHash (bytes32)
//   slot 27: abdicationEffectiveAt (mapping(Capability => uint64))
//
// These constants are the single source of truth for cross-domain reads.
// ZoneInbox and ZoneOutbox use them to read portal state via
// TempoState.readTempoStorageSlot(). If the portal layout changes,
// update these constants and the vm.load regression tests will catch mismatches.
bytes32 constant PORTAL_ADMIN_SLOT = bytes32(uint256(0));
bytes32 constant PORTAL_CURRENT_DEPOSIT_QUEUE_HASH_SLOT = bytes32(uint256(3));
bytes32 constant PORTAL_ENCRYPTION_KEYS_SLOT = bytes32(uint256(5));
bytes32 constant PORTAL_TOKEN_CONFIGS_SLOT = bytes32(uint256(6));
bytes32 constant PORTAL_ENABLED_TOKENS_SLOT = bytes32(uint256(7));
bytes32 constant PORTAL_TOKEN_ENABLEMENT_HASH_SLOT = bytes32(uint256(26));
bytes32 constant PORTAL_PENDING_ADMIN_SLOT = bytes32(uint256(13));
bytes32 constant PORTAL_ROLE_SLOT = bytes32(uint256(20));
bytes32 constant PORTAL_ENFORCEMENT_MODES_SLOT = bytes32(uint256(PORTAL_ROLE_SLOT) + 1);
bytes32 constant PORTAL_MAX_TEMPO_GAS_RATE_SLOT =
    bytes32(uint256(PORTAL_ENFORCEMENT_MODES_SLOT) + 1);
bytes32 constant PORTAL_ACCESS_MODE_SLOT = PORTAL_ENFORCEMENT_MODES_SLOT;
bytes32 constant PORTAL_GATEWAY_MODE_SLOT = PORTAL_ENFORCEMENT_MODES_SLOT;
bytes32 constant PORTAL_LEADER_SLOT = bytes32(uint256(PORTAL_MAX_TEMPO_GAS_RATE_SLOT) + 1);
bytes32 constant PORTAL_PAUSE_SLOT = bytes32(uint256(25));
bytes32 constant PORTAL_LEADER_ACTIVATION_TEMPO_BLOCK_SLOT =
    bytes32(uint256(PORTAL_LEADER_SLOT) + 1);

/// @title IVerifier
/// @notice Interface for zone proof/attestation verification
interface IVerifier {

    /// @notice Verify a batch proof
    /// @dev The proof validates:
    ///      1. Valid state transition from prevBlockHash to nextBlockHash
    ///      2. Zone committed to tempoBlockNumber (via TempoState)
    ///      3. If anchorBlockNumber == tempoBlockNumber: zone's hash matches anchorBlockHash
    ///      4. If anchorBlockNumber > tempoBlockNumber: ancestry chain from tempoBlockNumber to anchorBlockNumber
    ///      5. ZoneOutbox.lastBatch().withdrawalBatchIndex == expectedWithdrawalBatchIndex
    ///      6. ZoneOutbox.lastBatch().withdrawalQueueHash matches withdrawalQueueHash
    ///      7. Deposit processing is correct (validated via Tempo state read inside proof)
    ///      8. The final executed Zone block number equals nextZoneHeight
    /// @param zoneId Unique identifier of the zone whose batch is being verified
    /// @param tempoBlockNumber Block zone committed to (from TempoState)
    /// @param anchorBlockNumber Block whose hash is verified (tempoBlockNumber or recent block)
    /// @param anchorBlockHash Hash of anchorBlockNumber (from EIP-2935)
    /// @param expectedWithdrawalBatchIndex Expected batch index (portal.withdrawalBatchIndex + 1)
    /// @param nextZoneHeight Number of the final executed Zone block
    /// @param blockTransition Zone block hash transition
    /// @param depositQueueTransition Deposit queue processing transition
    /// @param withdrawalQueueHash Withdrawal queue hash chain for this batch (0 if none)
    /// @param verifierConfig Opaque payload for verifier (TEE attestation envelope, etc.)
    /// @param proof Validity proof or TEE attestation
    function verify(
        uint32 zoneId,
        uint64 tempoBlockNumber,
        uint64 anchorBlockNumber,
        bytes32 anchorBlockHash,
        uint64 expectedWithdrawalBatchIndex,
        uint256 nextZoneHeight,
        BlockTransition calldata blockTransition,
        DepositQueueTransition calldata depositQueueTransition,
        TokenEnablementTransition calldata tokenEnablementTransition,
        bytes32 withdrawalQueueHash,
        bytes calldata verifierConfig,
        bytes calldata proof
    )
        external
        view
        returns (bool);

}

/// @title IZoneFactory
/// @notice Interface for creating zones
interface IZoneFactory {

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    struct CreateZoneParams {
        address initialToken; // first TIP-20 to enable (admin can enable more later)
        bool accessMode; // whether to initially enforce the account allowlist
        bool gatewayMode; // whether to initially enforce callback gateway registration
        address[] allowedAccounts; // initial account allowlist (retained while access is open)
        address[] zoneGateways; // initial withdrawal-and-call implementations
        address admin;
        address[] sequencers;
        uint8 threshold;
        string rpcUrl;
    }

    event ZoneCreated(
        uint32 indexed zoneId,
        address indexed portal,
        address initialToken,
        bool accessMode,
        bool gatewayMode,
        address admin,
        address[] sequencers,
        uint8 threshold,
        address verifier
    );

    error InvalidToken();
    error NotOwner();
    error InvalidAdmin();
    error InvalidSequencerSet();
    error InvalidClosedLoopConfig();
    error DuplicateAllowedAccount();
    error DuplicateZoneGateway();

    /// @notice Returns the account authorized to create zones.
    function owner() external view returns (address);

    /// @notice Transfers zone-creation authority to `newOwner`.
    function transferOwnership(address newOwner) external;

    /// @notice Creates a new zone and deploys its portal contract.
    /// @param params The initial token, admin, sequencer set, threshold, and RPC URL.
    /// @return zoneId The newly assigned zone ID.
    /// @return portal The deployed portal address for the new zone.
    function createZone(CreateZoneParams calldata params)
        external
        returns (uint32 zoneId, address portal);

    /// @notice Returns the next zone ID that will be assigned.
    function nextZoneId() external view returns (uint32);

    /// @notice Returns the stored metadata for a zone.
    function zones(uint32 id) external view returns (ZoneInfo memory info);

    /// @notice Returns whether an address is a portal deployed by this factory.
    /// @param portal The portal address to check.
    /// @return isPortal True if `portal` was created by this factory.
    function isZonePortal(address portal) external view returns (bool);

}

/// @notice Per-token configuration in the portal's token registry
/// @dev enabled is permanent (write-once true); depositsActive can be toggled by admin.
///      Once enabled, withdrawals can never be disabled (non-custodial guarantee).
struct TokenConfig {
    bool enabled; // true once admin enables this token (permanent, irreversible)
    bool depositsActive; // admin can pause/unpause deposits; does not affect withdrawals
}

/// @title IZonePortal
/// @notice Interface for zone portal on Tempo
interface IZonePortal {

    /// @notice Emitted after a batch is accepted by `submitBatch`.
    /// @dev `withdrawalQueueIndex` is the logical (non-wrapping) withdrawal queue index the
    ///      batch's hash chain was enqueued under, or `NO_QUEUE_INDEX` (`type(uint256).max`)
    ///      when the batch carried no withdrawals. Indexed so off-chain recovery can query
    ///      the event for a specific logical index instead of counting events positionally.
    event BatchSubmitted(
        uint64 indexed withdrawalBatchIndex,
        uint256 indexed withdrawalQueueIndex,
        bytes32 nextProcessedDepositQueueHash,
        bytes32 nextBlockHash,
        bytes32 withdrawalQueueHash,
        uint64 lastProcessedDepositNumber,
        uint64 lastProcessedEnabledTokenCount
    );

    event WithdrawalProcessed(
        address indexed to,
        bytes32 indexed senderTag,
        address token,
        uint128 amount,
        bool callbackSuccess
    );

    event WithdrawalBounceBack(
        bytes32 indexed newCurrentDepositQueueHash,
        uint64 indexed fallbackNonce,
        address token,
        uint128 amount,
        uint64 depositNumber
    );

    /// @notice Emitted when the current admin nominates a new admin (two-step transfer).
    /// @dev A `newAdmin` of address(0) signals cancellation of a pending transfer.
    event AdminTransferStarted(address indexed currentAdmin, address indexed pendingAdmin);
    /// @notice Emitted when a pending admin accepts and the admin role is handed over.
    event AdminTransferred(address indexed previousAdmin, address indexed newAdmin);

    /// @notice Emitted when a deposit is made (recipient/memo not revealed)
    event DepositMade(
        bytes32 indexed newCurrentDepositQueueHash,
        address indexed sender,
        address token,
        uint128 netAmount,
        uint128 fee,
        uint256 keyIndex,
        bytes32 ephemeralPubkeyX,
        uint8 ephemeralPubkeyYParity,
        bytes ciphertext,
        bytes12 nonce,
        bytes16 tag,
        address tempoRefundRecipient,
        uint64 depositNumber
    );

    event DepositBounceBack(
        address indexed tempoRefundRecipient, address token, uint128 amount, uint128 bouncebackFee
    );

    event DepositBounceBackPending(
        address indexed tempoRefundRecipient, address token, uint128 amount, uint128 bouncebackFee
    );

    /// @notice Emitted when a recipient claims a previously-parked bounce-back refund.
    event RefundClaimed(address indexed recipient, address indexed token, uint128 amount);

    /// @notice Emitted when sequencer updates their encryption key
    /// @param x The X coordinate of the new key
    /// @param yParity The Y coordinate parity (0x02 or 0x03)
    /// @param pubkey The address derived from the new key
    /// @param keyIndex The index of this key in the history array
    /// @param activationBlock The Tempo block when this key becomes active
    event SequencerEncryptionKeyUpdated(
        bytes32 x, uint8 yParity, address pubkey, uint256 keyIndex, uint64 activationBlock
    );
    event ZoneGasRateUpdated(uint128 zoneGasRate);
    event MaxTempoGasRateUpdated(uint128 maxTempoGasRate);
    event BouncebackGasUpdated(uint64 bouncebackGas);

    /// @notice Emitted when admin enables a new TIP-20 token for bridging
    event TokenEnabled(address indexed token, string name, string symbol, string currency);

    /// @notice Emitted when admin pauses deposits for a token
    event DepositsPaused(address indexed token);

    /// @notice Emitted when admin resumes deposits for a token
    event DepositsResumed(address indexed token);

    /// @notice Emitted when deposits and withdrawal processing are paused.
    event PortalPaused(address indexed account);

    /// @notice Emitted when the admin resumes deposits and withdrawal processing early.
    event PortalResumed(address indexed account);

    /// @notice Emitted when the admin schedules permanent abdication of a capability.
    event AbdicationScheduled(Capability indexed capability, uint64 effectiveAt);

    /// @notice Emitted when the sequencer updates the zone's operator RPC endpoint
    event RpcUrlUpdated(string rpcUrl);

    /// @notice Emitted when the admin replaces the batch-attestation signer set.
    event SequencerSetUpdated(uint64 indexed nonce, uint8 threshold, address[] sequencers);

    /// @notice Emitted when block-production leadership transitions to a new sequencer.
    /// @dev Zone nodes derive leadership exclusively from finalized observations of this event.
    /// @param previousLeader The leader being replaced (address(0) at initialization).
    /// @param newLeader The individual sequencer address taking over block production.
    /// @param epoch The new monotonic leadership epoch.
    /// @param activationTempoBlock The Tempo block that recorded the transition.
    event LeaderUpdated(
        address indexed previousLeader,
        address indexed newLeader,
        uint64 indexed epoch,
        uint64 activationTempoBlock
    );

    /// @notice Emitted when the independently mutable enforcement flags are initialized or updated.
    event EnforcementModesUpdated(bool accessMode, bool gatewayMode);

    error NotSequencer();
    error NotAdmin();
    error NotPauseAuthority();
    error CapabilityAbdicated(Capability capability);
    error AbdicationAlreadyScheduled(Capability capability);
    error PortalIsPaused();
    error NotFactory();
    error NotSelf();
    error AlreadyInitialized();
    error MustDelegateCall();
    error NotPendingAdmin();
    error InvalidProof();
    error InvalidTempoBlockNumber();
    error CallbackRejected();
    error TransferFailed();
    error ReentrantWithdrawal();
    error EncryptionKeyExpired(uint256 keyIndex, uint64 activationBlock, uint64 supersededAtBlock);
    error InvalidEncryptionKeyIndex(uint256 keyIndex);
    error NoEncryptionKeySet();
    error NoEncryptionKeyAtBlock(uint64 blockNumber);
    error InvalidEphemeralPubkey();
    error InvalidCiphertextLength(uint256 actual, uint256 expected);
    error InvalidProofOfPossession();
    error DepositTooSmall();
    error DepositBlockCapacityExceeded(uint64 maximum);
    error TokenEnablementBlockCapacityExceeded(uint64 maximum);
    error TokenMetadataTooLong();
    error GasFeeRateTooHigh();
    error TokenNotEnabled();
    error DepositsNotActive();
    error TokenAlreadyEnabled();
    error TokenTransferPolicyNotSet();
    error TokenEnablementCursorNotInitialized();
    error InvalidBouncebackRecipient();
    error InvalidDepositTransition();
    error InvalidTokenEnablementTransition();
    error InvalidSequencerSet();
    error SequencerConfigurationUnchanged();
    error InvalidLeader();
    error ActiveLeaderRemoved();
    error LeaderAlreadyUpdatedThisBlock();
    error StaleLeadershipEpoch(uint64 expected, uint64 actual);
    error InvalidQuorumCertificate();
    error InvalidCallbackTarget();
    error CallbackDidNotReturnToZone();
    error AccountNotAllowed(address account);
    /// @notice Emitted when an account's portal role is initialized or updated.
    event RoleUpdated(address indexed account, Role prev, Role next);

    function initialize(
        uint32 zoneId,
        address initialToken,
        bool accessMode,
        bool gatewayMode,
        address[] calldata allowedAccounts,
        address[] calldata zoneGateways,
        address messenger,
        address admin,
        address[] calldata sequencers,
        uint8 threshold,
        address verifier,
        string calldata rpcUrl
    )
        external;

    /// @notice Fixed gas value for deposit fee calculation (100,000 gas)
    function FIXED_DEPOSIT_GAS() external view returns (uint64);

    /// @notice Maximum deposits that may remain outstanding on this portal.
    function MAX_UNPROCESSED_DEPOSITS() external view returns (uint64);

    /// @notice Maximum token enablements that may remain outstanding on this portal.
    function MAX_UNPROCESSED_TOKEN_ENABLEMENTS() external view returns (uint64);

    /// @notice Maximum byte length accepted for each bridged token metadata string.
    function MAX_TOKEN_METADATA_BYTES() external view returns (uint256);

    /// @notice Maximum callback gas accepted for withdrawals
    function MAX_WITHDRAWAL_GAS_LIMIT() external view returns (uint64);

    /// @notice Maximum allowed gas fee rate (1e18)
    function MAX_GAS_FEE_RATE() external view returns (uint128);

    function zoneId() external view returns (uint32);

    /// @notice Fixed callback messenger assigned during portal initialization.
    function messenger() external view returns (address);

    /// @notice Whether account allowlist enforcement is enabled.
    function isAccessEnforced() external view returns (bool);

    /// @notice Change account allowlist enforcement. Only callable by the admin.
    function setAccessMode(bool enforced) external;

    /// @notice Whether callback gateway registration enforcement is disabled.
    function isGatewayOpen() external view returns (bool);

    /// @notice Change callback gateway enforcement. Only callable by the admin.
    function setGatewayMode(bool enforced) external;

    /// @notice Whether an account has a Portal role.
    function hasRole(address account, Role role) external view returns (bool);

    /// @notice Add or remove an account from closed-loop portal flows.
    function setAllowedAccount(address account, bool allowed) external;

    /// @notice Add or remove a callback gateway.
    function setGateway(address account, bool allowed) external;

    /// @notice Add or remove a pause guardian.
    function setPauseGuardian(address account, bool allowed) external;

    function admin() external view returns (address);

    function pendingAdmin() external view returns (address);

    function zoneGasRate() external view returns (uint128);

    function maxTempoGasRate() external view returns (uint128);

    function bouncebackGas() external view returns (uint64);

    function verifier() external view returns (address);

    function withdrawalBatchIndex() external view returns (uint64);

    function blockHash() external view returns (bytes32);

    function currentDepositQueueHash() external view returns (bytes32);

    function depositCount() external view returns (uint64);

    function lastProcessedDepositNumber() external view returns (uint64);

    function lastSyncedTempoBlockNumber() external view returns (uint64);

    function withdrawalQueueHead() external view returns (uint256);

    function withdrawalQueueTail() external view returns (uint256);

    function withdrawalQueueSlot(uint256 queueIndex) external view returns (bytes32);

    /// @notice Configuration nonce for the active sequencer set and threshold.
    function sequencerSetVersion() external view returns (uint64);

    /// @notice Number of distinct registered signatures required for batch settlement.
    function sequencerThreshold() external view returns (uint8);

    /// @notice Highest zone block height accepted with a quorum certificate.
    function zoneHeight() external view returns (uint256);

    /// @notice Whether an account belongs to the active settlement signer set.
    function isSequencer(address account) external view returns (bool);

    /// @notice Number of accounts in the active settlement signer set.
    function sequencerCount() external view returns (uint256);

    /// @notice Return a signer-set member by index.
    function sequencerAt(uint256 index) external view returns (address);

    /// @notice Individual sequencer address of the active block-producing leader.
    function leader() external view returns (address);

    /// @notice Monotonic fencing epoch, incremented exactly once per real leader change.
    function leaderEpoch() external view returns (uint64);

    /// @notice Tempo block number that recorded the most recent leader transition.
    function leaderActivationTempoBlock() external view returns (uint64);

    /// @notice Transfer block-production leadership to another sequencer-set member.
    /// @dev Only callable by the admin or an active sequencer. A call naming the already-active
    ///      leader is a successful no-op so operators can fan the same request out to every node.
    /// @param newLeader The individual sequencer address of the new leader.
    /// @param expectedEpoch The finalized leaderEpoch the caller observed (compare-and-set).
    function setLeader(address newLeader, uint64 expectedEpoch) external;

    /*//////////////////////////////////////////////////////////////
                          TOKEN REGISTRY
    //////////////////////////////////////////////////////////////*/

    /// @notice Check if a token is enabled for bridging (permanent once enabled)
    function isTokenEnabled(address token) external view returns (bool);

    /// @notice Check if deposits are currently active for a token
    function areDepositsActive(address token) external view returns (bool);

    /// @notice Get the token configuration for a specific token
    function tokenConfig(address token) external view returns (TokenConfig memory);

    /// @notice Get the number of enabled tokens
    function enabledTokenCount() external view returns (uint256);

    /// @notice Get the number of enabled tokens confirmed as processed by submitted batches
    function lastProcessedEnabledTokenCount() external view returns (uint64);

    /// @notice Whether the processed enabled-token cursor has been initialized
    function tokenEnablementCursorInitialized() external view returns (bool);

    /// @notice Get an enabled token by index
    function enabledTokenAt(uint256 index) external view returns (address);

    /// @notice Append-only commitment to enabled token addresses and metadata
    function tokenEnablementHash() external view returns (bytes32);

    /// @notice Whether new deposits and withdrawal processing are paused.
    function paused() external view returns (bool);

    /// @notice Timestamp at which the current Portal pause expires.
    function pauseExpiry() external view returns (uint64);

    /// @notice Timestamp at which permanent abdication of a capability takes effect.
    function abdicationEffectiveAt(Capability capability) external view returns (uint64);

    /// @notice Pause deposits and withdrawal processing for 30 days.
    function pause() external;

    /// @notice Resume deposits and withdrawal processing before the pause expires.
    function resume() external;

    /// @notice Schedule permanent abdication of a Portal capability. Only callable by admin.
    function abdicate(Capability capability) external;

    /// @notice Enable another TIP-20 token for bridging. Only callable by admin.
    /// @dev Irreversible: once enabled, a token cannot be disabled.
    /// @notice Enable a token after a Zone batch authenticates the enabled-token cursor.
    function enableToken(address token) external;

    /// @notice Pause deposits for a token. Only callable by admin.
    /// @dev Does not affect withdrawal processing (non-custodial guarantee).
    function pauseDeposits(address token) external;

    /// @notice Resume deposits for a token. Only callable by admin.
    function resumeDeposits(address token) external;

    /// @notice The zone's operator RPC endpoint
    /// @return The stored RPC URL, or empty string if unset
    function rpcUrl() external view returns (string memory);

    /// @notice Update the zone's operator RPC endpoint. Only callable by sequencer.
    /// @param rpcUrl The new RPC URL (may be empty to clear it)
    function setRpcUrl(string calldata rpcUrl) external;

    /// @notice Atomically replace the sequencer set and settlement threshold. Only callable by admin.
    /// @dev Signers must be nonzero and unique; their order has no protocol meaning.
    function setSequencerSet(address[] calldata sequencers, uint8 threshold) external;

    /// @notice Start an admin transfer. Only callable by the current admin.
    /// @param newAdmin The address that will become admin after accepting (address(0) cancels).
    function transferAdmin(address newAdmin) external;

    /// @notice Accept a pending admin transfer. Only callable by the pending admin.
    function acceptAdmin() external;

    /// @notice Get the sequencer's current encryption public key for deposits
    /// @return x The X coordinate of the secp256k1 public key
    /// @return yParity The Y coordinate parity (0x02 or 0x03)
    /// @return pubkey The address derived from the public key
    function sequencerEncryptionKey()
        external
        view
        returns (bytes32 x, uint8 yParity, address pubkey);

    /// @notice Set the sequencer's encryption public key. Only callable by an active sequencer or admin.
    /// @dev Appends to key history. The new key becomes active at the current Tempo block.
    /// @param x The X coordinate of the secp256k1 public key
    /// @param yParity The Y coordinate parity (0x02 or 0x03)
    /// @param popV Recovery id of the proof-of-possession signature
    /// @param popR R component of the proof-of-possession signature
    /// @param popS S component of the proof-of-possession signature
    function setSequencerEncryptionKey(
        bytes32 x,
        uint8 yParity,
        uint8 popV,
        bytes32 popR,
        bytes32 popS
    )
        external;

    /// @notice Get the number of encryption keys in the history
    /// @return The total count of keys (including current)
    function encryptionKeyCount() external view returns (uint256);

    /// @notice Get a historical encryption key by index
    /// @param index The index in the key history (0 = first key)
    /// @return entry The key entry with activation block
    function encryptionKeyAt(uint256 index) external view returns (EncryptionKeyEntry memory entry);

    /// @notice Get the encryption key that was active at a specific Tempo block
    /// @dev Binary search through key history to find the correct key
    /// @param tempoBlockNumber The Tempo block number to query
    /// @return x The X coordinate of the active key
    /// @return yParity The Y coordinate parity
    /// @return keyIndex The index of this key in history
    function encryptionKeyAtBlock(uint64 tempoBlockNumber)
        external
        view
        returns (bytes32 x, uint8 yParity, uint256 keyIndex);

    /// @notice Set zone gas rate. Only callable by admin.
    /// @param _zoneGasRate Zone token units per gas unit on the zone
    function setZoneGasRate(uint128 _zoneGasRate) external;

    /// @notice Set the maximum Tempo gas rate a sequencer may configure on the zone.
    /// @param _maxTempoGasRate Maximum zone token units per gas unit on Tempo
    function setMaxTempoGasRate(uint128 _maxTempoGasRate) external;

    /// @notice Set the gas amount used to price failed-deposit bounce-backs on Tempo.
    /// @dev Only callable by admin.
    /// @param _bouncebackGas Gas amount used in the Tempo-side bounce-back fee calculation
    function setBouncebackGas(uint64 _bouncebackGas) external;

    /// @notice Calculate the fee for a deposit
    function calculateDepositFee() external view returns (uint128 fee);

    /// @notice Calculate the reserved Tempo-side fee for a failed-deposit bounce-back
    function calculateBouncebackFee() external view returns (uint128 fee);

    /// @notice Check if an encryption key is still valid for new deposits
    /// @dev A key is valid if it's the current key OR if it was superseded less than
    ///      ENCRYPTION_KEY_GRACE_PERIOD blocks ago
    /// @param keyIndex The key index to check
    /// @return valid True if the key can be used for new deposits
    /// @return expiresAtBlock Block number when this key expires (0 if current key, never expires)
    function isEncryptionKeyValid(uint256 keyIndex)
        external
        view
        returns (bool valid, uint64 expiresAtBlock);

    /// @notice Alias for `depositEncrypted`.
    /// @dev This entrypoint accepts only encrypted recipient and memo data and emits
    ///      `DepositMade`.
    function deposit(
        address token,
        uint128 amount,
        uint256 keyIndex,
        DepositPayload calldata encrypted,
        address tempoRefundRecipient
    )
        external
        returns (bytes32 newCurrentDepositQueueHash);

    /// @notice Deposit with encrypted recipient and memo
    /// @dev The encrypted payload contains (to, memo) encrypted to the sequencer's key
    ///      at the specified keyIndex. The user must specify which key they encrypted to,
    ///      ensuring correct decryption even if the key rotates before inclusion.
    ///      The token identity is public (not encrypted) since the portal must escrow it.
    /// @param token The TIP-20 token to deposit
    /// @param amount Amount to deposit
    /// @param keyIndex Index of the encryption key used (from encryptionKeyAt)
    /// @param encrypted The encrypted payload (recipient and memo)
    /// @return newCurrentDepositQueueHash The new deposit queue hash
    function depositEncrypted(
        address token,
        uint128 amount,
        uint256 keyIndex,
        DepositPayload calldata encrypted,
        address tempoRefundRecipient
    )
        external
        returns (bytes32 newCurrentDepositQueueHash);

    function processWithdrawals(Withdrawal[] calldata withdrawals, bytes32 remainingQueue) external;

    function deliverWithdrawal(
        address token,
        address target,
        uint128 amount,
        bytes32 senderTag,
        uint64 gasLimit,
        bytes calldata data
    )
        external;

    function refunds(address token, address owner) external view returns (uint128);

    function claimRefund(address token) external returns (uint128 amount);

    /// @notice Submit a batch with an n-of-m certificate for its zone tip.
    function submitBatch(
        uint64 tempoBlockNumber,
        uint64 recentTempoBlockNumber,
        BlockTransition calldata blockTransition,
        DepositQueueTransition calldata depositQueueTransition,
        TokenEnablementTransition calldata tokenEnablementTransition,
        bytes32 withdrawalQueueHash,
        bytes calldata verifierConfig,
        bytes calldata proof,
        uint256 zoneHeight,
        bytes[] calldata signatures
    )
        external;

}

/// @title IZoneMessenger
/// @notice Interface for the shared zone messenger on Tempo (handles withdrawal callbacks)
interface IZoneMessenger {

    /// @notice Relay a withdrawal message. Only callable by the registered portal for `zoneId`.
    /// @dev Transfers tokens it received from the portal to target, then executes callback.
    ///      If callback reverts, the entire call reverts (including the transfer).
    /// @param zoneId The source zone ID.
    /// @param token The TIP-20 token to transfer
    /// @param senderTag The authenticated sender commitment from the zone
    /// @param target The Tempo recipient
    /// @param amount Tokens to transfer from portal to target
    /// @param gasLimit Max gas for the callback
    /// @param data Calldata for the target
    function relayMessage(
        uint32 zoneId,
        address token,
        bytes32 senderTag,
        address target,
        uint128 amount,
        uint64 gasLimit,
        bytes calldata data
    )
        external;

}

/// @title IWithdrawalReceiver
/// @notice Interface for contracts that receive withdrawals with callbacks
interface IWithdrawalReceiver {

    function onWithdrawalReceived(
        uint32 zoneId,
        address sourcePortal,
        bytes32 senderTag,
        address token,
        uint128 amount,
        bytes calldata callbackData
    )
        external
        returns (bytes4);

}

/// @notice Withdrawal batch parameters stored in state for proof access
/// @dev Written to storage on each finalizeWithdrawalBatch() call so proofs can read from state root
///      instead of parsing event logs (which are expensive and hard to prove)
struct LastBatch {
    bytes32 withdrawalQueueHash;
    uint64 withdrawalBatchIndex;
}

/// @title ITempoState
/// @notice Interface for zone-side Tempo state verification predeploy
/// @dev Deployed at 0x1c00000000000000000000000000000000000000
///      System-only contract. Only ZoneInbox can call finalizeTempo().
///      Only ZoneInbox and ZoneOutbox can call readTempoStorageSlot(s).
interface ITempoState {

    event TempoBlockFinalized(
        bytes32 indexed blockHash, uint64 indexed blockNumber, bytes32 stateRoot
    );

    error InvalidParentHash();
    error InvalidBlockNumber();
    error InvalidTimestamp();
    error InvalidRlpData();
    error OnlyZoneInbox();

    /// @notice Current finalized Tempo block hash (keccak256 of RLP-encoded header)
    function tempoBlockHash() external view returns (bytes32);

    /// @notice Current finalized Tempo block number
    function tempoBlockNumber() external view returns (uint64);

    /// @notice Finalize a Tempo block header. Only callable by ZoneInbox.
    /// @dev Validates chain continuity and that the Zone timestamp to be at or after the final header.
    ///      Called by ZoneInbox.advanceTempo(). Executor enforces ZoneInbox-only access.
    /// @param headers Consecutive RLP-encoded Tempo headers
    function finalizeTempo(bytes[] calldata headers) external;

    /// @notice Read a storage slot from a Tempo contract
    function readTempoStorageSlot(address account, bytes32 slot) external view returns (bytes32);

    /// @notice Read multiple storage slots from a Tempo contract
    function readTempoStorageSlots(
        address account,
        bytes32[] calldata slots
    )
        external
        view
        returns (bytes32[] memory);

}

/// @title IZoneInbox
/// @notice Interface for zone-side system contract that advances Tempo state and processes deposits
interface IZoneInbox {

    event TempoAdvanced(
        bytes32 indexed tempoBlockHash,
        uint64 indexed tempoBlockNumber,
        uint256 depositsProcessed,
        bytes32 newProcessedDepositQueueHash,
        uint64 lastProcessedDepositNumber,
        uint64 lastProcessedEnabledTokenCount
    );

    /// @notice Emitted when a deposit is processed (decrypted and credited)
    // Revealed after decryption
    event DepositProcessed(
        bytes32 indexed depositHash,
        address indexed sender,
        address indexed to,
        address token,
        uint128 amount,
        bytes32 memo
    );

    /// @notice Emitted when a deposit fails (invalid ciphertext, funds returned to sender)
    event DepositFailed(
        bytes32 indexed depositHash, address indexed sender, address token, uint128 amount
    );

    event DepositRejected(
        bytes32 indexed depositHash,
        address indexed sender,
        DepositType depositType,
        address token,
        uint128 amount,
        address tempoRefundRecipient
    );

    event WithdrawalBounceBackProcessed(
        address indexed zoneFallbackRecipient, address token, uint128 amount
    );

    event WithdrawalBounceBackPending(
        address indexed zoneFallbackRecipient, address token, uint128 amount
    );

    event RefundClaimed(address indexed recipient, address indexed token, uint128 amount);

    /// @notice Emitted when a TIP-20 token is enabled on the zone via advanceTempo
    event TokenEnabled(address indexed token, string name, string symbol, string currency);

    error InvalidTokenEnablementHash();
    error OnlySequencer();
    error InvalidDepositQueueHash();
    error InvalidWithdrawalBounceBack();
    error MissingDecryptionData();
    error ExtraDecryptionData();
    error InvalidSharedSecretProof();
    error Unauthorized();

    /// @notice Get the number of enabled tokens processed by the Zone Inbox
    function processedEnabledTokenCount() external view returns (uint64);

    /// @notice Authenticate Tempo ancestry without processing portal work.
    function advanceTempoHeaders(bytes[] calldata headers) external;

    /// @notice The Tempo portal address (for reading deposit queue hash)
    function tempoPortal() external view returns (address);

    /// @notice The TempoState predeploy address
    function tempoState() external view returns (ITempoState);

    /// @notice The zone's last processed deposit queue hash
    function processedDepositQueueHash() external view returns (bytes32);

    function processedDepositNumber() external view returns (uint64);

    /// @notice Append-only commitment already applied by the zone
    function processedTokenEnablementHash() external view returns (bytes32);

    function refunds(address token, address owner) external view returns (uint128);

    function claimRefund(address token) external returns (uint128 amount);

    /// @notice Advance Tempo state and process deposits in a single system-only call.
    /// @dev This is the main entry point for the block executor at block start.
    ///      1. Advances the zone's view of Tempo by processing the header
    ///      2. Processes user deposits and internal withdrawal bounce-backs
    ///      3. Requires the resulting hash chain to equal Tempo's currentDepositQueueHash
    ///
    ///      For user deposits, the sequencer provides DecryptionData with the
    ///      ECDH shared secret and proof. ZoneInbox derives (to, memo) onchain.
    ///
    /// @param header RLP-encoded Tempo block header
    /// @param deposits All queued deposits through the current head, oldest first
    /// @param decryptions Decryption data for valid user deposits, in order
    /// @param enabledTokens Tokens to activate directly in the ZoneInbox
    function advanceTempo(
        bytes calldata header,
        QueuedDeposit[] calldata deposits,
        DecryptionData[] calldata decryptions,
        EnabledToken[] calldata enabledTokens
    )
        external;

}

/// @title IZoneOutbox
/// @notice Interface for zone outbox on the zone
interface IZoneOutbox {

    error OnlySequencer();
    error GasLimitTooHigh();
    error OnlyZoneInbox();
    error InvalidWithdrawalCount(uint256 actual, uint256 expected);
    error InvalidEncryptedSenderCount(uint256 actual, uint256 expected);
    error InvalidEncryptedSenderLength(uint256 actual, uint256 expected);
    error InvalidFallbackRecipient();
    error CallbackDataTooLarge();
    error GasFeeRateTooHigh();
    error TransferFailed();
    error InvalidBlockNumber();
    error TooManyWithdrawalsThisBlock();
    error InvalidRevealTo();
    error InvalidCurrentTxHash();
    error ZeroAmountWithdrawal();
    error StaticCallNotAllowed();

    /// @notice Maximum callback data size (1KB)
    function MAX_CALLBACK_DATA_SIZE() external view returns (uint256);

    /// @notice Maximum callback gas accepted for withdrawals
    function MAX_WITHDRAWAL_GAS_LIMIT() external view returns (uint64);

    /// @notice Base gas cost for processing a withdrawal on Tempo (excluding callback)
    function WITHDRAWAL_BASE_GAS() external view returns (uint64);

    function REVEAL_TO_KEY_LENGTH() external view returns (uint256);

    function AUTHENTICATED_WITHDRAWAL_CIPHERTEXT_LENGTH() external view returns (uint256);

    event WithdrawalRequested(
        uint64 indexed withdrawalIndex,
        address indexed sender,
        address token,
        address to,
        uint128 amount,
        uint128 fee,
        bytes32 memo,
        uint64 gasLimit,
        uint64 fallbackNonce,
        bytes data,
        bytes revealTo
    );

    event TempoGasRateUpdated(uint128 tempoGasRate);

    event MaxWithdrawalsPerBlockUpdated(uint32 maxWithdrawalsPerBlock);

    /// @notice Emitted when sequencer finalizes a batch at end of block
    /// @dev Kept for observability. Proof reads from lastBatch storage instead.
    event BatchFinalized(bytes32 indexed withdrawalQueueHash, uint64 withdrawalBatchIndex);

    /// @notice Tempo gas rate (zone token units per gas unit on Tempo)
    /// @dev Fee = (WITHDRAWAL_BASE_GAS + gasLimit) * tempoGasRate
    function tempoGasRate() external view returns (uint128);

    /// @notice Next withdrawal index (monotonically increasing)
    function nextWithdrawalIndex() external view returns (uint64);

    /// @notice Last nonce assigned to a user withdrawal fallback recipient
    function lastFallbackNonce() external view returns (uint64);

    /// @notice Resolve and delete a fallback recipient. Only callable by ZoneInbox.
    function consumeFallbackRecipient(uint64 fallbackNonce)
        external
        returns (address zoneFallbackRecipient);

    /// @notice Last finalized batch parameters (for proof access via state root)
    function lastBatch() external view returns (LastBatch memory);

    /// @notice Number of pending withdrawals
    function pendingWithdrawalsCount() external view returns (uint256);

    /// @notice Pending withdrawals waiting to be finalized
    function getPendingWithdrawals() external view returns (PendingWithdrawal[] memory);

    /// @notice Timestamp of the latest withdrawal batch finalization
    function lastFinalizedTimestamp() external view returns (uint64);

    /// @notice Maximum number of withdrawal requests per zone block (0 = unlimited)
    function maxWithdrawalsPerBlock() external view returns (uint32);

    /// @notice Set Tempo gas rate. Only callable by sequencer.
    /// @dev Sequencer publishes this rate and takes the risk on Tempo gas price fluctuations.
    ///      The rate must not exceed the finalized portal maxTempoGasRate.
    /// @param _tempoGasRate Zone token units per gas unit on Tempo
    function setTempoGasRate(uint128 _tempoGasRate) external;

    /// @notice Set maximum withdrawal requests per zone block. Only callable by sequencer.
    /// @dev Set to 0 for unlimited. Provides rate-limiting in addition to the gas fee mechanism.
    function setMaxWithdrawalsPerBlock(uint32 _maxWithdrawalsPerBlock) external;

    /// @notice Calculate the fee for a withdrawal with the given gasLimit
    /// @dev Fee = (WITHDRAWAL_BASE_GAS + gasLimit) * tempoGasRate
    function calculateWithdrawalFee(uint64 gasLimit) external view returns (uint128);

    /// @notice Request a withdrawal from the zone back to Tempo
    /// @dev Caller must approve outbox to spend amount + fee of the specified token.
    ///      The token must be enabled on the portal. Withdrawals can never be disabled
    ///      for an enabled token (non-custodial guarantee).
    /// @param token The TIP-20 token to withdraw
    function requestWithdrawal(
        address token,
        address to,
        uint128 amount,
        bytes32 memo,
        uint64 gasLimit,
        address zoneFallbackRecipient,
        bytes calldata data,
        bytes calldata revealTo
    )
        external;

    function enqueueDepositBounceBack(
        address token,
        uint128 amount,
        address tempoRefundRecipient
    )
        external;

    /// @notice Finalize batch at end of block - build withdrawal hash and write to state
    /// @dev Only callable by sequencer. Required per batch. `count` must equal
    ///      the current pending withdrawal count (including 0 for an empty batch).
    ///      Writes withdrawal batch parameters to lastBatch storage for proof access.
    /// @param count The number of pending withdrawals to process
    /// @return withdrawalQueueHash The hash chain (0 if no withdrawals)
    function finalizeWithdrawalBatch(
        uint256 count,
        uint64 blockNumber,
        bytes[] calldata encryptedSenders
    )
        external
        returns (bytes32 withdrawalQueueHash);

}
