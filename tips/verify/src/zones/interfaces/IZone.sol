// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @title IZoneToken
/// @notice Interface for the zone's zone token (TIP-20 with mint/burn for system)
interface IZoneToken {

    function mint(address to, uint256 amount) external;

    function burn(uint256 amount) external;

    function transfer(address to, uint256 amount) external returns (bool);

    function transferFrom(address from, address to, uint256 amount) external returns (bool);

    function balanceOf(address account) external view returns (uint256);

}

/// @notice Common types for the Zone protocol
struct ZoneInfo {
    uint32 zoneId;
    address portal;
    address initialToken; // first TIP-20 enabled at zone creation (additional tokens enabled via enableToken)
    address admin;
    address sequencer;
    address verifier;
    bytes32 genesisBlockHash;
    bytes32 genesisTempoBlockHash;
    uint64 genesisTempoBlockNumber;
    string rpcUrl;
}

/// @notice Zone creation parameters stored in genesis
struct ZoneParams {
    bytes32 genesisBlockHash;
    bytes32 genesisTempoBlockHash;
    uint64 genesisTempoBlockNumber;
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
///      that nextProcessedHash is an ancestor of (or equal to) currentDepositQueueHash.
///      This allows partial deposit processing.
///      The deposit numbers mirror the hash chain for easy status checking:
///      a deposit with number N is confirmed once lastProcessedDepositNumber >= N.
struct DepositQueueTransition {
    bytes32 prevProcessedHash; // where proof starts (verified against zone state)
    bytes32 nextProcessedHash; // where zone processed up to (proof output)
    uint64 prevDepositNumber; // deposit counter at prevProcessedHash
    uint64 nextDepositNumber; // deposit counter at nextProcessedHash
}

/// @notice Deposit type discriminator for the unified deposit queue
/// @dev Used in hash chain: keccak256(abi.encode(depositType, depositData, prevHash))
enum DepositType {
    Regular, // Standard deposit with plaintext recipient and memo
    Encrypted // Encrypted deposit with hidden recipient and memo
}

struct Deposit {
    address token; // TIP-20 token being deposited
    address sender;
    address to;
    uint128 amount;
    address bouncebackRecipient;
    bytes32 memo;
}

/*//////////////////////////////////////////////////////////////
                        ENCRYPTED DEPOSITS
//////////////////////////////////////////////////////////////*/

/// @notice Encrypted deposit payload (recipient and memo encrypted to sequencer)
/// @dev Uses ECIES with secp256k1: ephemeral ECDH + AES-256-GCM
struct EncryptedDepositPayload {
    bytes32 ephemeralPubkeyX; // Ephemeral public key X coordinate (for ECDH)
    uint8 ephemeralPubkeyYParity; // Y coordinate parity (0x02 or 0x03)
    bytes ciphertext; // AES-256-GCM encrypted (to || memo || padding)
    bytes12 nonce; // GCM nonce
    bytes16 tag; // GCM authentication tag
}

/// @notice Encrypted deposit stored in the queue
/// @dev Sender, token, amount, and key index are public; recipient and memo are encrypted.
///      The token identity is public because the portal must escrow the correct token.
///      The keyIndex specifies which encryption key the user used, allowing the prover
///      to look up the correct key for decryption even after key rotations.
struct EncryptedDeposit {
    address token; // TIP-20 token being deposited (public, for escrow accounting)
    address sender; // Depositor (public, for refunds)
    uint128 amount; // Amount (public, for accounting)
    address bouncebackRecipient; // Tempo recipient for a failed-deposit refund
    uint256 keyIndex; // Index of encryption key used (specified by depositor)
    EncryptedDepositPayload encrypted; // Encrypted (to, memo)
}

/// @notice Historical record of an encryption key with its activation block
/// @dev Storage layout per entry (2 slots):
///      slot 0: x (bytes32) - full slot
///      slot 1: yParity (uint8, lowest byte) | activationBlock (uint64, next 8 bytes)
///      WARNING: Do not reorder fields. ZoneInbox._readEncryptionKey() and
///      ZoneConfig.sequencerEncryptionKey() read these via raw storage slot access.
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
///      The depositData is ABI-encoded Deposit or EncryptedDeposit depending on type.
struct QueuedDeposit {
    DepositType depositType;
    bytes depositData; // abi.encode(Deposit) or abi.encode(EncryptedDeposit)
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

/// @notice Decryption data provided by sequencer for encrypted deposits
/// @dev Must match 1:1 with encrypted deposits in the queue (in order of appearance).
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

/*//////////////////////////////////////////////////////////////
                    CRYPTOGRAPHIC PRECOMPILES
//////////////////////////////////////////////////////////////*/

/// @notice Token to be enabled on the zone via the TIP20 factory
struct EnabledToken {
    address token;
    string name;
    string symbol;
    string currency;
}

/// @title ITIP20ZoneFactory
/// @notice Interface for the zone's TIP20 factory that enables new tokens
interface ITIP20ZoneFactory {

    function enableToken(
        address token,
        string calldata name,
        string calldata symbol,
        string calldata currency
    )
        external;

}

// TIP20 factory predeploy address
address constant TIP20_FACTORY_ADDRESS = 0x20Fc000000000000000000000000000000000000;

// Precompile address for Chaum-Pedersen proof verification
// Predeploy at 0x1c00000000000000000000000000000000000100
address constant CHAUM_PEDERSEN_VERIFY = 0x1C00000000000000000000000000000000000100;

// Precompile address for AES-256-GCM decryption
// Predeploy at 0x1c00000000000000000000000000000000000101
address constant AES_GCM_DECRYPT = 0x1C00000000000000000000000000000000000101;

// Precompile address for SHA256 (standard Ethereum precompile)
// Used for HKDF-SHA256 implementation in Solidity
address constant SHA256 = 0x0000000000000000000000000000000000000002;

/// @title IChaumPedersenVerify
/// @notice Precompile for verifying Chaum-Pedersen proofs of ECDH shared secret derivation
/// @dev Verifies that the sequencer knows privSeq such that:
///      - pubSeq = privSeq * G (their public key)
///      - sharedSecretPoint = privSeq * ephemeralPub (the ECDH computation)
///      This proves correct derivation without revealing the private key.
interface IChaumPedersenVerify {

    /// @notice Verify a Chaum-Pedersen proof for ECDH shared secret derivation
    /// @dev Verification equations:
    ///      - R1 = s*G - c*pubSeq
    ///      - R2 = s*ephemeralPub - c*sharedSecretPoint
    ///      - c' = hash(G, ephemeralPub, pubSeq, sharedSecretPoint, R1, R2)
    ///      - Check: c == c'
    /// @param ephemeralPubX The X coordinate of the ephemeral public key
    /// @param ephemeralPubYParity The Y coordinate parity (0x02 or 0x03)
    /// @param sharedSecret The claimed shared secret (x-coordinate)
    /// @param sharedSecretYParity The Y coordinate parity of the shared secret point (0x02 or 0x03)
    /// @param sequencerPubX The sequencer's public key X coordinate
    /// @param sequencerPubYParity The sequencer's public key Y parity
    /// @param proof The Chaum-Pedersen proof (s, c)
    /// @return valid True if the proof verifies correctly
    function verifyProof(
        bytes32 ephemeralPubX,
        uint8 ephemeralPubYParity,
        bytes32 sharedSecret,
        uint8 sharedSecretYParity,
        bytes32 sequencerPubX,
        uint8 sequencerPubYParity,
        ChaumPedersenProof calldata proof
    )
        external
        view
        returns (bool valid);

}

/// @title IAesGcmDecrypt
/// @notice Minimal precompile for AES-256-GCM decryption with authentication
/// @dev Decrypts ciphertext and verifies the GCM authentication tag.
///      HKDF-SHA256 key derivation is done in Solidity using the SHA256 precompile.
interface IAesGcmDecrypt {

    /// @notice Decrypt AES-256-GCM ciphertext and verify authentication tag
    /// @dev Returns empty bytes and false if tag verification fails.
    ///      AAD (Additional Authenticated Data) is typically empty for ECIES.
    /// @param key AES-256 key (32 bytes)
    /// @param nonce GCM nonce (12 bytes)
    /// @param ciphertext The encrypted data
    /// @param aad Additional authenticated data (use empty bytes if none)
    /// @param tag GCM authentication tag (16 bytes)
    /// @return plaintext The decrypted data (empty if verification fails)
    /// @return valid True if the tag verifies and decryption succeeds
    function decrypt(
        bytes32 key,
        bytes12 nonce,
        bytes calldata ciphertext,
        bytes calldata aad,
        bytes16 tag
    )
        external
        view
        returns (bytes memory plaintext, bool valid);

}

// Maximum callback gas a withdrawal may request.
// The processor adds fixed overhead plus an EIP-150 cushion, so this value
// keeps the outer `processWithdrawal` transaction well below a 30M gas L1 block
// limit.
uint64 constant MAX_WITHDRAWAL_CALLBACK_GAS = 10_000_000;

struct Withdrawal {
    address token; // TIP-20 token being withdrawn
    bytes32 senderTag; // keccak256(abi.encodePacked(sender, txHash))
    address to; // Tempo recipient
    uint128 amount; // amount to send to recipient (excludes fee)
    uint128 fee; // processing fee for sequencer (calculated at request time)
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
    uint128 fee; // processing fee for sequencer (calculated at request time)
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

// ZoneConfig system contract address (0x1c00...0003)
address constant ZONE_CONFIG = 0x1c00000000000000000000000000000000000003;

// ZoneTxContext precompile address (0x1c00...0005)
address constant ZONE_TX_CONTEXT = 0x1C00000000000000000000000000000000000005;

/// @title IZoneTxContext
/// @notice Interface for the zone precompile that exposes the currently executing tx hash
interface IZoneTxContext {

    /// @notice Returns the hash of the currently executing zone transaction
    function currentTxHash() external returns (bytes32);

}

/*//////////////////////////////////////////////////////////////
                ZONE PORTAL STORAGE SLOT CONSTANTS
//////////////////////////////////////////////////////////////*/

// ZonePortal storage layout:
//   slot 0: sequencer (address)
//   slot 1: admin (address)
//   slot 2: pendingSequencer (address)
//   slot 3: zoneGasRate (uint128) + withdrawalBatchIndex (uint64) [packed]
//   slot 4: blockHash (bytes32)
//   slot 5: currentDepositQueueHash (bytes32)
//   slot 6: depositCount (uint64) + lastProcessedDepositNumber (uint64) + lastSyncedTempoBlockNumber (uint64) [packed]
//   slot 7: _encryptionKeys (EncryptionKeyEntry[])
//   slot 8: _tokenConfigs (mapping(address => TokenConfig))
//   slot 9: _enabledTokens (address[])
//   slot 10: refunds (mapping(address => mapping(address => uint128)))
//   slot 11: _withdrawalQueue.head
//   slot 12: _withdrawalQueue.tail
//   slot 13: _withdrawalQueue.slots (mapping(uint256 => bytes32))
//   slot 14: rpcUrl (string)
//   slot 15: pendingAdmin (address)
//   slot 16: _withdrawalReentrancyStatus (uint256)
//   slot 17: zoneId (uint32) + messenger (address) [packed]
//   slot 18: verifier (address) + genesisTempoBlockNumber (uint64) + _initialized (bool) [packed]
//
// These constants are the single source of truth for cross-domain reads.
// ZoneConfig and ZoneInbox use them to read portal state via
// TempoState.readTempoStorageSlot(). If the portal layout changes,
// update these constants and the vm.load regression tests will catch mismatches.
bytes32 constant PORTAL_SEQUENCER_SLOT = bytes32(uint256(0));
bytes32 constant PORTAL_ADMIN_SLOT = bytes32(uint256(1));
bytes32 constant PORTAL_PENDING_SEQUENCER_SLOT = bytes32(uint256(2));
bytes32 constant PORTAL_CURRENT_DEPOSIT_QUEUE_HASH_SLOT = bytes32(uint256(5));
bytes32 constant PORTAL_ENCRYPTION_KEYS_SLOT = bytes32(uint256(7));
bytes32 constant PORTAL_TOKEN_CONFIGS_SLOT = bytes32(uint256(8));
bytes32 constant PORTAL_ENABLED_TOKENS_SLOT = bytes32(uint256(9));
bytes32 constant PORTAL_PENDING_ADMIN_SLOT = bytes32(uint256(15));

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
    ///      7. Zone block beneficiary matches sequencer
    ///      8. Deposit processing is correct (validated via Tempo state read inside proof)
    /// @param tempoBlockNumber Block zone committed to (from TempoState)
    /// @param anchorBlockNumber Block whose hash is verified (tempoBlockNumber or recent block)
    /// @param anchorBlockHash Hash of anchorBlockNumber (from EIP-2935)
    /// @param expectedWithdrawalBatchIndex Expected batch index (portal.withdrawalBatchIndex + 1)
    /// @param sequencer Sequencer address (zone block beneficiary must match)
    /// @param blockTransition Zone block hash transition
    /// @param depositQueueTransition Deposit queue processing transition
    /// @param withdrawalQueueHash Withdrawal queue hash chain for this batch (0 if none)
    /// @param verifierConfig Opaque payload for verifier (TEE attestation envelope, etc.)
    /// @param proof Validity proof or TEE attestation
    function verify(
        uint64 tempoBlockNumber,
        uint64 anchorBlockNumber,
        bytes32 anchorBlockHash,
        uint64 expectedWithdrawalBatchIndex,
        address sequencer,
        BlockTransition calldata blockTransition,
        DepositQueueTransition calldata depositQueueTransition,
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
        address initialToken; // first TIP-20 to enable (sequencer can enable more later)
        address admin;
        address sequencer;
        address verifier;
        ZoneParams zoneParams;
        string rpcUrl;
    }

    event ZoneCreated(
        uint32 indexed zoneId,
        address indexed portal,
        address initialToken,
        address admin,
        address sequencer,
        address verifier,
        bytes32 genesisBlockHash,
        bytes32 genesisTempoBlockHash,
        uint64 genesisTempoBlockNumber
    );

    error InvalidToken();
    error InvalidOwner();
    error NotOwner();
    error InvalidAdmin();
    error InvalidSequencer();
    error InvalidVerifier();
    error InsufficientGas();
    error ZoneIdOverflow();

    /// @notice Returns the account authorized to create zones.
    function owner() external view returns (address);

    /// @notice Transfers zone-creation authority to `newOwner`.
    function transferOwnership(address newOwner) external;

    /// @notice Returns whether a verifier contract is approved for zone creation.
    /// @param verifier The verifier contract address to check.
    /// @return valid True if `verifier` can be passed to `createZone`.
    function isValidVerifier(address verifier) external view returns (bool);

    /// @notice Returns the default verifier deployed by the factory.
    /// @return verifier The default verifier contract address.
    function verifier() external view returns (address);

    /// @notice Creates a new zone and deploys its portal contract.
    /// @param params The initial token, sequencer, verifier, and genesis parameters for the zone.
    /// @return zoneId The newly assigned zone ID.
    /// @return portal The deployed portal address for the new zone.
    function createZone(CreateZoneParams calldata params)
        external
        returns (uint32 zoneId, address portal);

    /// @notice Returns the number of zones created so far.
    /// @return count The total number of created zones, excluding reserved zone ID 0.
    function zoneCount() external view returns (uint32);

    /// @notice Returns the stored metadata for a zone.
    /// @param zoneId The zone ID to query.
    /// @return info The zone metadata recorded for `zoneId`.
    function zones(uint32 zoneId) external view returns (ZoneInfo memory);

    /// @notice Returns whether an address is a portal deployed by this factory.
    /// @param portal The portal address to check.
    /// @return isPortal True if `portal` was created by this factory.
    function isZonePortal(address portal) external view returns (bool);

    /// @notice Returns the shared messenger used for withdrawal callbacks.
    /// @return messenger The shared messenger contract address.
    function messenger() external view returns (address);

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

    event DepositMade(
        bytes32 indexed newCurrentDepositQueueHash,
        address indexed sender,
        address token,
        address to,
        uint128 netAmount,
        uint128 fee,
        bytes32 memo,
        address bouncebackRecipient,
        uint64 depositNumber
    );

    event BatchSubmitted(
        uint64 indexed withdrawalBatchIndex,
        bytes32 nextProcessedDepositQueueHash,
        bytes32 nextBlockHash,
        bytes32 withdrawalQueueHash,
        uint64 lastProcessedDepositNumber
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

    /// @notice Emitted when the current sequencer nominates a new sequencer (two-step transfer).
    /// @dev A `pendingSequencer` of address(0) signals cancellation of a pending transfer.
    event SequencerTransferStarted(
        address indexed currentSequencer, address indexed pendingSequencer
    );
    /// @notice Emitted when a pending sequencer accepts and the sequencer role is handed over.
    event SequencerTransferred(address indexed previousSequencer, address indexed newSequencer);

    /// @notice Emitted when the current admin nominates a new admin (two-step transfer).
    /// @dev A `newAdmin` of address(0) signals cancellation of a pending transfer.
    event AdminTransferStarted(address indexed currentAdmin, address indexed pendingAdmin);
    /// @notice Emitted when a pending admin accepts and the admin role is handed over.
    event AdminTransferred(address indexed previousAdmin, address indexed newAdmin);

    /// @notice Emitted when an encrypted deposit is made (recipient/memo not revealed)
    event EncryptedDepositMade(
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
        address bouncebackRecipient,
        uint64 depositNumber
    );

    event DepositBounceBack(
        address indexed bouncebackRecipient, address token, uint128 amount, uint128 bouncebackFee
    );

    event DepositBounceBackPending(
        address indexed bouncebackRecipient, address token, uint128 amount, uint128 bouncebackFee
    );

    /// @notice Emitted when a recipient claims a previously-parked bounce-back refund.
    event RefundClaimed(address indexed recipient, address indexed token, uint128 amount);

    /// @notice Emitted when sequencer updates their encryption key
    /// @param x The X coordinate of the new key
    /// @param yParity The Y coordinate parity (0x02 or 0x03)
    /// @param keyIndex The index of this key in the history array
    /// @param activationBlock The Tempo block when this key becomes active
    event SequencerEncryptionKeyUpdated(
        bytes32 x, uint8 yParity, uint256 keyIndex, uint64 activationBlock
    );
    event ZoneGasRateUpdated(uint128 zoneGasRate);

    /// @notice Emitted when admin enables a new TIP-20 token for bridging
    event TokenEnabled(address indexed token, string name, string symbol, string currency);

    /// @notice Emitted when admin pauses deposits for a token
    event DepositsPaused(address indexed token);

    /// @notice Emitted when admin resumes deposits for a token
    event DepositsResumed(address indexed token);

    /// @notice Emitted when the sequencer updates the zone's public RPC endpoint
    event RpcUrlUpdated(string rpcUrl);

    error NotSequencer();
    error NotAdmin();
    error NotFactory();
    error AlreadyInitialized();
    error NotPendingSequencer();
    error NotPendingAdmin();
    error InvalidProof();
    error InvalidTempoBlockNumber();
    error CallbackRejected();
    error TransferFailed();
    error NotSelf();
    error ReentrantWithdrawal();
    error EncryptionKeyExpired(uint256 keyIndex, uint64 activationBlock, uint64 supersededAtBlock);
    error InvalidEncryptionKeyIndex(uint256 keyIndex);
    error NoEncryptionKeySet();
    error NoEncryptionKeyAtBlock(uint64 blockNumber);
    error InvalidEphemeralPubkey();
    error InvalidCiphertextLength(uint256 actual, uint256 expected);
    error InvalidProofOfPossession();
    error DepositTooSmall();
    error GasFeeRateTooHigh();
    error TokenNotEnabled();
    error DepositsNotActive();
    error TokenAlreadyEnabled();
    error InvalidBouncebackRecipient();
    error InvalidDepositTransition();

    function initialize(
        uint32 zoneId,
        address initialToken,
        address messenger,
        address admin,
        address sequencer,
        address verifier,
        bytes32 genesisBlockHash,
        uint64 genesisTempoBlockNumber,
        string calldata rpcUrl
    )
        external;

    /// @notice Fixed gas value for deposit fee calculation (100,000 gas)
    function FIXED_DEPOSIT_GAS() external view returns (uint64);

    /// @notice Fixed gas value for deposit bounce-back fee calculation (300,000 gas)
    function FIXED_BOUNCEBACK_GAS() external view returns (uint64);

    /// @notice Maximum callback gas accepted for withdrawals
    function MAX_WITHDRAWAL_GAS_LIMIT() external view returns (uint64);

    /// @notice Maximum allowed gas fee rate (1e18)
    function MAX_GAS_FEE_RATE() external view returns (uint128);

    function zoneId() external view returns (uint32);

    function sequencer() external view returns (address);

    function admin() external view returns (address);

    function pendingSequencer() external view returns (address);

    function pendingAdmin() external view returns (address);

    function zoneGasRate() external view returns (uint128);

    function verifier() external view returns (address);

    function messenger() external view returns (address);

    function withdrawalBatchIndex() external view returns (uint64);

    function blockHash() external view returns (bytes32);

    function currentDepositQueueHash() external view returns (bytes32);

    function lastSyncedTempoBlockNumber() external view returns (uint64);

    function withdrawalQueueHead() external view returns (uint256);

    function withdrawalQueueTail() external view returns (uint256);

    function withdrawalQueueSlot(uint256 slot) external view returns (bytes32);

    function genesisTempoBlockNumber() external view returns (uint64);

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

    /// @notice Get an enabled token by index
    function enabledTokenAt(uint256 index) external view returns (address);

    /// @notice Enable a new TIP-20 token for bridging. Only callable by admin.
    /// @dev Irreversible: once enabled, a token cannot be disabled.
    ///      Validates the token is a TIP-20.
    function enableToken(address token) external;

    /// @notice Pause deposits for a token. Only callable by admin.
    /// @dev Does not affect withdrawal processing (non-custodial guarantee).
    function pauseDeposits(address token) external;

    /// @notice Resume deposits for a token. Only callable by admin.
    function resumeDeposits(address token) external;

    /// @notice The zone's public RPC endpoint
    /// @return The stored RPC URL, or empty string if unset
    function rpcUrl() external view returns (string memory);

    /// @notice Update the zone's public RPC endpoint. Only callable by sequencer.
    /// @param rpcUrl The new RPC URL (may be empty to clear it)
    function setRpcUrl(string calldata rpcUrl) external;

    /// @notice Start a sequencer transfer. Only callable by current sequencer.
    /// @param newSequencer The address that will become sequencer after accepting.
    function transferSequencer(address newSequencer) external;

    /// @notice Accept a pending sequencer transfer. Only callable by pending sequencer.
    function acceptSequencer() external;

    /// @notice Start an admin transfer. Only callable by the current admin.
    /// @param newAdmin The address that will become admin after accepting (address(0) cancels).
    function transferAdmin(address newAdmin) external;

    /// @notice Accept a pending admin transfer. Only callable by the pending admin.
    function acceptAdmin() external;

    /// @notice Get the sequencer's current encryption public key for encrypted deposits
    /// @return x The X coordinate of the secp256k1 public key
    /// @return yParity The Y coordinate parity (0x02 or 0x03)
    function sequencerEncryptionKey() external view returns (bytes32 x, uint8 yParity);

    /// @notice Set the sequencer's encryption public key. Only callable by sequencer.
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

    /// @notice Set zone gas rate. Only callable by sequencer.
    /// @param _zoneGasRate Zone token units per gas unit on the zone
    function setZoneGasRate(uint128 _zoneGasRate) external;

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

    function deposit(
        address token,
        address to,
        uint128 amount,
        bytes32 memo,
        address bouncebackRecipient
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
        EncryptedDepositPayload calldata encrypted,
        address bouncebackRecipient
    )
        external
        returns (bytes32 newCurrentDepositQueueHash);

    function processWithdrawal(Withdrawal calldata withdrawal, bytes32 remainingQueue) external;

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

    function submitBatch(
        uint64 tempoBlockNumber,
        uint64 recentTempoBlockNumber,
        BlockTransition calldata blockTransition,
        DepositQueueTransition calldata depositQueueTransition,
        bytes32 withdrawalQueueHash,
        bytes calldata verifierConfig,
        bytes calldata proof
    )
        external;

}

/// @title IZoneMessenger
/// @notice Shared callback sender for zone withdrawals.
interface IZoneMessenger {

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
///      Only ZoneInbox, ZoneOutbox, and ZoneConfig can call readTempoStorageSlot(s).
interface ITempoState {

    event TempoBlockFinalized(
        bytes32 indexed blockHash, uint64 indexed blockNumber, bytes32 stateRoot
    );

    error InvalidParentHash();
    error InvalidBlockNumber();
    error InvalidRlpData();
    error OnlyZoneInbox();

    /// @notice Current finalized Tempo block hash (keccak256 of RLP-encoded header)
    function tempoBlockHash() external view returns (bytes32);

    /// @notice Current finalized Tempo block number
    function tempoBlockNumber() external view returns (uint64);

    /// @notice Finalize a Tempo block header. Only callable by ZoneInbox.
    /// @dev Validates chain continuity (parent hash must match, number must be +1).
    ///      Called by ZoneInbox.advanceTempo(). Executor enforces ZoneInbox-only access.
    /// @param header RLP-encoded Tempo header
    function finalizeTempo(bytes calldata header) external;

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
        uint64 lastProcessedDepositNumber
    );

    event DepositProcessed(
        bytes32 indexed depositHash,
        address indexed sender,
        address indexed to,
        address token,
        uint128 amount,
        bytes32 memo
    );

    /// @notice Emitted when an encrypted deposit is processed (decrypted and credited)
    // Revealed after decryption
    event EncryptedDepositProcessed(
        bytes32 indexed depositHash,
        address indexed sender,
        address indexed to,
        address token,
        uint128 amount,
        bytes32 memo
    );

    /// @notice Emitted when an encrypted deposit fails (invalid ciphertext, funds returned to sender)
    event EncryptedDepositFailed(
        bytes32 indexed depositHash, address indexed sender, address token, uint128 amount
    );

    event DepositFailed(
        bytes32 indexed depositHash,
        address indexed sender,
        address indexed to,
        address token,
        uint128 amount,
        address bouncebackRecipient
    );

    event DepositRejected(
        bytes32 indexed depositHash,
        address indexed sender,
        DepositType depositType,
        address token,
        uint128 amount,
        address bouncebackRecipient
    );

    event WithdrawalBounceBackProcessed(
        address indexed fallbackRecipient, address token, uint128 amount
    );

    event WithdrawalBounceBackPending(
        address indexed fallbackRecipient, address token, uint128 amount
    );

    event RefundClaimed(address indexed recipient, address indexed token, uint128 amount);

    /// @notice Emitted when a TIP-20 token is enabled on the zone via advanceTempo
    event TokenEnabled(address indexed token, string name, string symbol, string currency);

    error OnlySequencer();
    error InvalidDepositQueueHash();
    error MissingDecryptionData();
    error ExtraDecryptionData();
    error InvalidSharedSecretProof();

    /// @notice Zone configuration (reads sequencer from L1)
    function config() external view returns (IZoneConfig);

    /// @notice The Tempo portal address (for reading deposit queue hash)
    function tempoPortal() external view returns (address);

    /// @notice The TempoState predeploy address
    function tempoState() external view returns (ITempoState);

    /// @notice The zone's last processed deposit queue hash
    function processedDepositQueueHash() external view returns (bytes32);

    function processedDepositNumber() external view returns (uint64);

    function refunds(address token, address owner) external view returns (uint128);

    function claimRefund(address token) external returns (uint128 amount);

    /// @notice Advance Tempo state and process deposits in a single sequencer-only call.
    /// @dev This is the main entry point for the sequencer at block start.
    ///      1. Advances the zone's view of Tempo by processing the header
    ///      2. Processes deposits from the unified queue (regular and encrypted)
    ///      3. Validates the resulting hash chain is an ancestor of Tempo's currentDepositQueueHash
    ///
    ///      The sequencer may process a bounded subset of pending deposits.
    ///      The proof validates contiguity: processedDepositQueueHash
    ///      must be an ancestor of (or equal to) Tempo's currentDepositQueueHash.
    ///
    ///      For encrypted deposits, the sequencer provides DecryptionData with the
    ///      ECDH shared secret and proof. ZoneInbox derives (to, memo) onchain.
    ///
    /// @param header RLP-encoded Tempo block header
    /// @param deposits Array of queued deposits to process (oldest first, must be contiguous)
    /// @param decryptions Decryption data for valid encrypted deposits, in order
    /// @param enabledTokens Tokens to enable on the zone via the TIP20 factory
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

    /// @notice Maximum callback data size (1KB)
    function MAX_CALLBACK_DATA_SIZE() external view returns (uint256);

    /// @notice Maximum callback gas accepted for withdrawals
    function MAX_WITHDRAWAL_GAS_LIMIT() external view returns (uint64);

    /// @notice Base gas cost for processing a withdrawal on Tempo (excluding callback)
    function WITHDRAWAL_BASE_GAS() external view returns (uint64);

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

    event MaxWithdrawalsPerBlockUpdated(uint256 maxWithdrawalsPerBlock);

    /// @notice Emitted when sequencer finalizes a batch at end of block
    /// @dev Kept for observability. Proof reads from lastBatch storage instead.
    event BatchFinalized(bytes32 indexed withdrawalQueueHash, uint64 withdrawalBatchIndex);

    /// @notice Zone configuration (reads sequencer from L1)
    function config() external view returns (IZoneConfig);

    /// @notice Tempo gas rate (zone token units per gas unit on Tempo)
    /// @dev Fee = (WITHDRAWAL_BASE_GAS + gasLimit) * tempoGasRate
    function tempoGasRate() external view returns (uint128);

    /// @notice Next withdrawal index (monotonically increasing)
    function nextWithdrawalIndex() external view returns (uint64);

    /// @notice Last nonce assigned to a user withdrawal fallback recipient
    function lastFallbackNonce() external view returns (uint64);

    /// @notice Resolve and delete a fallback recipient. Only callable by ZoneInbox.
    function consumeFallbackRecipient(uint64 fallbackNonce) external returns (address recipient);

    /// @notice Current withdrawal batch index (monotonically increasing)
    function withdrawalBatchIndex() external view returns (uint64);

    /// @notice Last finalized batch parameters (for proof access via state root)
    function lastBatch() external view returns (LastBatch memory);

    /// @notice Number of pending withdrawals
    function pendingWithdrawalsCount() external view returns (uint256);

    /// @notice Pending withdrawals waiting to be finalized
    function getPendingWithdrawals() external view returns (PendingWithdrawal[] memory);

    /// @notice Timestamp of the latest withdrawal batch finalization
    function lastFinalizedTimestamp() external view returns (uint64);

    /// @notice Maximum number of withdrawal requests per zone block (0 = unlimited)
    function maxWithdrawalsPerBlock() external view returns (uint256);

    /// @notice Set Tempo gas rate. Only callable by sequencer.
    /// @dev Sequencer publishes this rate and takes the risk on Tempo gas price fluctuations.
    /// @param _tempoGasRate Zone token units per gas unit on Tempo
    function setTempoGasRate(uint128 _tempoGasRate) external;

    /// @notice Set maximum withdrawal requests per zone block. Only callable by sequencer.
    /// @dev Set to 0 for unlimited. Provides rate-limiting in addition to the gas fee mechanism.
    function setMaxWithdrawalsPerBlock(uint256 _maxWithdrawalsPerBlock) external;

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
        address fallbackRecipient,
        bytes calldata data,
        bytes calldata revealTo
    )
        external;

    function enqueueDepositBounceBack(
        address token,
        uint128 amount,
        address bouncebackRecipient
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

/// @title IZoneConfig
/// @notice Interface for zone configuration and L1 state access
/// @dev System contract predeploy at 0x1c00000000000000000000000000000000000003
///      Provides centralized access to zone metadata and reads sequencer from L1.
interface IZoneConfig {

    error NotSequencer();
    error NoEncryptionKeySet();

    /// @notice L1 ZonePortal address
    function tempoPortal() external view returns (address);

    /// @notice TempoState predeploy for L1 reads
    function tempoState() external view returns (ITempoState);

    /// @notice Get current sequencer by reading from L1 ZonePortal
    /// @dev Reads from finalized Tempo state. L1 is single source of truth.
    function sequencer() external view returns (address);

    /// @notice Get pending sequencer by reading from L1 ZonePortal
    function pendingSequencer() external view returns (address);

    /// @notice Get sequencer's encryption public key by reading from L1 ZonePortal
    /// @dev Used for encrypted deposits (ECIES).
    function sequencerEncryptionKey() external view returns (bytes32 x, uint8 yParity);

    /// @notice Check if an address is the current sequencer
    function isSequencer(address account) external view returns (bool);

    /// @notice Check if a token is enabled by reading from L1 ZonePortal
    function isEnabledToken(address token) external view returns (bool);

}
