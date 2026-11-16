// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {
    BlockTransition,
    Capability,
    Deposit,
    DepositBucket,
    DepositPayload,
    DepositQueueTransition,
    DepositType,
    ENCRYPTION_KEY_GRACE_PERIOD,
    EncryptionKeyEntry,
    IVerifier,
    IZoneFactory,
    IZoneMessenger,
    IZonePortal,
    MAX_WITHDRAWAL_CALLBACK_GAS,
    QueuedDeposit,
    QueuedWithdrawal,
    QueuedWithdrawals,
    Role,
    TokenConfig,
    TokenEnablementTransition,
    VirtualDeposit,
    Withdrawal,
    WithdrawalBounceBackDeposit,
    WithdrawalLimit,
    ZONE_FACTORY_ADDRESS,
    ZONE_PORTAL_IMPL_ADDRESS,
    ZONE_PORTAL_PREFIX
} from "../interfaces/IZone.sol";
import { getBlockHash } from "../libraries/BlockHashHistory.sol";
import { DepositQueueLib } from "../libraries/DepositQueueLib.sol";
import { ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE } from "../libraries/EncryptedDeposit.sol";
import { Secp256k1Lib } from "../libraries/Secp256k1Lib.sol";
import { WithdrawalQueue, WithdrawalQueueLib } from "../libraries/WithdrawalQueueLib.sol";
import { StdPrecompiles } from "tempo-std/StdPrecompiles.sol";
import { IStorageCredits } from "tempo-std/interfaces/IStorageCredits.sol";
import { ITIP20 } from "tempo-std/interfaces/ITIP20.sol";
import { ITIP20Factory } from "tempo-std/interfaces/ITIP20Factory.sol";
import { ITIP403Registry } from "tempo-std/interfaces/ITIP403Registry.sol";

/// @title ZonePortal
/// @notice Per-zone portal that escrows zone tokens on Tempo and manages deposits/withdrawals
contract ZonePortal is IZonePortal {

    using WithdrawalQueueLib for WithdrawalQueue;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice TIP-403 registry for transfer policy authorization checks
    ITIP403Registry internal constant TIP403_REGISTRY =
        ITIP403Registry(StdPrecompiles.TIP403_REGISTRY_ADDRESS);

    /// @notice Fixed gas value for deposit fee calculation
    /// @dev Set to 100,000 gas. Deposit fee = FIXED_DEPOSIT_GAS * zoneGasRate.
    ///      This provides a stable pricing basis for deposits while allowing the admin
    ///      to adjust the zoneGasRate based on operational costs.
    uint64 public constant FIXED_DEPOSIT_GAS = 100_000;

    /// @notice Queue entries between consecutive deposit-queue checkpoints.
    /// @dev Matches the replaced runtime's cap, so the first range after bootstrap fits a block.
    uint64 public constant DEPOSITS_PER_BUCKET = 230;

    /// @notice Unsettled queue entries per congestion price tier.
    /// @dev The first tier is free, matching the depth the replaced runtime admitted.
    uint64 public constant DEPOSITS_PER_CONGESTION_TIER = 230;

    /// @notice Price tiers over which the congestion premium rises linearly to its cap.
    uint64 public constant CONGESTION_MAX_TIER = 32;

    /// @notice Maximum congestion premium on a deposit, in token units.
    uint128 public constant CONGESTION_MAX_FEE = 100_000;

    /// @notice Checkpoints one pruning run may delete.
    /// @dev Appends add at most one checkpoint each, so pruning keeps pace while settlement does.
    uint64 public constant DEPOSIT_BUCKETS_PRUNED_PER_CALL = 2;

    /// @dev Most storage slots one checkpoint write creates: the checkpoint's hash. Its weight
    ///      stays unwritten while every entry weighs one unit.
    uint64 internal constant CHECKPOINT_CREATED_SLOTS = 1;

    /// @dev Most storage slots the bootstrap creates: the base, the array length, and checkpoint 0.
    uint64 internal constant BOOTSTRAP_CREATED_SLOTS = 3;

    /// @notice Maximum enabled tokens that may remain unprocessed by the Zone.
    /// @dev Under T9, processing 230 worst-case deposits plus 8 token enablements with maximum
    ///      metadata uses 214,832,282 gas, below the buffered 225,000,000 gas ceiling.
    uint64 public constant MAX_UNPROCESSED_TOKEN_ENABLEMENTS = 8;

    /// @notice Maximum byte length of each token metadata string copied into the zone.
    /// @dev Keeps name, symbol, and currency in Solidity's one-slot short-string representation.
    uint256 public constant MAX_TOKEN_METADATA_BYTES = 31;

    uint256 internal constant WITHDRAWAL_NOT_ENTERED = 0;
    uint256 internal constant WITHDRAWAL_PROCESSING = 1;
    uint256 internal constant CALLBACK_DEPOSIT_AVAILABLE = 2;
    uint256 internal constant CALLBACK_DEPOSIT_CONSUMED = 3;

    /// @notice Scale factor from 18-decimal Tempo gas prices to 6-decimal TIP-20 units
    uint256 internal constant TEMPO_BASE_FEE_SCALE = 1e12;

    /// @notice Maximum gas a withdrawal callback may request
    /// @dev Over-cap legacy withdrawals are dequeued and bounced back in `processWithdrawals`.
    uint64 public constant MAX_WITHDRAWAL_GAS_LIMIT = MAX_WITHDRAWAL_CALLBACK_GAS;

    /// @notice Maximum allowed gas fee rate to prevent overflows
    uint128 public constant MAX_GAS_FEE_RATE = 1e18;

    /// @notice Maximum number of independently countable settlement signers.
    /// @dev Matches the creation and replacement bound fixed by TIP-1091.
    uint256 public constant MAX_SEQUENCERS = 8;

    /// @notice Duration of every emergency pause.
    uint64 public constant PAUSE_DURATION = 30 days;

    /// @notice Delay before a capability abdication becomes effective.
    uint64 public constant ABDICATION_DELAY = PAUSE_DURATION;

    bytes32 internal constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 internal constant NAME_HASH = keccak256("ZonePortal");
    bytes32 internal constant VERSION_HASH = keccak256("1");
    bytes32 internal constant SETTLEMENT_ATTESTATION_TYPEHASH = keccak256(
        "SettlementAttestation(uint32 zoneId,uint64 sequencerSetVersion,uint256 zoneHeight,uint256 withdrawalBatchIndex,address verifier,uint64 tempoBlockNumber,uint64 anchorBlockNumber,bytes32 anchorBlockHash,bytes32 blockTransitionHash,bytes32 depositQueueTransitionHash,bytes32 tokenEnablementTransitionHash,bytes32 withdrawalQueueHash,bytes32 verifierConfigHash)"
    );
    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Governance admin address
    address public admin;

    /// @notice Zone gas rate (zone token units per gas unit on the zone)
    /// @dev Sequencer publishes this rate and takes the risk on zone gas costs.
    ///      Deposit fee = FIXED_DEPOSIT_GAS * zoneGasRate
    uint128 public zoneGasRate;
    uint64 public withdrawalBatchIndex;
    bytes32 public blockHash;

    /// @notice Current deposit queue hash (where new deposits land)
    bytes32 public currentDepositQueueHash;

    /// @notice Total number of deposits enqueued (monotonic counter, 1-indexed).
    /// @dev Each deposit(), depositEncrypted(), and withdrawal bounce-back increments this.
    ///      The deposit number is emitted in deposit events so users can track their position.
    uint64 public depositCount;

    /// @notice Last deposit number confirmed as processed by a batch proof.
    /// @dev Updated in submitBatch(). A deposit with number N is confirmed once
    ///      lastProcessedDepositNumber >= N.
    uint64 public lastProcessedDepositNumber;

    /// @notice Last Tempo block number the zone has synced to
    uint64 public lastSyncedTempoBlockNumber;

    /// @notice Gas amount used to price a failed-deposit bounce-back on Tempo.
    /// @dev Packed into the unused bytes in slot 4. Defaults to zero.
    uint64 public bouncebackGas;

    /// @notice Historical encryption public keys with activation blocks
    /// @dev Users specify which key they encrypted to (by index). Maintained for key rotation.
    ///      Stored at slot 5 in the ZonePortal storage layout.
    EncryptionKeyEntry[] internal _encryptionKeys;

    /// @notice Per-token configuration (stored at slot 6)
    /// @dev TokenConfig.enabled is permanent (write-once true); depositsActive can be toggled.
    mapping(address => TokenConfig) internal _tokenConfigs;

    /// @notice Append-only list of enabled tokens (stored at slot 7)
    /// @dev Tokens can never be removed from this list (non-custodial guarantee).
    address[] internal _enabledTokens;

    /// @notice Refunds parked after a deposit bounce-back transfer reverts on Tempo.
    mapping(address token => mapping(address owner => uint128 amount)) public refunds;

    /// @notice Withdrawal queue (zone→Tempo): unbounded FIFO
    WithdrawalQueue internal _withdrawalQueue;

    /// @notice Operator RPC endpoint for the zone
    string public rpcUrl;

    /// @notice Pending admin for two-step admin transfer
    address public pendingAdmin;

    /// @notice Reentrancy guard for withdrawal delivery.
    uint256 internal _withdrawalReentrancyStatus;

    /// @notice Zone metadata stored after the cross-domain layout.
    /// @dev These values must remain in account storage so each delegatecall proxy observes its
    ///      own metadata. Keep them after the established slots read directly by zone contracts.
    uint32 public zoneId;
    /// @notice Fixed callback messenger assigned during initialization.
    address public messenger;
    address public verifier;
    bool internal _initialized;

    /// @notice Configuration nonce for the active sequencer set and threshold.
    uint64 public sequencerSetVersion;
    uint8 public sequencerThreshold;
    uint256 public zoneHeight;
    address[] internal _sequencers;
    /// @dev Reserved slot 19, available for future use.
    uint256 private _reservedSlot19;
    /// @dev Mutually exclusive Portal roles. Sequencer membership is derived from this mapping.
    mapping(address => Role) internal role;

    /// @dev Solidity packs both enforcement booleans into slot 21.
    bool internal _isAccessEnforced;
    bool internal _isGatewayEnforced;

    /// @dev Reserve the remainder of slot 21 so the cross-domain fee cap has a dedicated slot.
    uint240 private _enforcementModesPadding;

    /// @notice Maximum Tempo gas rate a sequencer may configure on the zone-side outbox.
    /// @dev Defaults to zero and is read from finalized Tempo state by zone system contracts.
    uint128 public maxTempoGasRate;

    /// @notice Individual sequencer address of the active block-producing leader.
    /// @dev Appended after maxTempoGasRate; do not reorder existing storage. Zone nodes derive
    ///      leadership exclusively from finalized reads of these fields and the LeaderUpdated
    ///      event. Reads as zero for portals initialized before leadership landed; the first
    ///      setLeader from that state bootstraps epoch 1.
    address public leader;

    /// @notice Monotonic fencing epoch, incremented exactly once per real leader change.
    uint64 public leaderEpoch;

    /// @notice Tempo block number that recorded the most recent leader transition.
    uint64 public leaderActivationTempoBlock;

    /// @dev Retired per-Tempo-block deposit admission counters, retained for storage compatibility.
    uint64 internal _depositCountBlock;
    uint64 internal _depositsInCurrentBlock;

    /// @dev Retired per-Tempo-block token-enablement counters, retained for storage compatibility.
    uint64 internal _tokenEnableCountBlock;
    uint64 internal _tokensEnabledInCurrentBlock;

    /// @notice Timestamp at which the current emergency pause expires.
    /// @dev Packed after the token-enablement counter in slot 25.
    uint64 public pauseExpiry;

    /// @notice Append-only commitment to every enabled token and its metadata.
    /// @dev Stored at slot 26.
    bytes32 public tokenEnablementHash;

    /// @notice Time after which the corresponding configuration surface is permanently closed.
    mapping(Capability => uint64) public abdicationEffectiveAt;

    /// @notice Enabled-token prefix confirmed by accepted Zone proofs.
    /// @dev Appended after all T10 storage for upgrade safety.
    uint64 public lastProcessedEnabledTokenCount;

    /// @notice Whether the T13 token cursor has been authenticated by an operational batch.
    bool public tokenEnablementCursorInitialized;

    /// @notice Whether zone-internal TIP-20 transfers are enabled.
    /// @dev Packed after the token cursor flag in slot 28. Defaults to false, so existing zones
    ///      opt in explicitly. Read from finalized Tempo state by the zone TIP-20 precompile.
    bool public transfersEnabled;

    /// @notice Deposit-queue checkpoints (slot 29). Pruning zeroes entries, keeping indices stable.
    DepositBucket[] public depositBuckets;

    // Every append and settlement writes slot 30, so the per-block price snapshot shares it.

    /// @dev Reserved for the cumulative entry weight appended since bootstrap (slot 30).
    ///      Unwritten while every entry weighs one unit.
    uint64 internal depositWeight;

    /// @dev Reserved for the lower bound on the entry weight settled since bootstrap (slot 30).
    ///      Unwritten while every entry weighs one unit.
    uint64 internal settledDepositWeight;

    /// @notice Tempo block whose first append or settlement fixed `depositPriceTier` (slot 30).
    uint64 public depositPriceBlock;

    /// @notice Tier charged in `depositPriceBlock`: start tier, lowered by settlement (slot 30).
    uint64 public depositPriceTier;

    /// @notice `depositCount` when checkpoints bootstrapped (slot 31).
    uint64 public depositBucketBase;

    /// @notice First checkpoint index not yet pruned (slot 31).
    uint64 public nextDepositBucketToPrune;

    /// @dev TIP-1094 minimum accepted key version; zero means the initial minimum of 1. Kept out of
    ///      slot 28, which TIP-1180 fills with the identity registrar and enforcement flag.
    uint8 internal _minimumAddressVersion;

    /// @notice TIP-1150 per-token withdrawal limits (slot 32).
    mapping(address token => WithdrawalLimit) internal _withdrawalLimits;

    /// @notice TIP-1150 per-token queues of withdrawals waiting for limit capacity (slot 33).
    mapping(address token => QueuedWithdrawals) internal _queuedWithdrawals;

    /*//////////////////////////////////////////////////////////////
                             INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    function initialize(
        uint32 _zoneId,
        address _initialToken,
        bool accessEnforced,
        bool gatewayEnforced,
        address[] calldata _allowedAccounts,
        address[] calldata _zoneGateways,
        address _messenger,
        address _admin,
        address[] calldata initialSequencers,
        uint8 _threshold,
        address _verifier,
        string calldata _rpcUrl
    )
        external
        onlyDelegateCall
    {
        if (msg.sender != ZONE_FACTORY_ADDRESS) revert NotFactory();
        if (_initialized) revert AlreadyInitialized();

        _initialized = true;
        zoneId = _zoneId;
        messenger = _messenger;
        admin = _admin;
        verifier = _verifier;
        _isAccessEnforced = accessEnforced;
        _isGatewayEnforced = gatewayEnforced;
        rpcUrl = _rpcUrl;
        emit EnforcementModesUpdated(accessEnforced, gatewayEnforced);

        _replaceSequencerSet(initialSequencers, _threshold, false);
        // The first sequencer bootstraps leadership so a fresh zone has a producer without a
        // separate setLeader call. The creation block is replayed by every zone node because
        // zone genesis anchors before createZone.
        _setLeader(initialSequencers[0]);

        for (uint256 i; i < _zoneGateways.length; ++i) {
            address account = _zoneGateways[i];
            require(role[account] == Role.None);
            role[account] = Role.CallbackGateway;
            emit RoleUpdated(account, Role.None, Role.CallbackGateway);
        }
        for (uint256 i; i < _allowedAccounts.length; ++i) {
            address account = _allowedAccounts[i];
            require(account != _messenger);
            require(role[account] == Role.None);
            role[account] = Role.Account;
            emit RoleUpdated(account, Role.None, Role.Account);
        }

        // Enable the initial token. Operational token enablement remains frozen until a Zone batch
        // authenticates a nonzero enabled-token prefix and initializes the cursor.
        _enableTokenInternal(_initialToken);
    }

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Initialization is valid only in a portal proxy's storage context.
    modifier onlyDelegateCall() {
        if (address(this) == ZONE_PORTAL_IMPL_ADDRESS) revert MustDelegateCall();
        _;
    }

    modifier onlySequencer() {
        if (!isSequencer(msg.sender)) revert NotSequencer();
        _;
    }

    modifier onlySequencerOrAdmin() {
        if (msg.sender != admin && !isSequencer(msg.sender)) revert NotSequencer();
        _;
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    modifier whenNotPaused() {
        if (paused()) revert PortalIsPaused();
        _;
    }

    modifier onlySelf() {
        if (msg.sender != address(this)) revert NotSelf();
        _;
    }

    modifier nonReentrantWithdrawal() {
        if (_withdrawalReentrancyStatus != WITHDRAWAL_NOT_ENTERED) {
            revert ReentrantWithdrawal();
        }
        _withdrawalReentrancyStatus = WITHDRAWAL_PROCESSING;
        _;
        _withdrawalReentrancyStatus = WITHDRAWAL_NOT_ENTERED;
    }

    /// @inheritdoc IZonePortal
    function setSequencerSet(
        address[] calldata newSequencers,
        uint8 newThreshold
    )
        external
        onlyAdmin
    {
        _replaceSequencerSet(newSequencers, newThreshold, true);
    }

    function _replaceSequencerSet(
        address[] calldata newSequencers,
        uint8 newThreshold,
        bool rejectUnchanged
    )
        internal
    {
        uint256 length = newSequencers.length;
        if (length == 0 || length > MAX_SEQUENCERS || newThreshold == 0 || newThreshold > length) {
            revert InvalidSequencerSet();
        }

        for (uint256 i = 0; i < length; ++i) {
            address signer = newSequencers[i];
            if (signer == address(0)) revert InvalidSequencerSet();
            Role existing = role[signer];
            require(existing == Role.None || existing == Role.Sequencer);

            for (uint256 j = 0; j < i; ++j) {
                if (newSequencers[j] == signer) revert InvalidSequencerSet();
            }
        }

        bool membersUnchanged = length == _sequencers.length;
        if (membersUnchanged) {
            for (uint256 i = 0; i < length; ++i) {
                if (!isSequencer(newSequencers[i])) {
                    membersUnchanged = false;
                    break;
                }
            }
        }
        if (rejectUnchanged && membersUnchanged && newThreshold == sequencerThreshold) {
            revert SequencerConfigurationUnchanged();
        }

        for (uint256 i = 0; i < _sequencers.length; ++i) {
            address signer = _sequencers[i];
            role[signer] = Role.None;
            emit RoleUpdated(signer, Role.Sequencer, Role.None);
        }
        delete _sequencers;
        for (uint256 i = 0; i < length; ++i) {
            address signer = newSequencers[i];
            _sequencers.push(signer);
            role[signer] = Role.Sequencer;
            emit RoleUpdated(signer, Role.None, Role.Sequencer);
        }
        // Rotating out the active leader would strand block production: transfer leadership
        // first (add the replacement, setLeader, then remove the old member).
        if (leader != address(0) && !isSequencer(leader)) {
            revert ActiveLeaderRemoved();
        }

        sequencerThreshold = newThreshold;
        uint64 nonce = sequencerSetVersion;
        if (rejectUnchanged) nonce = ++sequencerSetVersion;
        emit SequencerSetUpdated(nonce, newThreshold, newSequencers);
    }

    /// @inheritdoc IZonePortal
    function sequencerCount() external view returns (uint256) {
        return _sequencers.length;
    }

    /// @inheritdoc IZonePortal
    function sequencerAt(uint256 index) external view returns (address) {
        return _sequencers[index];
    }

    /// @inheritdoc IZonePortal
    function isSequencer(address account) public view returns (bool) {
        return role[account] == Role.Sequencer;
    }

    /// @inheritdoc IZonePortal
    function setLeader(address newLeader, uint64 expectedEpoch) external onlySequencerOrAdmin {
        if (!isSequencer(newLeader)) revert InvalidLeader();
        // Idempotent fanout: every node relays the same target, only the first call transitions.
        if (newLeader == leader) return;
        // Compare-and-set: a delayed duplicate carrying a pre-handoff epoch cannot roll
        // leadership back after a later transition.
        if (leaderEpoch != expectedEpoch) {
            revert StaleLeadershipEpoch(expectedEpoch, leaderEpoch);
        }
        // One distinct leader per Tempo block keeps exactly one authorized producer for the
        // corresponding zone block.
        if (leaderActivationTempoBlock == uint64(block.number)) {
            revert LeaderAlreadyUpdatedThisBlock();
        }

        _setLeader(newLeader);
    }

    /// @dev Single write path for a leadership transition: assign, bump the fencing epoch,
    ///      stamp the activation block, emit. `crates/l1` decodes `LeaderUpdated` to drive
    ///      node roles, so every transition must go through here to stay consistent.
    function _setLeader(address newLeader) private {
        address previous = leader;
        leader = newLeader;
        leaderEpoch += 1;
        uint64 activationTempoBlock = uint64(block.number);
        leaderActivationTempoBlock = activationTempoBlock;
        emit LeaderUpdated(previous, newLeader, leaderEpoch, activationTempoBlock);
    }

    /// @notice Set zone gas rate. Only callable by admin.
    /// @dev The admin publishes the operational rate and receives collected deposit fees.
    /// @param _zoneGasRate Zone token units per gas unit on the zone
    function setZoneGasRate(uint128 _zoneGasRate) external onlyAdmin {
        if (_zoneGasRate > MAX_GAS_FEE_RATE) revert GasFeeRateTooHigh();
        zoneGasRate = _zoneGasRate;
        emit ZoneGasRateUpdated(_zoneGasRate);
    }

    /// @notice Set the maximum Tempo gas rate a sequencer may configure on the zone-side outbox.
    function setMaxTempoGasRate(uint128 _maxTempoGasRate) external onlyAdmin {
        if (_maxTempoGasRate > MAX_GAS_FEE_RATE) revert GasFeeRateTooHigh();
        maxTempoGasRate = _maxTempoGasRate;
        emit MaxTempoGasRateUpdated(_maxTempoGasRate);
    }

    /// @notice Set the gas amount used to price failed-deposit bounce-backs on Tempo.
    /// @dev Only the admin can change the amount because it determines the fee deducted from a
    ///      failed deposit at processing time.
    function setBouncebackGas(uint64 _bouncebackGas) external onlyAdmin {
        bouncebackGas = _bouncebackGas;
        emit BouncebackGasUpdated(_bouncebackGas);
    }

    /*//////////////////////////////////////////////////////////////
                             ADMIN MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Start an admin transfer. Only callable by the current admin.
    /// @dev Two-step handoff: the new admin only takes over once it calls
    ///      {acceptAdmin}, which prevents fat-fingered transfers.
    ///      Passing address(0) cancels a pending transfer.
    /// @param newAdmin The address that will become admin after accepting (address(0) cancels).
    function transferAdmin(address newAdmin) external onlyAdmin {
        pendingAdmin = newAdmin;
        emit AdminTransferStarted(admin, newAdmin);
    }

    /// @notice Accept a pending admin transfer. Only callable by the pending admin.
    /// @dev The explicit `pendingAdmin == address(0)` check because it is technically
    ///      possible to make a system tx on L1 with msg.sender == 0.
    ///      The Admin key can only be rotated, never renounced.
    function acceptAdmin() external {
        if (pendingAdmin == address(0) || msg.sender != pendingAdmin) revert NotPendingAdmin();
        address previousAdmin = admin;
        admin = pendingAdmin;
        pendingAdmin = address(0);
        emit AdminTransferred(previousAdmin, admin);
    }

    /// @notice TIP-1094: lowest address key version still accepted.
    function minimumAddressVersion() public view returns (uint8) {
        return _minimumAddressVersion == 0 ? 1 : _minimumAddressVersion;
    }

    /// @notice TIP-1094: raise the minimum accepted address key version. Raise-only.
    function retireAddressVersionsBelow(uint8 minimumVersion) external onlyAdmin {
        // One version per call, so a single mistyped value can't retire every issued address.
        if (minimumVersion != minimumAddressVersion() + 1) {
            revert InvalidVersionRetirement(minimumVersion);
        }
        _minimumAddressVersion = minimumVersion;
        emit AddressVersionsRetired(minimumVersion);
    }

    /// @notice Enable or disable account allowlist enforcement without discarding membership.
    function setAccessMode(bool enforced) external onlyAdmin {
        _requireCapabilityActive(Capability.AccessPolicy);
        _isAccessEnforced = enforced;
        emit EnforcementModesUpdated(enforced, _isGatewayEnforced);
    }

    /// @notice Enable or disable callback gateway registration enforcement.
    function setGatewayMode(bool enforced) external onlyAdmin {
        _requireCapabilityActive(Capability.AccessPolicy);
        _isGatewayEnforced = enforced;
        emit EnforcementModesUpdated(_isAccessEnforced, enforced);
    }

    /// @notice Enable or disable zone-internal TIP-20 transfers.
    function setTransfersEnabled(bool enabled) external onlyAdmin {
        _requireCapabilityActive(Capability.AccessPolicy);
        transfersEnabled = enabled;
        emit TransfersEnabledUpdated(enabled);
    }

    /*//////////////////////////////////////////////////////////////
                           WITHDRAWAL LIMITS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IZonePortal
    /// @dev Not gated by pause or by any Capability abdication.
    function setWithdrawalLimit(address token, uint128 maxAmount, uint64 period) external {
        if (msg.sender != IZoneFactory(ZONE_FACTORY_ADDRESS).owner()) {
            revert NotWithdrawalLimitAuthority();
        }
        // A whole refill rate makes every refill exact.
        bool valid = maxAmount == 0 ? period == 0 : period != 0 && maxAmount % period == 0;
        if (!valid) revert InvalidWithdrawalLimit();

        WithdrawalLimit storage limit = _withdrawalLimits[token];
        if (maxAmount == 0) {
            // Queued records stay queued and are then paid in full.
            delete _withdrawalLimits[token];
        } else {
            // A new limit starts full. A changed limit keeps its capacity refilled under the old
            // limit, capped at the new maxAmount.
            uint128 oldMaxAmount = limit.maxAmount;
            uint128 available =
                oldMaxAmount == 0 ? maxAmount : _refilledCapacity(limit, oldMaxAmount);
            if (available > maxAmount) available = maxAmount;
            limit.maxAmount = maxAmount;
            limit.period = period;
            _setAvailable(limit, available);
        }
        emit WithdrawalLimitSet(token, maxAmount, period);
    }

    /// @inheritdoc IZonePortal
    function withdrawalLimit(address token)
        external
        view
        returns (uint128 maxAmount, uint64 period, uint128 available)
    {
        WithdrawalLimit storage limit = _withdrawalLimits[token];
        maxAmount = limit.maxAmount;
        period = limit.period;
        if (maxAmount != 0) available = _refilledCapacity(limit, maxAmount);
    }

    /// @inheritdoc IZonePortal
    function queuedWithdrawals(address token) external view returns (uint64 head, uint64 tail) {
        QueuedWithdrawals storage queue = _queuedWithdrawals[token];
        return (queue.head, queue.tail);
    }

    /// @inheritdoc IZonePortal
    function queuedWithdrawalAt(
        address token,
        uint256 index
    )
        external
        view
        returns (QueuedWithdrawal memory)
    {
        return _queuedWithdrawals[token].entries[index];
    }

    /// @dev Capacity of a token limited to maxAmount, refilled to block.timestamp, without
    ///      writing it. maxAmount is a multiple of period, so the refill is exact.
    function _refilledCapacity(
        WithdrawalLimit storage limit,
        uint128 maxAmount
    )
        internal
        view
        returns (uint128)
    {
        uint256 refilled = uint256(limit.available) + (block.timestamp - limit.updatedAt)
            * uint256(maxAmount / limit.period);
        return refilled > maxAmount ? maxAmount : uint128(refilled);
    }

    /// @dev Stores capacity as of block.timestamp, in one slot.
    function _setAvailable(WithdrawalLimit storage limit, uint128 available) internal {
        limit.available = available;
        limit.updatedAt = uint64(block.timestamp);
    }

    /// @dev Returns capacity taken by a payout whose delivery failed, capped at maxAmount.
    function _restoreWithdrawalLimit(WithdrawalLimit storage limit, uint128 amount) internal {
        uint128 maxAmount = limit.maxAmount;
        uint256 restored = uint256(limit.available) + amount;
        limit.available = restored > maxAmount ? maxAmount : uint128(restored);
    }

    /// @notice Return whether account allowlist enforcement is enabled.
    function isAccessEnforced() public view returns (bool) {
        return _isAccessEnforced;
    }

    /// @notice Return whether callback gateway registration enforcement is disabled.
    function isGatewayOpen() public view returns (bool) {
        return !_isGatewayEnforced;
    }

    /// @notice Add or remove an account from closed-loop portal flows.
    /// @dev Returns without emitting when already configured. Abdication freezes all changes.
    function setAllowedAccount(address account, bool allowed) external onlyAdmin {
        _requireCapabilityActive(Capability.AccessPolicy);
        if (allowed) require(account != messenger);
        Role previous = role[account];
        Role next = allowed ? Role.Account : Role.None;
        if (previous == next) return;
        require(previous == (allowed ? Role.None : Role.Account));
        role[account] = next;
        emit RoleUpdated(account, previous, next);
    }

    /// @notice Add or remove a callback gateway.
    /// @dev Returns without emitting when already configured. Abdication freezes all changes.
    function setGateway(address account, bool allowed) external onlyAdmin {
        _requireCapabilityActive(Capability.AccessPolicy);
        Role previous = role[account];
        Role next = allowed ? Role.CallbackGateway : Role.None;
        if (previous == next) return;
        require(previous == (allowed ? Role.None : Role.CallbackGateway));
        role[account] = next;
        emit RoleUpdated(account, previous, next);
    }

    /// @notice Add or remove a pause guardian.
    /// @dev Pause-capability abdication freezes both additions and removals.
    function setPauseGuardian(address account, bool allowed) external onlyAdmin {
        _requireCapabilityActive(Capability.PausePortal);
        Role previous = role[account];
        Role next = allowed ? Role.PauseGuardian : Role.None;
        if (previous == next) return;
        require(previous == (allowed ? Role.None : Role.PauseGuardian));
        role[account] = next;
        emit RoleUpdated(account, previous, next);
    }

    function hasRole(address account, Role expected) public view returns (bool) {
        return role[account] == expected;
    }

    /*//////////////////////////////////////////////////////////////
                           QUEUE ACCESSORS
    //////////////////////////////////////////////////////////////*/

    function withdrawalQueueHead() external view returns (uint256) {
        return _withdrawalQueue.head;
    }

    function withdrawalQueueTail() external view returns (uint256) {
        return _withdrawalQueue.tail;
    }

    function withdrawalQueueSlot(uint256 queueIndex) external view returns (bytes32) {
        return _withdrawalQueue.slots[queueIndex];
    }

    /*//////////////////////////////////////////////////////////////
                          TOKEN REGISTRY
    //////////////////////////////////////////////////////////////*/

    /// @notice Check if a token is enabled for bridging
    function isTokenEnabled(address _token) external view returns (bool) {
        return _tokenConfigs[_token].enabled;
    }

    /// @notice Check if deposits are currently active for a token
    function areDepositsActive(address _token) external view returns (bool) {
        TokenConfig storage cfg = _tokenConfigs[_token];
        return !paused() && cfg.enabled && cfg.depositsActive;
    }

    /// @notice Get the token configuration for a specific token
    function tokenConfig(address _token) external view returns (TokenConfig memory) {
        return _tokenConfigs[_token];
    }

    /// @notice Get the number of enabled tokens
    function enabledTokenCount() external view returns (uint256) {
        return _enabledTokens.length;
    }

    /// @notice Get an enabled token by index
    function enabledTokenAt(uint256 index) external view returns (address) {
        return _enabledTokens[index];
    }

    /// @notice Whether deposits, withdrawal processing, and refund claims are paused.
    /// @dev The pause expires automatically once block.timestamp reaches pauseExpiry.
    function paused() public view returns (bool) {
        return block.timestamp < pauseExpiry;
    }

    /// @notice Pause deposits, withdrawal processing, and refund claims for 30 days.
    function pause() external whenNotPaused {
        _requireCapabilityActive(Capability.PausePortal);
        if (
            msg.sender != admin && !isSequencer(msg.sender)
                && !hasRole(msg.sender, Role.PauseGuardian)
        ) {
            revert NotPauseAuthority();
        }
        pauseExpiry = uint64(block.timestamp) + PAUSE_DURATION;
        emit PortalPaused(msg.sender);
    }

    /// @notice Resume deposits, withdrawal processing, and refund claims before expiry.
    /// @dev Admin recovery remains available after the pause capability is abdicated.
    function resume() external onlyAdmin {
        pauseExpiry = 0;
        emit PortalResumed(msg.sender);
    }

    /// @notice Schedule permanent abdication of a Portal configuration surface.
    function abdicate(Capability capability) external onlyAdmin whenNotPaused {
        if (abdicationEffectiveAt[capability] != 0) revert AbdicationAlreadyScheduled(capability);
        uint64 effectiveAt = uint64(block.timestamp) + ABDICATION_DELAY;
        abdicationEffectiveAt[capability] = effectiveAt;
        emit AbdicationScheduled(capability, effectiveAt);
    }

    function _requireCapabilityActive(Capability capability) internal view {
        uint64 effectiveAt = abdicationEffectiveAt[capability];
        if (effectiveAt != 0 && block.timestamp >= effectiveAt) {
            revert CapabilityAbdicated(capability);
        }
    }

    /// @notice Enable a new TIP-20 token for bridging. Only callable by admin.
    /// @dev Irreversible: once enabled, a token cannot be disabled. Frozen until the first Zone
    ///      batch authenticates the enabled-token cursor.
    function enableToken(address _token) external onlyAdmin {
        if (_tokenConfigs[_token].enabled) revert TokenAlreadyEnabled();
        if (!ITIP20Factory(StdPrecompiles.TIP20_FACTORY_ADDRESS).isTIP20(_token)) {
            revert TokenNotEnabled();
        }
        if (!tokenEnablementCursorInitialized) revert TokenEnablementCursorNotInitialized();
        if (
            _enabledTokens.length - lastProcessedEnabledTokenCount
                >= MAX_UNPROCESSED_TOKEN_ENABLEMENTS
        ) {
            revert TokenEnablementBlockCapacityExceeded(MAX_UNPROCESSED_TOKEN_ENABLEMENTS);
        }
        _enableTokenInternal(_token);
    }

    /// @notice Pause deposits for a token. Only callable by admin.
    /// @dev Does not affect withdrawal processing (non-custodial guarantee).
    function pauseDeposits(address _token) external onlyAdmin {
        if (!_tokenConfigs[_token].enabled) revert TokenNotEnabled();
        _tokenConfigs[_token].depositsActive = false;
        emit DepositsPaused(_token);
    }

    /// @notice Resume deposits for a token. Only callable by admin.
    function resumeDeposits(address _token) external onlyAdmin {
        if (!_tokenConfigs[_token].enabled) revert TokenNotEnabled();
        _tokenConfigs[_token].depositsActive = true;
        emit DepositsResumed(_token);
    }

    /// @notice Internal function to enable a token (used by initializer and enableToken)
    function _enableTokenInternal(address _token) internal {
        // Bound the metadata copied into the zone before mutating portal or policy state. The zone
        // must initialize every token emitted in this block inside advanceTempo's fixed gas budget.
        string memory name = ITIP20(_token).name();
        string memory symbol = ITIP20(_token).symbol();
        string memory currency = ITIP20(_token).currency();
        if (
            bytes(name).length > MAX_TOKEN_METADATA_BYTES
                || bytes(symbol).length > MAX_TOKEN_METADATA_BYTES
                || bytes(currency).length > MAX_TOKEN_METADATA_BYTES
        ) {
            revert TokenMetadataTooLong();
        }

        address[] memory tokens = new address[](1);
        tokens[0] = _token;

        (bool isSet,) = TIP403_REGISTRY.tokenTransferPolicyId(_token);
        if (!isSet) {
            TIP403_REGISTRY.migrateTransferPolicyIds(tokens);
            (isSet,) = TIP403_REGISTRY.tokenTransferPolicyId(_token);
        }
        if (!isSet) {
            revert TokenTransferPolicyNotSet();
        }

        tokenEnablementHash =
            keccak256(abi.encode(tokenEnablementHash, _token, name, symbol, currency));
        _tokenConfigs[_token] = TokenConfig({ enabled: true, depositsActive: true });
        _enabledTokens.push(_token);

        emit TokenEnabled(_token, name, symbol, currency);
    }

    /// @notice Update the zone's operator RPC endpoint.
    /// @param _rpcUrl The new RPC url
    function setRpcUrl(string calldata _rpcUrl) external onlySequencer {
        rpcUrl = _rpcUrl;
        emit RpcUrlUpdated(_rpcUrl);
    }

    /*//////////////////////////////////////////////////////////////
                        ENCRYPTION KEY MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the sequencer's current encryption public key
    /// @return x The X coordinate
    /// @return yParity The Y coordinate parity (0x02 or 0x03)
    /// @return pubkey The address derived from the public key
    function sequencerEncryptionKey()
        external
        view
        returns (bytes32 x, uint8 yParity, address pubkey)
    {
        if (_encryptionKeys.length == 0) revert NoEncryptionKeySet();
        EncryptionKeyEntry storage current = _encryptionKeys[_encryptionKeys.length - 1];
        return (current.x, current.yParity, Secp256k1Lib.deriveAddress(current.x, current.yParity));
    }

    /// @notice Set the sequencer's encryption public key with proof of possession from its private key
    /// @dev Only callable by an active sequencer or the admin. Appends to key history.
    ///      No reentrancy guard is needed because this function makes no unrestricted external
    ///      calls; its only external calls are to fixed cryptographic precompiles.
    ///      Requires a valid ECDSA signature over keccak256(abi.encode(address(this), x, yParity))
    ///      produced by the private key corresponding to (x, yParity). This prevents accidental
    ///      registration of keys the sequencer cannot decrypt with.
    /// @param x The X coordinate (must be valid secp256k1 point)
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
        external
        onlySequencerOrAdmin
    {
        // Validate yParity
        if (!Secp256k1Lib.isCompressedYParity(yParity)) revert InvalidEphemeralPubkey();

        // Validate x is on the secp256k1 curve
        if (!Secp256k1Lib.isValidX(x)) revert InvalidEphemeralPubkey();

        // Verify proof of possession: the caller must prove control of the encryption private key.
        bytes32 message = keccak256(abi.encode(address(this), x, yParity));
        address recovered = ecrecover(message, popV, popR, popS);
        address expected = Secp256k1Lib.deriveAddress(x, yParity);
        if (recovered == address(0) || recovered != expected) {
            revert InvalidProofOfPossession();
        }

        uint64 activationBlock = uint64(block.number);
        _encryptionKeys.push(
            EncryptionKeyEntry({ x: x, yParity: yParity, activationBlock: activationBlock })
        );
        emit SequencerEncryptionKeyUpdated(
            x, yParity, expected, _encryptionKeys.length - 1, activationBlock
        );
    }

    /// @notice Get the number of keys in the history
    function encryptionKeyCount() external view returns (uint256) {
        return _encryptionKeys.length;
    }

    /// @notice Get a historical encryption key by index
    /// @param index The index in the key history (0 = first key)
    /// @return entry The key entry with activation block
    function encryptionKeyAt(uint256 index)
        external
        view
        returns (EncryptionKeyEntry memory entry)
    {
        if (index >= _encryptionKeys.length) {
            revert InvalidEncryptionKeyIndex(index);
        }
        return _encryptionKeys[index];
    }

    /// @notice Get the encryption key that was active at a specific Tempo block
    /// @dev Binary search through key history to find the correct key
    /// @param tempoBlockNumber The Tempo block number to query
    /// @return x The X coordinate of the active key
    /// @return yParity The Y coordinate parity
    /// @return keyIndex The index of this key in history
    function encryptionKeyAtBlock(uint64 tempoBlockNumber)
        external
        view
        returns (bytes32 x, uint8 yParity, uint256 keyIndex)
    {
        uint256 len = _encryptionKeys.length;
        if (len == 0 || tempoBlockNumber < _encryptionKeys[0].activationBlock) {
            revert NoEncryptionKeyAtBlock(tempoBlockNumber);
        }

        uint256 low = 0;
        uint256 high = len - 1;
        while (low < high) {
            uint256 mid = (low + high + 1) / 2;
            if (_encryptionKeys[mid].activationBlock <= tempoBlockNumber) {
                low = mid;
            } else {
                high = mid - 1;
            }
        }

        EncryptionKeyEntry storage entry = _encryptionKeys[low];
        return (entry.x, entry.yParity, low);
    }

    /// @notice Check if an encryption key is still valid for new deposits
    /// @param keyIndex The key index to check
    /// @return valid True if the key can be used for new deposits
    /// @return expiresAtBlock Block number when this key expires (0 if current key)
    function isEncryptionKeyValid(uint256 keyIndex)
        public
        view
        returns (bool valid, uint64 expiresAtBlock)
    {
        if (keyIndex >= _encryptionKeys.length) {
            return (false, 0);
        }

        // Current key (latest) never expires
        if (keyIndex == _encryptionKeys.length - 1) {
            return (true, 0);
        }

        // Old keys are valid during grace period after supersession
        EncryptionKeyEntry storage nextKey = _encryptionKeys[keyIndex + 1];
        uint64 expiration = nextKey.activationBlock + ENCRYPTION_KEY_GRACE_PERIOD;

        valid = block.number < expiration;
        expiresAtBlock = expiration;
    }

    /*//////////////////////////////////////////////////////////////
                               DEPOSITS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IZonePortal
    /// @return fee The deposit fee in zone token units
    function calculateDepositFee() external view returns (uint128 fee) {
        fee = _operationalDepositFee() + _congestionFee(_unsettledCongestionTier());
    }

    function _operationalDepositFee() internal view returns (uint128) {
        return uint128(FIXED_DEPOSIT_GAS) * zoneGasRate;
    }

    /// @dev The tier of the entries unsettled in the current state.
    function _unsettledCongestionTier() internal view returns (uint64) {
        return (depositCount - lastProcessedDepositNumber) / DEPOSITS_PER_CONGESTION_TIER;
    }

    function _congestionFee(uint64 tier) internal pure returns (uint128) {
        uint64 rampedTiers = tier < CONGESTION_MAX_TIER ? tier : CONGESTION_MAX_TIER;
        return CONGESTION_MAX_FEE * rampedTiers / CONGESTION_MAX_TIER;
    }

    /// @notice Calculate the reserved fee for a failed-deposit bounce-back
    /// @dev Fee = ceil(bouncebackGas * block.basefee / 1e12)
    /// @return fee The bounce-back fee in token units
    function calculateBouncebackFee() public view returns (uint128 fee) {
        uint256 gasFee = uint256(bouncebackGas) * block.basefee;
        // Round up after scaling so bounce-backs do not underpay.
        fee = uint128((gasFee + TEMPO_BASE_FEE_SCALE - 1) / TEMPO_BASE_FEE_SCALE);
    }

    function _validateDepositsActive(address _token) internal view {
        TokenConfig storage cfg = _tokenConfigs[_token];
        if (!cfg.enabled) revert TokenNotEnabled();
        if (!cfg.depositsActive) revert DepositsNotActive();
    }

    function _requireAllowed(address account) internal view {
        if (!_isAllowed(account)) revert AccountNotAllowed(account);
    }

    function _requireAllowedDepositor(address account) internal view {
        if (!_isAccessEnforced) return;
        if (_isGatewayEnforced && hasRole(account, Role.CallbackGateway)) {
            return;
        }
        if (!hasRole(account, Role.Account)) revert AccountNotAllowed(account);
    }

    function _isAllowed(address account) internal view returns (bool) {
        return !_isAccessEnforced || hasRole(account, Role.Account);
    }

    function _collectDepositFunds(
        address _token,
        uint128 amount,
        uint128 maxFee
    )
        internal
        returns (uint128 fee, uint128 netAmount)
    {
        (fee, netAmount) = _chargeDepositFee(amount, maxFee);

        // TIP-20 transfers revert on failure, so no boolean check is needed here.
        ITIP20(_token).transferFrom(msg.sender, address(this), amount);
        if (fee > 0) {
            ITIP20(_token).transfer(admin, fee);
        }
    }

    /// @dev The fee for one deposit of `amount`, reverting above `maxFee` or when too little is
    ///      left for a bounce-back.
    function _chargeDepositFee(
        uint128 amount,
        uint128 maxFee
    )
        internal
        returns (uint128 fee, uint128 netAmount)
    {
        fee = _operationalDepositFee();
        // A withdrawal callback may return one deposit, which already paid Zone fees.
        if (_withdrawalReentrancyStatus == CALLBACK_DEPOSIT_AVAILABLE) {
            _withdrawalReentrancyStatus = CALLBACK_DEPOSIT_CONSUMED;
        } else {
            // Neither entries nor settlements earlier in the block can raise the tier.
            fee += _congestionFee(_snapshotCongestionTier());
        }
        if (fee > maxFee) revert FeeTooHigh(fee, maxFee);
        if (amount < fee + calculateBouncebackFee()) revert DepositTooSmall();
        netAmount = amount - fee;
    }

    /// @dev Returns this block's tier, fixed from the state before the block's first change.
    function _snapshotCongestionTier() internal returns (uint64 tier) {
        if (depositPriceBlock == block.number) return depositPriceTier;
        tier = _unsettledCongestionTier();
        depositPriceBlock = uint64(block.number);
        depositPriceTier = tier;
    }

    /// @dev Appends one entry, checkpointing every `DEPOSITS_PER_BUCKET` entries.
    /// TODO: weigh entries as TIP-1171 specifies once an entry type weighs more than 1 unit.
    function _recordDeposit(bytes32 newCurrentDepositQueueHash)
        internal
        returns (uint64 thisDeposit)
    {
        // Checkpoint writes spend TIP-1060 credits directly. No external call runs before `Refund`.

        // Older runtimes stored no checkpoints. The first append starts them at the queue head.
        if (depositBuckets.length == 0) {
            StdPrecompiles.STORAGE_CREDITS.setBudget(BOOTSTRAP_CREATED_SLOTS);
            depositBucketBase = depositCount;
            depositBuckets.push().hash = currentDepositQueueHash;
            StdPrecompiles.STORAGE_CREDITS.setMode(IStorageCredits.Mode.Refund);
        }

        // Exempt entries also fix the block's price before they count toward it.
        _snapshotCongestionTier();

        currentDepositQueueHash = newCurrentDepositQueueHash;
        thisDeposit = ++depositCount;

        // Prune first so the checkpoint write can spend the credits that frees.
        // `processWithdrawals` prunes once, before the entries it appends.
        if (_withdrawalReentrancyStatus == WITHDRAWAL_NOT_ENTERED) {
            _pruneDepositBuckets();
        }

        if ((thisDeposit - depositBucketBase) % DEPOSITS_PER_BUCKET == 0) {
            StdPrecompiles.STORAGE_CREDITS.setBudget(CHECKPOINT_CREATED_SLOTS);
            depositBuckets.push().hash = newCurrentDepositQueueHash;
            StdPrecompiles.STORAGE_CREDITS.setMode(IStorageCredits.Mode.Refund);
        }
    }

    /// @dev Deletes up to `DEPOSIT_BUCKETS_PRUNED_PER_CALL` checkpoints whose successor is settled.
    function _pruneDepositBuckets() internal {
        uint64 first = nextDepositBucketToPrune;
        uint64 end = first + DEPOSIT_BUCKETS_PRUNED_PER_CALL;
        uint256 length = depositBuckets.length;
        uint64 base = depositBucketBase;
        uint64 settled = lastProcessedDepositNumber;
        uint64 next;
        for (next = first; next < end && next < length; ++next) {
            if (base + (next + 1) * DEPOSITS_PER_BUCKET > settled) break;
            delete depositBuckets[next];
        }
        if (next != first) nextDepositBucketToPrune = next;
    }

    /// @notice Alias for `depositEncrypted`.
    function deposit(
        address _token,
        uint128 amount,
        uint256 keyIndex,
        DepositPayload calldata encrypted,
        address tempoRefundRecipient
    )
        external
        whenNotPaused
        returns (bytes32 newCurrentDepositQueueHash)
    {
        return _deposit(
            _token, amount, keyIndex, encrypted, tempoRefundRecipient, _operationalDepositFee()
        );
    }

    /// @inheritdoc IZonePortal
    function deposit(
        address _token,
        uint128 amount,
        uint256 keyIndex,
        DepositPayload calldata encrypted,
        address tempoRefundRecipient,
        uint128 maxFee
    )
        external
        whenNotPaused
        returns (bytes32 newCurrentDepositQueueHash)
    {
        return _deposit(_token, amount, keyIndex, encrypted, tempoRefundRecipient, maxFee);
    }

    /// @notice Deposit with encrypted recipient and memo
    /// @dev The encrypted payload contains (to, memo) encrypted to the sequencer's key.
    ///      The token identity is public (not encrypted) since the portal must escrow it.
    ///      Validates that keyIndex is valid (exists and not expired).
    ///      Charges the configured zone deposit fee.
    /// @param _token The TIP-20 token to deposit
    /// @param amount Amount to deposit (fee deducted from this amount)
    /// @param keyIndex Index of the encryption key used (from encryptionKeyAt)
    /// @param encrypted The encrypted payload (recipient and memo)
    /// @return newCurrentDepositQueueHash The new deposit queue hash
    function depositEncrypted(
        address _token,
        uint128 amount,
        uint256 keyIndex,
        DepositPayload calldata encrypted,
        address tempoRefundRecipient
    )
        external
        whenNotPaused
        returns (bytes32 newCurrentDepositQueueHash)
    {
        return _deposit(
            _token, amount, keyIndex, encrypted, tempoRefundRecipient, _operationalDepositFee()
        );
    }

    /// @inheritdoc IZonePortal
    function depositEncrypted(
        address _token,
        uint128 amount,
        uint256 keyIndex,
        DepositPayload calldata encrypted,
        address tempoRefundRecipient,
        uint128 maxFee
    )
        external
        whenNotPaused
        returns (bytes32 newCurrentDepositQueueHash)
    {
        return _deposit(_token, amount, keyIndex, encrypted, tempoRefundRecipient, maxFee);
    }

    /// @notice TIP-1094: queue a TIP-20 transfer to a zone deposit address.
    /// @dev Called by native TIP-20 routing after it debited `originator` and credited this
    ///      portal with `grossAmount`; `msg.sender` is the token. The tokens are already here,
    ///      so nothing is pulled. Any revert reverts the whole transfer.
    function depositVirtual(
        address originator,
        uint128 grossAmount,
        address destination,
        bool hasMemo,
        bytes32 memo
    )
        external
        whenNotPaused
        returns (bytes32 newCurrentDepositQueueHash)
    {
        address token = msg.sender;
        // Only an enabled canonical TIP-20 can call this; ordinary accounts and contracts are
        // never enabled tokens.
        if (bytes12(bytes20(token)) != bytes12(0x20c000000000000000000000)) {
            revert TokenNotEnabled();
        }
        if (!hasMemo && memo != bytes32(0)) revert InvalidVirtualDeposit();
        if (!_isZoneDepositAddress(destination) || uint32(bytes4(bytes20(destination))) != zoneId) {
            revert InvalidVirtualDeposit();
        }
        uint8 version = uint8(bytes20(destination)[13]);
        if (version < minimumAddressVersion()) revert AddressVersionRetired(version);

        // Existing deposit checks, applied to the debited account.
        // A portal is the originator when a zone withdrawal pays out to a deposit address. A refund
        // to a portal would credit no one, so revert and let the withdrawal bounce back instead.
        if (originator == address(0) || bytes12(bytes20(originator)) == ZONE_PORTAL_PREFIX) {
            revert InvalidBouncebackRecipient();
        }
        _requireAllowedDepositor(originator);
        _requireAllowed(originator);
        _validateDepositsActive(token);
        uint64 policyId = ITIP20(token).transferPolicyId();
        if (!TIP403_REGISTRY.isAuthorizedRecipient(policyId, originator)) {
            revert ITIP20.PolicyForbids();
        }

        // A plain transfer cannot pass `maxFee`, so it accepts only the operational fee, like the
        // legacy deposit signatures: during congestion the transfer reverts with `FeeTooHigh`.
        (uint128 fee, uint128 netAmount) = _chargeDepositFee(grossAmount, _operationalDepositFee());
        if (fee > 0) {
            ITIP20(token).transfer(admin, fee);
        }

        VirtualDeposit memory depositData = VirtualDeposit({
            token: token,
            originator: originator,
            amount: netAmount,
            destination: destination,
            hasMemo: hasMemo,
            memo: memo
        });
        newCurrentDepositQueueHash =
            DepositQueueLib.enqueueVirtual(currentDepositQueueHash, depositData);

        uint64 thisDeposit = _recordDeposit(newCurrentDepositQueueHash);

        emit VirtualDepositMade(
            newCurrentDepositQueueHash,
            originator,
            token,
            destination,
            netAmount,
            fee,
            thisDeposit,
            hasMemo,
            memo
        );
    }

    function _deposit(
        address _token,
        uint128 amount,
        uint256 keyIndex,
        DepositPayload calldata encrypted,
        address tempoRefundRecipient,
        uint128 maxFee
    )
        internal
        returns (bytes32 newCurrentDepositQueueHash)
    {
        if (tempoRefundRecipient == address(0)) revert InvalidBouncebackRecipient();
        // Refunds are claimed by msg.sender, which can never be a TIP-1022 virtual address or a
        // TIP-1094 zone deposit address.
        if (
            StdPrecompiles.ADDRESS_REGISTRY.isVirtualAddress(tempoRefundRecipient)
                || _isZoneDepositAddress(tempoRefundRecipient)
        ) {
            revert InvalidBouncebackRecipient();
        }
        // Enforced gateways may deposit callback returns without also being allowed accounts.
        _requireAllowedDepositor(msg.sender);
        _requireAllowed(tempoRefundRecipient);

        _validateDepositsActive(_token);

        uint64 policyId = ITIP20(_token).transferPolicyId();
        if (!TIP403_REGISTRY.isAuthorizedRecipient(policyId, tempoRefundRecipient)) {
            revert ITIP20.PolicyForbids();
        }

        // Validate ephemeral public key is a valid secp256k1 point
        // Prevents griefing: invalid points make Chaum-Pedersen proofs impossible,
        // which would block chain progress on the zone side.
        if (!Secp256k1Lib.isCompressedYParity(encrypted.ephemeralPubkeyYParity)) {
            revert InvalidEphemeralPubkey();
        }
        if (!Secp256k1Lib.isValidX(encrypted.ephemeralPubkeyX)) {
            revert InvalidEphemeralPubkey();
        }

        // Validate ciphertext length — GCM ciphertext == plaintext length (tag is separate)
        // Prevents DoS: oversized ciphertexts inflate zone-side AES-GCM processing cost
        if (encrypted.ciphertext.length != ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE) {
            revert InvalidCiphertextLength(
                encrypted.ciphertext.length, ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE
            );
        }

        // Validate encryption key
        (bool valid,) = isEncryptionKeyValid(keyIndex);
        if (!valid) {
            if (keyIndex >= _encryptionKeys.length) {
                revert InvalidEncryptionKeyIndex(keyIndex);
            }
            EncryptionKeyEntry storage key = _encryptionKeys[keyIndex];
            EncryptionKeyEntry storage nextKey = _encryptionKeys[keyIndex + 1];
            revert EncryptionKeyExpired(keyIndex, key.activationBlock, nextKey.activationBlock);
        }

        (uint128 fee, uint128 netAmount) = _collectDepositFunds(_token, amount, maxFee);

        // Build the queued deposit.
        Deposit memory depositData = Deposit({
            token: _token,
            sender: msg.sender,
            amount: netAmount,
            tempoRefundRecipient: tempoRefundRecipient,
            keyIndex: keyIndex,
            encrypted: encrypted
        });

        // Insert the deposit into the queue.
        newCurrentDepositQueueHash =
            DepositQueueLib.enqueueDeposit(currentDepositQueueHash, depositData);
        uint64 thisDeposit = _recordDeposit(newCurrentDepositQueueHash);

        emit DepositMade(
            newCurrentDepositQueueHash,
            msg.sender,
            _token,
            netAmount,
            fee,
            keyIndex,
            encrypted.ephemeralPubkeyX,
            encrypted.ephemeralPubkeyYParity,
            encrypted.ciphertext,
            encrypted.nonce,
            encrypted.tag,
            tempoRefundRecipient,
            thisDeposit
        );
    }

    /*//////////////////////////////////////////////////////////////
                             WITHDRAWALS
    //////////////////////////////////////////////////////////////*/

    /// @notice Process multiple withdrawals from the queue in a single transaction.
    /// @dev Withdrawals must be supplied in queue order. `remainingQueue` is the queue suffix
    ///      after the last supplied withdrawal, or zero if the batch exhausts the current slot.
    ///      Plain-transfer and callback failures bounce back without blocking the FIFO.
    function processWithdrawals(
        Withdrawal[] calldata withdrawals,
        bytes32 remainingQueue
    )
        external
        onlySequencer
        whenNotPaused
        nonReentrantWithdrawal
    {
        bytes32[] memory remainingQueues = new bytes32[](withdrawals.length);
        bytes32 nextQueue = remainingQueue;

        for (uint256 i = withdrawals.length; i > 0; --i) {
            remainingQueues[i - 1] = nextQueue;
            nextQueue = keccak256(abi.encode(withdrawals[i - 1], nextQueue));
        }

        // One pruning run frees credits for every checkpoint this call appends.
        _pruneDepositBuckets();

        for (uint256 i; i < withdrawals.length; ++i) {
            Withdrawal calldata withdrawal = withdrawals[i];
            // Pop from withdrawal queue (library handles swap and hash verification)
            _withdrawalQueue.dequeue(withdrawal, remainingQueues[i]);
            _processWithdrawal(withdrawal);
        }
    }

    /// @dev Pays, bounces or queues one dequeued main-queue entry.
    function _processWithdrawal(Withdrawal calldata withdrawal) internal {
        address _token = withdrawal.token;
        uint128 amount = withdrawal.amount;
        bool isUserWithdrawal = withdrawal.fallbackNonce != 0;

        // Over-cap user withdrawals bounce before the limit applies and pay nothing out of escrow.
        // Deposit bounce-backs are never exempt this way, whatever their gasLimit.
        if (isUserWithdrawal && withdrawal.gasLimit > MAX_WITHDRAWAL_GAS_LIMIT) {
            _bounceWithdrawal(withdrawal);
            return;
        }

        QueuedWithdrawals storage tokenQueue = _queuedWithdrawals[_token];
        if (tokenQueue.head == tokenQueue.tail) {
            WithdrawalLimit storage limit = _withdrawalLimits[_token];
            uint128 maxAmount = limit.maxAmount;
            if (maxAmount == 0) {
                _payWithdrawal(withdrawal);
                return;
            }
            uint128 available = _refilledCapacity(limit, maxAmount);
            if (amount <= available) {
                // Charged before delivery, because a callback can reenter claimRefund.
                _setAvailable(limit, available - amount);
                uint128 unpaid = _payWithdrawal(withdrawal);
                if (unpaid != 0) _restoreWithdrawalLimit(limit, unpaid);
                return;
            }
        }

        if (isUserWithdrawal && withdrawal.gasLimit != 0) {
            // A callback that cannot be delivered now bounces back to the zone, including one
            // larger than maxAmount.
            _bounceWithdrawal(withdrawal);
        } else {
            _queueWithdrawal(withdrawal);
        }
    }

    /// @dev Delivers a whole main-queue entry, bouncing a failed user withdrawal back to the zone.
    /// @return unpaid Amount that did not leave escrow: all of a bounced user withdrawal, or the
    ///         refund a deposit bounce-back parked in refunds.
    function _payWithdrawal(Withdrawal calldata withdrawal) internal returns (uint128 unpaid) {
        uint128 amount = withdrawal.amount;
        if (withdrawal.fallbackNonce == 0) {
            uint128 bouncebackFee = calculateBouncebackFee();
            if (bouncebackFee > amount) bouncebackFee = amount;
            (bool refunded, uint128 collectedFee) = _processDepositBounceBack(
                withdrawal.token, withdrawal.to, amount, amount, bouncebackFee
            );
            return refunded ? 0 : amount - collectedFee;
        }
        if (!_deliverWithdrawal(withdrawal)) {
            _bounceWithdrawal(withdrawal);
            return amount;
        }
    }

    /// @dev Appends a plain withdrawal or deposit bounce-back to the tail of its token queue,
    ///      storing only what its payout reads.
    function _queueWithdrawal(Withdrawal calldata withdrawal) internal {
        address _token = withdrawal.token;
        QueuedWithdrawals storage tokenQueue = _queuedWithdrawals[_token];
        uint64 queueIndex = tokenQueue.tail;
        // A deposit bounce-back's payout emits no senderTag, so its record leaves that slot empty.
        bytes32 senderTag = withdrawal.fallbackNonce != 0 ? withdrawal.senderTag : bytes32(0);
        tokenQueue.entries[queueIndex] = QueuedWithdrawal({
            to: withdrawal.to,
            fallbackNonce: withdrawal.fallbackNonce,
            partlyPaid: false,
            senderTag: senderTag,
            remaining: withdrawal.amount
        });
        tokenQueue.tail = queueIndex + 1;
        emit WithdrawalQueued(
            _token,
            queueIndex,
            withdrawal.to,
            withdrawal.amount,
            senderTag,
            withdrawal.fallbackNonce
        );
    }

    /// @inheritdoc IZonePortal
    /// @dev Refills capacity once, then pays records in order from the head. Paying a token queue
    ///      runs no external code, so capacity is tracked in memory and written once at the end.
    function processQueuedWithdrawals(
        address token,
        uint256 maxEntries
    )
        external
        whenNotPaused
        nonReentrantWithdrawal
        returns (uint256 completed)
    {
        QueuedWithdrawals storage tokenQueue = _queuedWithdrawals[token];
        WithdrawalLimit storage limit = _withdrawalLimits[token];

        // One pruning run frees credits for every bounce-back this call appends.
        _pruneDepositBuckets();

        uint64 head = tokenQueue.head;
        uint64 tail = tokenQueue.tail;
        uint128 maxAmount = limit.maxAmount;
        uint128 available = maxAmount == 0 ? 0 : _refilledCapacity(limit, maxAmount);

        for (; completed < maxEntries && head < tail; ++completed) {
            bool complete;
            (complete, available) =
                _payQueuedWithdrawal(token, tokenQueue.entries[head], head, maxAmount, available);
            if (!complete) break;
            delete tokenQueue.entries[head];
            ++head;
        }

        tokenQueue.head = head;
        if (maxAmount != 0) _setAvailable(limit, available);
    }

    /// @dev Makes one payment on a token-queue record: its remainder, or maxAmount if smaller,
    ///      once available covers it. Token queues hold only plain withdrawals and deposit
    ///      bounce-backs.
    /// @return complete True if the record was fully paid, bounced back to the zone or parked.
    /// @return newAvailable Capacity left after this payment; unchanged for a token with no limit.
    function _payQueuedWithdrawal(
        address token,
        QueuedWithdrawal storage entry,
        uint64 queueIndex,
        uint128 maxAmount,
        uint128 available
    )
        internal
        returns (bool complete, uint128 newAvailable)
    {
        newAvailable = available;
        uint128 remaining = entry.remaining;
        uint128 pay = maxAmount == 0 || remaining <= maxAmount ? remaining : maxAmount;
        if (maxAmount != 0 && available < pay) return (false, available);
        address to = entry.to;
        uint64 fallbackNonce = entry.fallbackNonce;

        if (fallbackNonce == 0) {
            // The fee is attempted once, on the first payment, and capped at that payment.
            uint128 bouncebackFee;
            if (!entry.partlyPaid) {
                bouncebackFee = calculateBouncebackFee();
                if (bouncebackFee > pay) bouncebackFee = pay;
            }
            (bool refunded, uint128 collectedFee) =
                _processDepositBounceBack(token, to, pay, remaining, bouncebackFee);
            if (!refunded) {
                // The whole remainder is parked, which consumes no capacity. Only the fee left.
                if (maxAmount != 0) newAvailable = available - collectedFee;
                emit QueuedWithdrawalPaid(token, queueIndex, collectedFee, 0);
                return (true, newAvailable);
            }
        } else {
            bytes32 senderTag = entry.senderTag;
            if (!_deliverPlainWithdrawal(token, to, senderTag, pay)) {
                // The whole remainder returns to the zone, which consumes no capacity.
                _bounceWithdrawal(token, to, senderTag, remaining, fallbackNonce);
                emit QueuedWithdrawalPaid(token, queueIndex, 0, 0);
                return (true, available);
            }
        }

        if (maxAmount != 0) newAvailable = available - pay;
        remaining -= pay;
        emit QueuedWithdrawalPaid(token, queueIndex, pay, remaining);
        if (remaining == 0) return (true, newAvailable);
        entry.remaining = remaining;
        if (fallbackNonce == 0) entry.partlyPaid = true;
    }

    /// @dev Attempts to deliver a whole main-queue user withdrawal and emits WithdrawalProcessed
    ///      on success. The caller bounces it back on failure.
    function _deliverWithdrawal(Withdrawal calldata withdrawal) internal returns (bool success) {
        if (withdrawal.gasLimit == 0) {
            return _deliverPlainWithdrawal(
                withdrawal.token, withdrawal.to, withdrawal.senderTag, withdrawal.amount
            );
        }
        // Isolate callback effects so failure can be caught without reverting the dequeue.
        try this.deliverWithdrawal(
            withdrawal.token,
            withdrawal.to,
            withdrawal.amount,
            withdrawal.senderTag,
            withdrawal.gasLimit,
            withdrawal.callbackData
        ) {
            emit WithdrawalProcessed(
                withdrawal.to, withdrawal.senderTag, withdrawal.token, withdrawal.amount, true
            );
            return true;
        } catch {
            return false;
        }
    }

    /// @dev Attempts to transfer amount of a plain withdrawal to its recipient and emits
    ///      WithdrawalProcessed on success.
    function _deliverPlainWithdrawal(
        address token,
        address to,
        bytes32 senderTag,
        uint128 amount
    )
        internal
        returns (bool success)
    {
        // Re-check current roles without reverting so an in-flight withdrawal to a revoked
        // account or newly registered gateway bounces without blocking the FIFO.
        success = (!_isGatewayEnforced || !hasRole(to, Role.CallbackGateway)) && _isAllowed(to)
            && _tryTransfer(token, to, amount);
        if (success) emit WithdrawalProcessed(to, senderTag, token, amount, true);
    }

    /// @dev Returns a whole main-queue user withdrawal to its zone fallback recipient.
    function _bounceWithdrawal(Withdrawal calldata withdrawal) internal {
        _bounceWithdrawal(
            withdrawal.token,
            withdrawal.to,
            withdrawal.senderTag,
            withdrawal.amount,
            withdrawal.fallbackNonce
        );
    }

    /// @dev Returns amount of a user withdrawal to its zone fallback recipient.
    function _bounceWithdrawal(
        address token,
        address to,
        bytes32 senderTag,
        uint128 amount,
        uint64 fallbackNonce
    )
        internal
    {
        _enqueueBounceBack(token, amount, fallbackNonce);
        emit WithdrawalProcessed(to, senderTag, token, amount, false);
    }

    /// @notice Deliver a callback withdrawal in a revertable self-call frame.
    /// @dev Only callable by this portal. processWithdrawals catches failures and bounces back.
    function deliverWithdrawal(
        address token,
        address target,
        uint128 amount,
        bytes32 senderTag,
        uint64 gasLimit,
        bytes calldata data
    )
        external
        onlySelf
    {
        if (_isGatewayEnforced && !hasRole(target, Role.CallbackGateway)) {
            revert InvalidCallbackTarget();
        }
        if (!ITIP20(token).transfer(messenger, amount)) {
            revert TransferFailed();
        }

        bytes32 depositQueueHashBefore = currentDepositQueueHash;

        _withdrawalReentrancyStatus = CALLBACK_DEPOSIT_AVAILABLE;

        // We copy whatever the messenger reverts with, so keep its errors small.
        IZoneMessenger(messenger)
            .relayMessage(zoneId, token, senderTag, target, amount, gasLimit, data);

        // Return to the normal withdrawal-processing state. If relayMessage reverts, this write
        // and any callback deposit are reverted together.
        _withdrawalReentrancyStatus = WITHDRAWAL_PROCESSING;

        // In closed access, this proves only that some deposit was appended to this portal; it does
        // not bind that deposit to the callback's token, amount, or recipient. Callback data is
        // opaque, so an enforced gateway is trusted to constrain the operation and return the
        // intended result. Open access imposes no source-deposit invariant: callback value may go
        // to another zone or leave the zone system entirely.
        if (_isAccessEnforced && currentDepositQueueHash == depositQueueHashBefore) {
            revert CallbackDidNotReturnToZone();
        }
    }

    /// @dev Refunds amount of a deposit bounce-back (all of it, or one payment of a queued one),
    ///      charging bouncebackFee (at most amount) to the admin. If the refund cannot be
    ///      delivered, parks remaining, the entry's whole unpaid amount, less the fee in refunds.
    /// @return refunded True if the refund was delivered.
    /// @return collectedFee Fee the admin received.
    function _processDepositBounceBack(
        address _token,
        address to,
        uint128 amount,
        uint128 remaining,
        uint128 bouncebackFee
    )
        internal
        returns (bool refunded, uint128 collectedFee)
    {
        // Only deduct the fee if the admin transfer succeeds; otherwise the full amount remains
        // refundable to the deposit recipient.
        if (bouncebackFee > 0 && _tryTransfer(_token, admin, bouncebackFee)) {
            collectedFee = bouncebackFee;
        }
        uint128 refundAmount = amount - collectedFee;

        refunded = _isAllowed(to) && _tryTransfer(_token, to, refundAmount);

        if (refunded) {
            emit DepositBounceBack(to, _token, refundAmount, collectedFee);
        } else {
            uint128 parked = remaining - collectedFee;
            refunds[_token][to] += parked;
            emit DepositBounceBackPending(to, _token, parked, collectedFee);
        }
    }

    /// @inheritdoc IZonePortal
    /// @dev Parking a refund consumes no withdrawal-limit capacity, so claiming one does. Queued
    ///      records are paid before parked refunds, so a claim cannot hold capacity below what a
    ///      queued installment needs.
    function claimRefund(address token) external whenNotPaused returns (uint128 amount) {
        _requireAllowed(msg.sender);
        QueuedWithdrawals storage tokenQueue = _queuedWithdrawals[token];
        if (tokenQueue.head == tokenQueue.tail) {
            uint128 owed = refunds[token][msg.sender];
            amount = owed;

            WithdrawalLimit storage limit = _withdrawalLimits[token];
            uint128 maxAmount = limit.maxAmount;
            if (maxAmount != 0) {
                uint128 available = _refilledCapacity(limit, maxAmount);
                if (amount > available) amount = available;
                _setAvailable(limit, available - amount);
            }
            refunds[token][msg.sender] = owed - amount;
        }

        if (!_tryTransfer(token, msg.sender, amount)) revert CallbackRejected();

        emit RefundClaimed(msg.sender, token, amount);
    }

    /// @notice Attempt a TIP-20 transfer without bubbling recipient/policy reverts.
    /// @dev Returns false if the receive policy blocks direct delivery, or if the token transfer
    ///      reverts or returns false. Callers decide whether a failed transfer should be ignored,
    ///      parked for refund, or reverted.
    /// @param token The TIP-20 token to transfer.
    /// @param to The recipient address.
    /// @param amount The token amount to transfer.
    /// @return success True if the transfer completed directly to `to` and returned true.
    function _tryTransfer(
        address token,
        address to,
        uint128 amount
    )
        internal
        returns (bool success)
    {
        address effectiveRecipient;
        try StdPrecompiles.ADDRESS_REGISTRY.resolveRecipient(to) returns (address resolved) {
            effectiveRecipient = resolved;
        } catch {
            return false;
        }

        try TIP403_REGISTRY.validateReceivePolicy(
            token, address(this), effectiveRecipient
        ) returns (
            bool authorized, ITIP403Registry.BlockedReason
        ) {
            if (!authorized) return false;
        } catch {
            return false;
        }

        try ITIP20(token).transfer(to, amount) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }

    /// @notice Enqueue a bounce-back deposit for failed callback
    /// @param _token The token from the failed withdrawal
    /// @param amount The amount to bounce back
    /// @param fallbackNonce The nonce resolving to the zone bounce-back recipient
    function _enqueueBounceBack(address _token, uint128 amount, uint64 fallbackNonce) internal {
        WithdrawalBounceBackDeposit memory depositData = WithdrawalBounceBackDeposit({
            token: _token, to: address(uint160(fallbackNonce)), amount: amount
        });

        bytes32 newCurrentDepositQueueHash =
            DepositQueueLib.enqueue(currentDepositQueueHash, depositData);
        uint64 thisDeposit = _recordDeposit(newCurrentDepositQueueHash);

        emit WithdrawalBounceBack(
            newCurrentDepositQueueHash, fallbackNonce, _token, amount, thisDeposit
        );
    }

    /*//////////////////////////////////////////////////////////////
                           BATCH SUBMISSION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IZonePortal
    function submitBatch(
        uint64 tempoBlockNumber,
        uint64 recentTempoBlockNumber,
        BlockTransition calldata blockTransition,
        DepositQueueTransition calldata depositQueueTransition,
        TokenEnablementTransition calldata tokenEnablementTransition,
        bytes32 withdrawalQueueHash,
        bytes calldata verifierConfig,
        bytes calldata proof,
        uint256 nextZoneHeight,
        bytes[] calldata signatures
    )
        external
        onlySequencer
    {
        if (blockTransition.prevBlockHash != blockHash) {
            revert InvalidProof();
        }

        // Determine anchor block: either tempoBlockNumber (direct) or recentTempoBlockNumber (ancestry)
        uint64 anchorBlockNumber;
        bytes32 anchorBlockHash;

        if (recentTempoBlockNumber == 0) {
            // Direct mode: read tempoBlockNumber hash from EIP-2935
            anchorBlockNumber = tempoBlockNumber;
            if (tempoBlockNumber > block.number) {
                revert InvalidTempoBlockNumber();
            }

            anchorBlockHash = getBlockHash(tempoBlockNumber);
        } else {
            // Ancestry mode: read recentTempoBlockNumber hash, proof verifies ancestry chain
            if (recentTempoBlockNumber <= tempoBlockNumber) {
                revert InvalidTempoBlockNumber();
            }
            if (recentTempoBlockNumber > block.number) {
                revert InvalidTempoBlockNumber();
            }

            anchorBlockNumber = recentTempoBlockNumber;
            anchorBlockHash = getBlockHash(recentTempoBlockNumber);
        }

        if (anchorBlockHash == bytes32(0)) revert InvalidTempoBlockNumber();

        // The certificate binds every value that affects settlement, rather than only the
        // zone block hash. A leader therefore cannot reuse signatures for this block with a
        // different withdrawal root, deposit transition, Tempo anchor, or verifier config.
        if (!_verifySettlement(
                nextZoneHeight,
                tempoBlockNumber,
                anchorBlockNumber,
                anchorBlockHash,
                blockTransition,
                depositQueueTransition,
                tokenEnablementTransition,
                withdrawalQueueHash,
                verifierConfig,
                signatures
            )) revert InvalidQuorumCertificate();

        // These are strictly not necessary, but we'll assert them here since they are cheap while
        // the prover doesn't (yet) enforce them.
        //   - continuity:  prevDepositNumber must equal where we last left off
        //   - monotonic:   the queue can only advance (nextDepositNumber >= prevDepositNumber)
        //   - in-range:    cannot process more deposits than have been enqueued
        if (
            depositQueueTransition.prevDepositNumber != lastProcessedDepositNumber
                || depositQueueTransition.nextDepositNumber
                    < depositQueueTransition.prevDepositNumber
                || depositQueueTransition.nextDepositNumber > depositCount
        ) {
            revert InvalidDepositTransition();
        }

        uint64 enabledCount = uint64(_enabledTokens.length);
        //   - bootstrap:   before initialization, pre-T13 and the first T13 transition start at 0
        //   - continuity:  once initialized, prevProcessedTokenCount must equal where we last left off
        //   - monotonic:   the processed prefix can only advance
        //   - in-range:    cannot process more tokens than have been enabled
        uint64 expectedPrev = tokenEnablementCursorInitialized ? lastProcessedEnabledTokenCount : 0;
        if (
            tokenEnablementTransition.prevProcessedTokenCount != expectedPrev
                || tokenEnablementTransition.nextProcessedTokenCount
                    < tokenEnablementTransition.prevProcessedTokenCount
                || tokenEnablementTransition.nextProcessedTokenCount > enabledCount
        ) {
            revert InvalidTokenEnablementTransition();
        }
        if (
            !tokenEnablementCursorInitialized
                && tokenEnablementTransition.nextProcessedTokenCount != 0
                && enabledCount - tokenEnablementTransition.nextProcessedTokenCount
                    > MAX_UNPROCESSED_TOKEN_ENABLEMENTS
        ) {
            revert InvalidTokenEnablementTransition();
        }

        // Verify proof (handles both direct and ancestry modes)
        bool valid = IVerifier(verifier)
            .verify(
                zoneId,
                tempoBlockNumber,
                anchorBlockNumber,
                anchorBlockHash,
                withdrawalBatchIndex + 1,
                nextZoneHeight,
                blockTransition,
                depositQueueTransition,
                tokenEnablementTransition,
                withdrawalQueueHash,
                verifierConfig,
                proof
            );
        if (!valid) revert InvalidProof();

        // Update state
        withdrawalBatchIndex++;
        blockHash = blockTransition.nextBlockHash;
        lastSyncedTempoBlockNumber = tempoBlockNumber;
        _settleDeposits(depositQueueTransition.nextDepositNumber);
        if (
            tokenEnablementCursorInitialized
                || tokenEnablementTransition.nextProcessedTokenCount != 0
        ) {
            lastProcessedEnabledTokenCount = tokenEnablementTransition.nextProcessedTokenCount;
            tokenEnablementCursorInitialized = true;
        }
        zoneHeight = nextZoneHeight;

        uint256 assignedQueueIndex = _withdrawalQueue.enqueue(withdrawalQueueHash);

        // Emit event after state updates
        emit BatchSubmitted(
            withdrawalBatchIndex,
            assignedQueueIndex,
            depositQueueTransition.nextProcessedHash,
            blockHash,
            withdrawalQueueHash,
            lastProcessedDepositNumber,
            lastProcessedEnabledTokenCount
        );
    }

    /// @dev Advances settlement, may lower this block's tier, then prunes.
    /// TODO: weigh entries as TIP-1171 specifies once an entry type weighs more than 1 unit.
    function _settleDeposits(uint64 settled) internal {
        _snapshotCongestionTier();
        lastProcessedDepositNumber = settled;

        // Appends only raise the tier, so every deposit later in the block can pay the lower one.
        uint64 tier = _unsettledCongestionTier();
        if (tier < depositPriceTier) depositPriceTier = tier;
        _pruneDepositBuckets();
    }

    function _verifySettlement(
        uint256 nextZoneHeight,
        uint64 tempoBlockNumber,
        uint64 anchorBlockNumber,
        bytes32 anchorBlockHash,
        BlockTransition calldata blockTransition,
        DepositQueueTransition calldata depositQueueTransition,
        TokenEnablementTransition calldata tokenEnablementTransition,
        bytes32 withdrawalQueueHash,
        bytes calldata verifierConfig,
        bytes[] memory signatures
    )
        internal
        view
        returns (bool)
    {
        uint256 threshold = sequencerThreshold;
        if (
            nextZoneHeight <= zoneHeight || signatures.length < threshold
                || signatures.length > _sequencers.length
        ) {
            return false;
        }

        bytes32 structHash = keccak256(
            abi.encode(
                SETTLEMENT_ATTESTATION_TYPEHASH,
                zoneId,
                sequencerSetVersion,
                nextZoneHeight,
                withdrawalBatchIndex + 1,
                verifier,
                tempoBlockNumber,
                anchorBlockNumber,
                anchorBlockHash,
                keccak256(abi.encode(blockTransition)),
                keccak256(abi.encode(depositQueueTransition)),
                keccak256(abi.encode(tokenEnablementTransition)),
                withdrawalQueueHash,
                keccak256(verifierConfig)
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        address[] memory recovered = new address[](signatures.length);

        for (uint256 i = 0; i < signatures.length; ++i) {
            bytes memory signature = signatures[i];
            address signer;
            // The shared TIP-1020 verifier owns signature-format and canonicality checks.
            // Convert its reverts into `false` so the public verifier remains non-reverting.
            try StdPrecompiles.SIGNATURE_VERIFIER.recover(digest, signature) returns (
                address recoveredSigner
            ) {
                signer = recoveredSigner;
            } catch {
                return false;
            }
            if (signer == address(0) || !isSequencer(signer)) return false;
            for (uint256 j = 0; j < i; ++j) {
                if (recovered[j] == signer) return false;
            }
            recovered[i] = signer;
        }

        return signatures.length >= threshold;
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)
            )
        );
    }

    /// @dev TIP-1094: whether `account` has the zone deposit address format (magic bytes 4..13),
    ///      for any zone.
    function _isZoneDepositAddress(address account) internal pure returns (bool) {
        return bytes9(bytes20(account) << 32) == bytes9(0xfcfcfcfcfcfcfcfcfc);
    }

}
