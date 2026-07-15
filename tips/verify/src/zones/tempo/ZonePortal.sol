// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {
    BlockTransition,
    Deposit,
    DepositQueueTransition,
    DepositType,
    ENCRYPTION_KEY_GRACE_PERIOD,
    EncryptedDeposit,
    EncryptedDepositPayload,
    EncryptionKeyEntry,
    IVerifier,
    IZoneMessenger,
    IZonePortal,
    MAX_WITHDRAWAL_CALLBACK_GAS,
    QueuedDeposit,
    TokenConfig,
    Withdrawal
} from "../interfaces/IZone.sol";
import { getBlockHash } from "../libraries/BlockHashHistory.sol";
import { DepositQueueLib } from "../libraries/DepositQueueLib.sol";
import { Secp256k1Lib } from "../libraries/Secp256k1Lib.sol";
import { WithdrawalQueue, WithdrawalQueueLib } from "../libraries/WithdrawalQueueLib.sol";
import { StdPrecompiles } from "tempo-std/StdPrecompiles.sol";
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
    ///      This provides a stable pricing basis for deposits while allowing sequencer
    ///      flexibility to adjust the zoneGasRate based on operational costs.
    uint64 public constant FIXED_DEPOSIT_GAS = 100_000;

    /// @notice Fixed gas value for failed-deposit bounce-back fee calculation
    /// @dev Priced against Tempo gas because the refund is paid on Tempo.
    uint64 public constant FIXED_BOUNCEBACK_GAS = 300_000;

    /// @notice Scale factor from 18-decimal Tempo gas prices to 6-decimal TIP-20 units
    uint256 internal constant TEMPO_BASE_FEE_SCALE = 1e12;

    /// @notice Maximum gas a withdrawal callback may request
    /// @dev Over-cap legacy withdrawals are dequeued and bounced back in `processWithdrawal`.
    uint64 public constant MAX_WITHDRAWAL_GAS_LIMIT = MAX_WITHDRAWAL_CALLBACK_GAS;

    /// @notice Maximum allowed gas fee rate to prevent overflows
    uint128 public constant MAX_GAS_FEE_RATE = 1e18;

    /// @dev The explicitly configured factory is the only initializer authority.
    ///      This is protocol-wide code configuration and does not consume proxy storage.
    address internal immutable _factory;

    /// @dev Canonical account that holds the portal logic contract's runtime code.
    ///      This is supplied separately because the runtime is copied from a template deployment.
    address internal immutable _portalLogic;

    /// @notice Encrypted deposit payloads always encrypt `(address to, bytes32 memo)`.
    uint256 internal constant ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE = 64;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Current sequencer address
    address public sequencer;

    /// @notice Governance admin address
    address public admin;

    /// @notice Pending sequencer for two-step transfer
    address public pendingSequencer;

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

    /// @notice Historical encryption keys with activation blocks
    /// @dev Users specify which key they encrypted to (by index). Maintained for key rotation.
    ///      Stored at slot 7 in the ZonePortal storage layout.
    EncryptionKeyEntry[] internal _encryptionKeys;

    /// @notice Per-token configuration (stored at slot 8)
    /// @dev TokenConfig.enabled is permanent (write-once true); depositsActive can be toggled.
    mapping(address => TokenConfig) internal _tokenConfigs;

    /// @notice Append-only list of enabled tokens (stored at slot 9)
    /// @dev Tokens can never be removed from this list (non-custodial guarantee).
    address[] internal _enabledTokens;

    /// @notice Refunds parked after a deposit bounce-back transfer reverts on Tempo.
    mapping(address token => mapping(address owner => uint128 amount)) public refunds;

    /// @notice Withdrawal queue (zone->Tempo): fixed-size ring buffer
    WithdrawalQueue internal _withdrawalQueue;

    /// @notice Public RPC endpoint for the zone
    string public rpcUrl;

    /// @notice Pending admin for two-step admin transfer
    address public pendingAdmin;

    /// @notice Reentrancy guard for withdrawal delivery.
    uint256 internal _withdrawalReentrancyStatus;

    /// @notice Zone metadata stored after the cross-domain layout.
    /// @dev These values must remain in account storage so each delegatecall proxy observes its
    ///      own metadata. Keep them after the established slots read directly by zone contracts.
    uint32 public zoneId;
    address public messenger;
    address public verifier;
    uint64 public genesisTempoBlockNumber;
    bool internal _initialized;

    /*//////////////////////////////////////////////////////////////
                             INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    /// @dev This constructor executes only for the temporary template deployment used to
    ///      produce runtime code. It is not executed at `portalLogic` when the protocol
    ///      installs that runtime there; `portalLogic` identifies that canonical address
    ///      for the direct-call guard.
    constructor(address factory, address portalLogic) {
        _factory = factory;
        _portalLogic = portalLogic;
    }

    function initialize(
        uint32 _zoneId,
        address _initialToken,
        address _messenger,
        address _admin,
        address _sequencer,
        address _verifier,
        bytes32 _genesisBlockHash,
        uint64 _genesisTempoBlockNumber,
        string calldata _rpcUrl
    )
        external
        onlyDelegateCall
    {
        if (msg.sender != _factory) revert NotFactory();
        if (_initialized) revert AlreadyInitialized();

        _initialized = true;
        zoneId = _zoneId;
        admin = _admin;
        sequencer = _sequencer;
        verifier = _verifier;
        messenger = _messenger;
        blockHash = _genesisBlockHash;
        genesisTempoBlockNumber = _genesisTempoBlockNumber;
        rpcUrl = _rpcUrl;

        // Enable the initial token
        _enableTokenInternal(_initialToken);
    }

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Initialization is valid only in a portal proxy's storage context.
    modifier onlyDelegateCall() {
        if (address(this) == _portalLogic) revert MustDelegateCall();
        _;
    }

    modifier onlySequencer() {
        if (msg.sender != sequencer) revert NotSequencer();
        _;
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    modifier onlySelf() {
        if (msg.sender != address(this)) revert NotSelf();
        _;
    }

    modifier nonReentrantWithdrawal() {
        if (_withdrawalReentrancyStatus != 0) revert ReentrantWithdrawal();
        _withdrawalReentrancyStatus = 1;
        _;
        _withdrawalReentrancyStatus = 0;
    }

    /*//////////////////////////////////////////////////////////////
                           SEQUENCER MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Start a sequencer transfer. Only callable by current sequencer.
    /// @param newSequencer The address that will become sequencer after accepting.
    function transferSequencer(address newSequencer) external onlySequencer {
        pendingSequencer = newSequencer;
        emit SequencerTransferStarted(sequencer, newSequencer);
    }

    /// @notice Accept a pending sequencer transfer. Only callable by pending sequencer.
    /// @dev The explicit `pendingSequencer == address(0)` check because it is technically
    ///      possible to make a system tx on L1 with msg.sender == 0.
    ///      The Sequencer key can only be rotated, never renounced.
    function acceptSequencer() external {
        if (pendingSequencer == address(0) || msg.sender != pendingSequencer) {
            revert NotPendingSequencer();
        }
        address previousSequencer = sequencer;
        sequencer = pendingSequencer;
        pendingSequencer = address(0);
        emit SequencerTransferred(previousSequencer, sequencer);
    }

    /// @notice Set zone gas rate. Only callable by sequencer.
    /// @dev Sequencer publishes this rate and takes the risk on zone gas costs.
    ///      If actual zone gas is higher, sequencer covers the difference.
    ///      If actual zone gas is lower, sequencer keeps the surplus.
    /// @param _zoneGasRate Zone token units per gas unit on the zone
    function setZoneGasRate(uint128 _zoneGasRate) external onlySequencer {
        if (_zoneGasRate > MAX_GAS_FEE_RATE) revert GasFeeRateTooHigh();
        zoneGasRate = _zoneGasRate;
        emit ZoneGasRateUpdated(_zoneGasRate);
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

    /*//////////////////////////////////////////////////////////////
                           QUEUE ACCESSORS
    //////////////////////////////////////////////////////////////*/

    function withdrawalQueueHead() external view returns (uint256) {
        return _withdrawalQueue.head;
    }

    function withdrawalQueueTail() external view returns (uint256) {
        return _withdrawalQueue.tail;
    }

    function withdrawalQueueSlot(uint256 slot) external view returns (bytes32) {
        return _withdrawalQueue.slots[slot];
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
        return cfg.enabled && cfg.depositsActive;
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

    /// @notice Enable a new TIP-20 token for bridging. Only callable by admin.
    /// @dev Irreversible: once enabled, a token cannot be disabled (non-custodial guarantee).
    ///      Validates the token is a TIP-20.
    function enableToken(address _token) external onlyAdmin {
        if (_tokenConfigs[_token].enabled) revert TokenAlreadyEnabled();
        if (!ITIP20Factory(StdPrecompiles.TIP20_FACTORY_ADDRESS).isTIP20(_token)) {
            revert TokenNotEnabled();
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
        _tokenConfigs[_token] = TokenConfig({ enabled: true, depositsActive: true });
        _enabledTokens.push(_token);

        // Read token metadata for the event so zone-side can create matching TIP-20
        string memory name = ITIP20(_token).name();
        string memory symbol = ITIP20(_token).symbol();
        string memory currency = ITIP20(_token).currency();

        emit TokenEnabled(_token, name, symbol, currency);
    }

    /// @notice Update the zone's public RPC endpoint.
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
    function sequencerEncryptionKey() external view returns (bytes32 x, uint8 yParity) {
        if (_encryptionKeys.length == 0) revert NoEncryptionKeySet();
        EncryptionKeyEntry storage current = _encryptionKeys[_encryptionKeys.length - 1];
        return (current.x, current.yParity);
    }

    /// @notice Set the sequencer's encryption public key with proof of possession
    /// @dev Only callable by the sequencer. Appends to key history.
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
        onlySequencer
    {
        // Validate yParity
        if (!Secp256k1Lib.isCompressedYParity(yParity)) revert InvalidEphemeralPubkey();

        // Validate x is on the secp256k1 curve
        if (!Secp256k1Lib.isValidX(x)) revert InvalidEphemeralPubkey();

        // Verify proof of possession: the sequencer must sign with the encryption key's private key
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
        emit SequencerEncryptionKeyUpdated(x, yParity, _encryptionKeys.length - 1, activationBlock);
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

    /// @notice Calculate the fee for a deposit
    /// @dev Fee = FIXED_DEPOSIT_GAS * zoneGasRate
    /// @return fee The deposit fee in zone token units
    function calculateDepositFee() public view returns (uint128 fee) {
        fee = uint128(FIXED_DEPOSIT_GAS) * zoneGasRate;
    }

    /// @notice Calculate the reserved fee for a failed-deposit bounce-back
    /// @dev Fee = ceil(FIXED_BOUNCEBACK_GAS * block.basefee / 1e12)
    /// @return fee The bounce-back fee in token units
    function calculateBouncebackFee() public view returns (uint128 fee) {
        uint256 gasFee = uint256(FIXED_BOUNCEBACK_GAS) * block.basefee;
        // Round up after scaling so bounce-backs do not underpay.
        fee = uint128((gasFee + TEMPO_BASE_FEE_SCALE - 1) / TEMPO_BASE_FEE_SCALE);
    }

    function _validateDepositsActive(address _token) internal view {
        TokenConfig storage cfg = _tokenConfigs[_token];
        if (!cfg.enabled) revert TokenNotEnabled();
        if (!cfg.depositsActive) revert DepositsNotActive();
    }

    function _validateDepositPolicy(
        address _token,
        address to,
        address bouncebackRecipient
    )
        internal
        view
    {
        uint64 policyId = ITIP20(_token).transferPolicyId();
        if (!TIP403_REGISTRY.isAuthorizedRecipient(policyId, to)) {
            revert ITIP20.PolicyForbids();
        }
        if (!TIP403_REGISTRY.isAuthorizedMintRecipient(policyId, to)) {
            revert ITIP20.PolicyForbids();
        }
        if (!TIP403_REGISTRY.isAuthorizedRecipient(policyId, bouncebackRecipient)) {
            revert ITIP20.PolicyForbids();
        }
    }

    function _collectDepositFunds(
        address _token,
        uint128 amount
    )
        internal
        returns (uint128 fee, uint128 netAmount)
    {
        fee = calculateDepositFee();
        uint128 bouncebackFee = calculateBouncebackFee();
        if (amount < fee + bouncebackFee) revert DepositTooSmall();
        netAmount = amount - fee;

        // TIP-20 transfers revert on failure, so no boolean check is needed here.
        ITIP20(_token).transferFrom(msg.sender, address(this), amount);
        if (fee > 0) {
            ITIP20(_token).transfer(sequencer, fee);
        }
    }

    function _recordDeposit(bytes32 newCurrentDepositQueueHash)
        internal
        returns (uint64 thisDeposit)
    {
        currentDepositQueueHash = newCurrentDepositQueueHash;
        thisDeposit = ++depositCount;
    }

    /// @notice Deposit a TIP-20 token into the zone. Returns the new current deposit queue hash.
    /// @dev Fee is deducted from amount and paid to sequencer in the same token.
    ///      The token must be enabled and deposits must be active.
    /// @param _token The TIP-20 token to deposit
    /// @param to Recipient address on the zone
    /// @param amount Total amount to deposit (fee will be deducted)
    /// @param memo User-provided context
    /// @return newCurrentDepositQueueHash The new deposit queue hash after this deposit
    function deposit(
        address _token,
        address to,
        uint128 amount,
        bytes32 memo,
        address bouncebackRecipient
    )
        external
        returns (bytes32 newCurrentDepositQueueHash)
    {
        if (bouncebackRecipient == address(0)) revert InvalidBouncebackRecipient();

        _validateDepositsActive(_token);
        _validateDepositPolicy(_token, to, bouncebackRecipient);
        (uint128 fee, uint128 netAmount) = _collectDepositFunds(_token, amount);

        // Build deposit struct with net amount (fee already paid to sequencer on Tempo)
        Deposit memory depositData = Deposit({
            token: _token,
            sender: msg.sender,
            to: to,
            amount: netAmount,
            bouncebackRecipient: bouncebackRecipient,
            memo: memo
        });

        // Insert deposit into queue
        newCurrentDepositQueueHash = DepositQueueLib.enqueue(currentDepositQueueHash, depositData);
        uint64 thisDeposit = _recordDeposit(newCurrentDepositQueueHash);

        emit DepositMade(
            newCurrentDepositQueueHash,
            msg.sender,
            _token,
            to,
            netAmount,
            fee,
            memo,
            bouncebackRecipient,
            thisDeposit
        );
    }

    /// @notice Deposit with encrypted recipient and memo
    /// @dev The encrypted payload contains (to, memo) encrypted to the sequencer's key.
    ///      The token identity is public (not encrypted) since the portal must escrow it.
    ///      Validates that keyIndex is valid (exists and not expired).
    ///      Charges the same deposit fee as regular deposits.
    /// @param _token The TIP-20 token to deposit
    /// @param amount Amount to deposit (fee deducted from this amount)
    /// @param keyIndex Index of the encryption key used (from encryptionKeyAt)
    /// @param encrypted The encrypted payload (recipient and memo)
    /// @return newCurrentDepositQueueHash The new deposit queue hash
    function depositEncrypted(
        address _token,
        uint128 amount,
        uint256 keyIndex,
        EncryptedDepositPayload calldata encrypted,
        address bouncebackRecipient
    )
        external
        returns (bytes32 newCurrentDepositQueueHash)
    {
        if (bouncebackRecipient == address(0)) revert InvalidBouncebackRecipient();

        _validateDepositsActive(_token);

        uint64 policyId = ITIP20(_token).transferPolicyId();
        if (!TIP403_REGISTRY.isAuthorizedRecipient(policyId, bouncebackRecipient)) {
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

        // Validate ciphertext length - GCM ciphertext == plaintext length (tag is separate)
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

        (uint128 fee, uint128 netAmount) = _collectDepositFunds(_token, amount);

        // Build encrypted deposit struct
        EncryptedDeposit memory depositData = EncryptedDeposit({
            token: _token,
            sender: msg.sender,
            amount: netAmount,
            bouncebackRecipient: bouncebackRecipient,
            keyIndex: keyIndex,
            encrypted: encrypted
        });

        // Insert encrypted deposit into queue
        newCurrentDepositQueueHash =
            DepositQueueLib.enqueueEncrypted(currentDepositQueueHash, depositData);
        uint64 thisDeposit = _recordDeposit(newCurrentDepositQueueHash);

        emit EncryptedDepositMade(
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
            bouncebackRecipient,
            thisDeposit
        );
    }

    /*//////////////////////////////////////////////////////////////
                             WITHDRAWALS
    //////////////////////////////////////////////////////////////*/

    /// @notice Process the next withdrawal from the queue. Only callable by the sequencer.
    /// @dev Fee transfer to the sequencer is best-effort.
    ///      On withdrawal failure, only the amount (not fee) is bounced back.
    ///      The token to transfer is read from the withdrawal struct.
    function processWithdrawal(
        Withdrawal calldata withdrawal,
        bytes32 remainingQueue
    )
        external
        onlySequencer
        nonReentrantWithdrawal
    {
        // Pop from withdrawal queue (library handles swap and hash verification)
        _withdrawalQueue.dequeue(withdrawal, remainingQueue);

        address _token = withdrawal.token;

        if (withdrawal.fallbackNonce == 0) {
            _processDepositBounceBack(withdrawal);
            return;
        }

        // Transfer fee to sequencer.
        if (withdrawal.fee > 0) {
            // Fee transfer can fail for e.g. TIP-403 blacklist. The sequencer
            // forgoes the fee so the withdrawal itself does not stall.
            _tryTransfer(_token, sequencer, withdrawal.fee);
        }

        if (withdrawal.gasLimit > MAX_WITHDRAWAL_GAS_LIMIT) {
            _enqueueBounceBack(_token, withdrawal.amount, withdrawal.fallbackNonce);
            emit WithdrawalProcessed(
                withdrawal.to, withdrawal.senderTag, _token, withdrawal.amount, false
            );
            return;
        }

        bool success;
        if (withdrawal.gasLimit == 0) {
            success = _tryTransfer(_token, withdrawal.to, withdrawal.amount);
        } else {
            try this.deliverWithdrawal(
                _token,
                withdrawal.to,
                withdrawal.amount,
                withdrawal.senderTag,
                withdrawal.gasLimit,
                withdrawal.callbackData
            ) {
                success = true;
            } catch {
                success = false;
            }
        }

        if (!success) {
            // Callback failed: bounce back to zone (only amount, not fee)
            _enqueueBounceBack(_token, withdrawal.amount, withdrawal.fallbackNonce);
        }
        emit WithdrawalProcessed(
            withdrawal.to, withdrawal.senderTag, _token, withdrawal.amount, success
        );
    }

    /// @notice Deliver a callback withdrawal in a revertable self-call frame.
    /// @dev Only callable by this portal. It transfers only the current withdrawal amount to
    ///      the shared messenger, then asks the messenger to call the target. If delivery
    ///      fails, this call reverts and rolls back the transfer to the messenger. The outer
    ///      processWithdrawal catches the revert and records a bounce-back.
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
        if (!ITIP20(token).transfer(messenger, amount)) {
            revert TransferFailed();
        }

        IZoneMessenger(messenger)
            .relayMessage(zoneId, token, senderTag, target, amount, gasLimit, data);
    }

    function _processDepositBounceBack(Withdrawal calldata withdrawal) internal {
        address _token = withdrawal.token;
        uint128 bouncebackFee = calculateBouncebackFee();
        if (bouncebackFee > withdrawal.amount) {
            bouncebackFee = withdrawal.amount;
        }
        uint128 refundAmount = withdrawal.amount - bouncebackFee;

        if (bouncebackFee > 0) {
            // If the fee transfer fails, (e.g. TIP-403 blacklist), the sequencer
            // forgoes the fee so the bounce-back itself does not stall.
            _tryTransfer(_token, sequencer, bouncebackFee); // ignore failure
        }

        bool success = _tryTransfer(_token, withdrawal.to, refundAmount);

        if (success) {
            emit DepositBounceBack(withdrawal.to, _token, refundAmount, bouncebackFee);
        } else {
            refunds[_token][withdrawal.to] += refundAmount;
            emit DepositBounceBackPending(withdrawal.to, _token, refundAmount, bouncebackFee);
        }
    }

    function claimRefund(address token) external returns (uint128 amount) {
        amount = refunds[token][msg.sender];
        refunds[token][msg.sender] = 0;

        if (!_tryTransfer(token, msg.sender, amount)) revert CallbackRejected();

        emit RefundClaimed(msg.sender, token, amount);
    }

    /// @notice Attempt a TIP-20 transfer without bubbling recipient/policy reverts.
    /// @dev Returns false if the token transfer reverts or returns false. Callers decide
    ///      whether a failed transfer should be ignored, parked for refund, or reverted.
    /// @param token The TIP-20 token to transfer.
    /// @param to The recipient address.
    /// @param amount The token amount to transfer.
    /// @return success True if the transfer completed and returned true.
    function _tryTransfer(
        address token,
        address to,
        uint128 amount
    )
        internal
        returns (bool success)
    {
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
        Deposit memory depositData = Deposit({
            token: _token,
            sender: address(this),
            to: address(uint160(fallbackNonce)),
            amount: amount,
            bouncebackRecipient: address(0),
            memo: bytes32(0)
        });

        bytes32 newCurrentDepositQueueHash =
            DepositQueueLib.enqueue(currentDepositQueueHash, depositData);
        currentDepositQueueHash = newCurrentDepositQueueHash;
        uint64 thisDeposit = ++depositCount;

        emit WithdrawalBounceBack(
            newCurrentDepositQueueHash, fallbackNonce, _token, amount, thisDeposit
        );
    }

    /*//////////////////////////////////////////////////////////////
                           BATCH SUBMISSION
    //////////////////////////////////////////////////////////////*/

    /// @notice Submit a batch and verify the proof. Only callable by the sequencer.
    /// @param tempoBlockNumber Block number zone committed to (from zone's TempoState)
    /// @param recentTempoBlockNumber Optional recent block for ancestry proof (0 = use direct lookup)
    function submitBatch(
        uint64 tempoBlockNumber,
        uint64 recentTempoBlockNumber,
        BlockTransition calldata blockTransition,
        DepositQueueTransition calldata depositQueueTransition,
        bytes32 withdrawalQueueHash,
        bytes calldata verifierConfig,
        bytes calldata proof
    )
        external
        onlySequencer
    {
        if (blockTransition.prevBlockHash != blockHash) {
            revert InvalidProof();
        }

        // Validate tempoBlockNumber is valid (applies to both direct and ancestry modes)
        if (tempoBlockNumber < genesisTempoBlockNumber) {
            revert InvalidTempoBlockNumber();
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

        // Verify proof (handles both direct and ancestry modes)
        bool valid = IVerifier(verifier)
            .verify(
                tempoBlockNumber,
                anchorBlockNumber,
                anchorBlockHash,
                withdrawalBatchIndex + 1,
                sequencer,
                blockTransition,
                depositQueueTransition,
                withdrawalQueueHash,
                verifierConfig,
                proof
            );
        if (!valid) revert InvalidProof();

        // Update state
        withdrawalBatchIndex++;
        blockHash = blockTransition.nextBlockHash;
        lastSyncedTempoBlockNumber = tempoBlockNumber;
        lastProcessedDepositNumber = depositQueueTransition.nextDepositNumber;

        _withdrawalQueue.enqueue(withdrawalQueueHash);

        // Emit event after state updates
        emit BatchSubmitted(
            withdrawalBatchIndex,
            depositQueueTransition.nextProcessedHash,
            blockHash,
            withdrawalQueueHash,
            lastProcessedDepositNumber
        );
    }

}
