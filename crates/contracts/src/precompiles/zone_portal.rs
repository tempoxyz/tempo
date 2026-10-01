//! Complete portal ABI used by native execution and historical compatibility checks.
//!
//! Legacy overloads remain represented for decoding historical transactions.
//! Runtime admission must select the overload active at the executed fork.

pub use ZonePortal::{
    BlockTransition, Deposit, DepositPayload, DepositQueueTransition, TokenEnablementTransition,
    Withdrawal, ZonePortalErrors as ZonePortalError,
};

/// Defines the complete portal ABI with the calling crate's binding macro.
///
/// The binding macro selects RPC and serde features. Generating local bindings
/// lets SDK crates add inherent RPC helpers while sharing protocol definitions.
#[macro_export]
macro_rules! zone_portal_abi {
    ($binding:path) => {
        $binding! {
            #[sol(abi)]
            #[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
            contract ZonePortal {
                // -- Shared types --
                enum Role {
                    None,
                    Sequencer,
                    Account,
                    CallbackGateway,
                    PauseGuardian
                }

                enum Capability {
                    PausePortal,
                    AccessPolicy
                }

                struct Withdrawal {
                    address token;
                    bytes32 senderTag;
                    address to;
                    uint128 amount;
                    bytes32 memo;
                    uint64 gasLimit;
                    uint64 fallbackNonce;
                    bytes callbackData;
                    bytes encryptedSender;
                }

                /// Deposit payload (ECIES-encrypted recipient and memo).
                struct DepositPayload {
                    bytes32 ephemeralPubkeyX;
                    uint8 ephemeralPubkeyYParity;
                    bytes ciphertext;
                    bytes12 nonce;
                    bytes16 tag;
                }

                /// User deposit stored in the queue.
                struct Deposit {
                    address token;
                    address sender;
                    uint128 amount;
                    address tempoRefundRecipient;
                    uint256 keyIndex;
                    DepositPayload encrypted;
                }

                struct EncryptionKeyEntry {
                    bytes32 x;
                    uint8 yParity;
                    uint64 activationBlock;
                }

                struct TokenConfig {
                    bool enabled;
                    bool depositsActive;
                }

                struct BlockTransition {
                    bytes32 prevBlockHash;
                    bytes32 nextBlockHash;
                }

                struct DepositQueueTransition {
                    bytes32 prevProcessedHash;
                    bytes32 nextProcessedHash;
                    uint64 prevDepositNumber;
                    uint64 nextDepositNumber;
                }

                /// Processed prefix transition for the portal's append-only enabled-token array.
                struct TokenEnablementTransition {
                    uint64 prevProcessedTokenCount;
                    uint64 nextProcessedTokenCount;
                }

                // -- Events --

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

                /// Event emitted when a new TIP-20 token is enabled for bridging.
                /// Includes token metadata so the zone can create a matching TIP-20.
                event TokenEnabled(address indexed token, string name, string symbol, string currency);
                event DepositsPaused(address indexed token);
                event DepositsResumed(address indexed token);
                event PortalPaused(address indexed account);
                event PortalResumed(address indexed account);
                event AbdicationScheduled(Capability indexed capability, uint64 effectiveAt);
                event RpcUrlUpdated(string rpcUrl);

                event SequencerEncryptionKeyUpdated(
                    bytes32 x,
                    uint8 yParity,
                    address pubkey,
                    uint256 keyIndex,
                    uint64 activationBlock
                );

                /// `withdrawalQueueIndex` is the logical withdrawal queue index the batch's hash
                /// chain was enqueued under, or `NO_QUEUE_INDEX` when the batch
                /// carried no withdrawals.
                event BatchSubmitted(
                    uint64 indexed withdrawalBatchIndex,
                    uint256 indexed withdrawalQueueIndex,
                    bytes32 nextProcessedDepositQueueHash,
                    bytes32 nextBlockHash,
                    bytes32 withdrawalQueueHash,
                    uint64 lastProcessedDepositNumber
                );

                /// T13 batch event with the processed enabled-token cursor.
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

                event DepositBounceBack(
                    address indexed tempoRefundRecipient,
                    address token,
                    uint128 amount,
                    uint128 bouncebackFee
                );

                event DepositBounceBackPending(
                    address indexed tempoRefundRecipient,
                    address token,
                    uint128 amount,
                    uint128 bouncebackFee
                );

                event RefundClaimed(address indexed recipient, address indexed token, uint128 amount);

                event ZoneGasRateUpdated(uint128 zoneGasRate);
                event MaxTempoGasRateUpdated(uint128 maxTempoGasRate);
                event BouncebackGasUpdated(uint64 bouncebackGas);

                event AdminTransferStarted(
                    address indexed currentAdmin,
                    address indexed pendingAdmin
                );

                event AdminTransferred(
                    address indexed previousAdmin,
                    address indexed newAdmin
                );

                event RoleUpdated(address indexed account, Role prev, Role next);
                event EnforcementModesUpdated(bool accessMode, bool gatewayMode);
                event SequencerSetUpdated(uint64 indexed nonce, uint8 threshold, address[] sequencers);

                /// Emitted when block-production leadership transitions to a new sequencer.
                /// Zone nodes derive leadership exclusively from finalized observations of this event.
                event LeaderUpdated(
                    address indexed previousLeader,
                    address indexed newLeader,
                    uint64 indexed epoch,
                    uint64 activationTempoBlock
                );

                // -- Errors --

                error NotSequencer();
                error NotAdmin();
                error NotPauseAuthority();
                error CapabilityAbdicated(Capability capability);
                error AbdicationAlreadyScheduled(Capability capability);
                error PortalIsPaused();
                error NotPendingAdmin();
                error InvalidProof();
                error InvalidTempoBlockNumber();
                error NotFactory();
                error NotSelf();
                error AlreadyInitialized();
                error MustDelegateCall();
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
                error TokenEnablementBlockCapacityExceeded(uint64 maximum);
                error TokenMetadataTooLong();
                error GasFeeRateTooHigh();
                error DepositsNotActive();
                error TokenAlreadyEnabled();
                error TokenTransferPolicyNotSet();
                error TokenEnablementCursorNotInitialized();
                error InvalidDepositTransition();
                error InvalidTokenEnablementTransition();
                error InvalidSequencerSet();
                error SequencerConfigurationUnchanged();
                error InvalidQuorumCertificate();
                error CallbackDidNotReturnToZone();
                error InvalidBouncebackRecipient();
                error TokenNotEnabled();
                error DepositBlockCapacityExceeded(uint64 maximum);
                error InvalidCallbackTarget();
                error AccountNotAllowed(address account);
                error InvalidLeader();
                error ActiveLeaderRemoved();
                error LeaderAlreadyUpdatedThisBlock();
                error StaleLeadershipEpoch(uint64 expected, uint64 actual);

                // -- View functions --

                function zoneId() external view returns (uint32);
                function admin() external view returns (address);
                function messenger() external view returns (address);
                function isAccessEnforced() external view returns (bool);
                function setAccessMode(bool enforced) external;
                function isGatewayOpen() external view returns (bool);
                function setGatewayMode(bool enforced) external;
                function hasRole(address account, Role role) external view returns (bool);
                function setAllowedAccount(address account, bool allowed) external;
                function setGateway(address account, bool allowed) external;
                function setPauseGuardian(address account, bool allowed) external;
                function setSequencerSet(address[] calldata newSequencers, uint8 newThreshold) external;
                function verifier() external view returns (address);
                function sequencerSetVersion() external view returns (uint64);
                function sequencerThreshold() external view returns (uint8);
                function zoneHeight() external view returns (uint256);
                function isSequencer(address account) external view returns (bool);
                function sequencerCount() external view returns (uint256);
                function sequencerAt(uint256 index) external view returns (address);
                function leader() external view returns (address);
                function leaderEpoch() external view returns (uint64);
                function leaderActivationTempoBlock() external view returns (uint64);
                function setLeader(address newLeader, uint64 expectedEpoch) external;
                function withdrawalBatchIndex() external view returns (uint64);
                function blockHash() external view returns (bytes32);
                function currentDepositQueueHash() external view returns (bytes32);
                function lastSyncedTempoBlockNumber() external view returns (uint64);
                function withdrawalQueueHead() external view returns (uint256);
                function withdrawalQueueTail() external view returns (uint256);
                function withdrawalQueueSlot(uint256 queueIndex) external view returns (bytes32);
                function calculateDepositFee() external view returns (uint128 fee);
                function calculateBouncebackFee() external view returns (uint128 fee);
                function depositCount() external view returns (uint64);
                function lastProcessedDepositNumber() external view returns (uint64);
                function FIXED_DEPOSIT_GAS() external view returns (uint64);
                function MAX_GAS_FEE_RATE() external view returns (uint128);
                function MAX_TOKENS_ENABLED_PER_TEMPO_BLOCK() external view returns (uint64);
                function MAX_TOKEN_METADATA_BYTES() external view returns (uint256);
                function areDepositsActive(address token) external view returns (bool);
                function tokenConfig(address token) external view returns (TokenConfig memory);
                function initialize(uint32 zoneId, address initialToken, bool accessMode, bool gatewayMode, address[] calldata allowedAccounts, address[] calldata zoneGateways, address admin, address messenger, address[] calldata sequencers, uint8 threshold, address verifier, string calldata rpcUrl) external;
                function deliverWithdrawal(address to, address token, uint128 amount, bytes32 memo, uint64 gasLimit, bytes calldata callbackData) external;
                function MAX_DEPOSITS_PER_TEMPO_BLOCK() external view returns (uint64);
                function MAX_UNPROCESSED_DEPOSITS() external view returns (uint64);
                function MAX_UNPROCESSED_TOKEN_ENABLEMENTS() external view returns (uint64);
                function MAX_WITHDRAWAL_GAS_LIMIT() external view returns (uint64);
                function paused() external view returns (bool);
                function pauseExpiry() external view returns (uint64);
                function abdicationEffectiveAt(Capability capability) external view returns (uint64);

                // -- State-changing functions --

                function processWithdrawals(Withdrawal[] calldata withdrawals, bytes32 remainingQueue) external;
                function pause() external;
                function resume() external;
                function abdicate(Capability capability) external;

                function submitBatch(
                    uint64 tempoBlockNumber,
                    uint64 recentTempoBlockNumber,
                    BlockTransition calldata blockTransition,
                    DepositQueueTransition calldata depositQueueTransition,
                    bytes32 withdrawalQueueHash,
                    bytes calldata verifierConfig,
                    bytes calldata proof,
                    uint256 nextZoneHeight,
                    bytes[] calldata signatures
                ) external;

                /// Submit a batch with the enabled-token transition. Active from T13.
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
                ) external;

                function enableToken(address token) external;
                function pauseDeposits(address token) external;
                function resumeDeposits(address token) external;

                function setZoneGasRate(uint128 newZoneGasRate) external;
                function setMaxTempoGasRate(uint128 newMaxTempoGasRate) external;
                function setBouncebackGas(uint64 newBouncebackGas) external;

                function transferAdmin(address newAdmin) external;
                function acceptAdmin() external;

                function rpcUrl() external view returns (string memory);
                function setRpcUrl(string calldata rpcUrl) external;

                function deposit(
                    address token,
                    uint128 amount,
                    uint256 keyIndex,
                    DepositPayload calldata encrypted,
                    address tempoRefundRecipient
                ) external returns (bytes32 newCurrentDepositQueueHash);

                function depositEncrypted(
                    address token,
                    uint128 amount,
                    uint256 keyIndex,
                    DepositPayload calldata encrypted,
                    address tempoRefundRecipient
                ) external returns (bytes32 newCurrentDepositQueueHash);

                function setSequencerEncryptionKey(
                    bytes32 x,
                    uint8 yParity,
                    uint8 popV,
                    bytes32 popR,
                    bytes32 popS
                ) external;

                // -- View functions (token management) --

                function isTokenEnabled(address token) external view returns (bool);
                function enabledTokenCount() external view returns (uint256);
                function lastProcessedEnabledTokenCount() external view returns (uint64);
                function tokenEnablementCursorInitialized() external view returns (bool);
                function enabledTokenAt(uint256 index) external view returns (address);
                function tokenEnablementHash() external view returns (bytes32);
                function zoneGasRate() external view returns (uint128);
                function maxTempoGasRate() external view returns (uint128);
                function bouncebackGas() external view returns (uint64);
                function pendingAdmin() external view returns (address);
                function refunds(address token, address owner) external view returns (uint128);

                function sequencerEncryptionKey()
                    external
                    view
                    returns (bytes32 x, uint8 yParity, address pubkey);

                function encryptionKeyCount() external view returns (uint256);
                function encryptionKeyAt(uint256 index)
                    external view returns (EncryptionKeyEntry memory entry);
                function isEncryptionKeyValid(uint256 keyIndex)
                    external view returns (bool valid, uint64 expiresAtBlock);
                function encryptionKeyAtBlock(uint64 tempoBlockNumber)
                    external view returns (bytes32 x, uint8 yParity, uint256 keyIndex);
                function claimRefund(address token) external returns (uint128 amount);
            }
        }
    };
}

crate::zone_portal_abi!(crate::sol);

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::keccak256;
    use alloy_sol_types::{SolCall, SolEvent};

    #[test]
    fn payment_and_settlement_selectors_match_deployed_protocol() {
        for (signature, selector) in [
            (
                "deposit(address,uint128,uint256,(bytes32,uint8,bytes,bytes12,bytes16),address)",
                ZonePortal::depositCall::SELECTOR,
            ),
            (
                "depositEncrypted(address,uint128,uint256,(bytes32,uint8,bytes,bytes12,bytes16),address)",
                ZonePortal::depositEncryptedCall::SELECTOR,
            ),
            (
                "processWithdrawals((address,bytes32,address,uint128,bytes32,uint64,uint64,bytes,bytes)[],bytes32)",
                ZonePortal::processWithdrawalsCall::SELECTOR,
            ),
            (
                "claimRefund(address)",
                ZonePortal::claimRefundCall::SELECTOR,
            ),
            (
                "submitBatch(uint64,uint64,(bytes32,bytes32),(bytes32,bytes32,uint64,uint64),bytes32,bytes,bytes,uint256,bytes[])",
                ZonePortal::submitBatch_0Call::SELECTOR,
            ),
            (
                "submitBatch(uint64,uint64,(bytes32,bytes32),(bytes32,bytes32,uint64,uint64),(uint64,uint64),bytes32,bytes,bytes,uint256,bytes[])",
                ZonePortal::submitBatch_1Call::SELECTOR,
            ),
        ] {
            assert_eq!(selector.as_slice(), &keccak256(signature)[..4]);
        }
        assert_ne!(
            ZonePortal::submitBatch_0Call::SELECTOR,
            ZonePortal::submitBatch_1Call::SELECTOR
        );
    }

    #[test]
    fn settlement_events_keep_historical_and_t13_commitments_distinct() {
        assert_eq!(
            ZonePortal::BatchSubmitted_0::SIGNATURE_HASH,
            keccak256("BatchSubmitted(uint64,uint256,bytes32,bytes32,bytes32,uint64)")
        );
        assert_eq!(
            ZonePortal::BatchSubmitted_1::SIGNATURE_HASH,
            keccak256("BatchSubmitted(uint64,uint256,bytes32,bytes32,bytes32,uint64,uint64)")
        );
    }
}
