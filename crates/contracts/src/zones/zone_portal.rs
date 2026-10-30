//! `ZonePortal` — deployed on Tempo L1.

pub use ZonePortal::{
    BatchSubmitted_0 as LegacyBatchSubmitted, BatchSubmitted_1 as BatchSubmitted, BlockTransition,
    Deposit, DepositPayload, DepositQueueTransition, TokenEnablementTransition, Withdrawal,
    ZonePortalErrors as ZonePortalError, submitBatch_0Call as legacySubmitBatchCall,
    submitBatch_1Call as submitBatchCall,
};

use super::{IZoneOutbox, ZoneInboxEvent};
#[cfg(feature = "rpc")]
use alloc::{format, string::ToString};
use alloy_primitives::{Address, B256, Bytes, keccak256};
use alloy_sol_types::SolValue;

/// Maximum UTF-8 byte length of each enabled token metadata string.
pub const MAX_TOKEN_METADATA_BYTES: usize = 31;

crate::sol! {
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

    /// Proof-agnostic Zone verifier ABI retained by TIP-1098.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IZoneVerifier {
        function verify(
            uint32 zoneId,
            uint64 tempoBlockNumber,
            uint64 anchorBlockNumber,
            bytes32 anchorBlockHash,
            uint64 expectedWithdrawalBatchIndex,
            uint256 nextZoneHeight,
            ZonePortal.BlockTransition calldata blockTransition,
            ZonePortal.DepositQueueTransition calldata depositQueueTransition,
            ZonePortal.TokenEnablementTransition calldata tokenEnablementTransition,
            bytes32 withdrawalQueueHash,
            bytes calldata verifierConfig,
            bytes calldata proof
        ) external view returns (bool);
    }
}

#[cfg(feature = "rpc")]
impl<P: alloy_provider::Provider<N>, N: alloy_network::Network>
    ZonePortal::ZonePortalInstance<P, N>
{
    /// Returns all token addresses currently enabled for bridging on this [`ZonePortal`].
    ///
    /// Equivalent to [`enabled_tokens_at`](Self::enabled_tokens_at) pinned to the `latest`
    /// block tag.
    pub async fn enabled_tokens(
        &self,
    ) -> Result<alloc::vec::Vec<alloy_primitives::Address>, alloy_contract::Error> {
        self.enabled_tokens_at(alloy_rpc_types_eth::BlockId::latest())
            .await
    }

    /// Returns all token addresses enabled for bridging at `block_id`.
    ///
    /// Callers that pair the returned token list with other historical L1 reads
    /// should use this instead of [`enabled_tokens`](Self::enabled_tokens), so
    /// future `TokenEnabled` events are not mixed into older state snapshots.
    ///
    /// Issues two RPC requests regardless of registry size: an
    /// [`enabledTokenCount`](ZonePortal::enabledTokenCountCall) read, then one Multicall3
    /// `aggregate` batching an [`enabledTokenAt`](ZonePortal::enabledTokenAtCall) call per
    /// index. The batch executes as a single EVM call, so all index reads observe the same
    /// state snapshot; only the count read can race the batch when `block_id` is a moving tag
    /// like `latest`. If any index read reverts, the whole call errors.
    ///
    /// Requires Multicall3 at the canonical
    /// [`MULTICALL3_ADDRESS`](alloy_provider::MULTICALL3_ADDRESS) on the portal's chain; all
    /// Tempo networks predeploy it at genesis.
    pub async fn enabled_tokens_at(
        &self,
        block_id: alloy_rpc_types_eth::BlockId,
    ) -> Result<alloc::vec::Vec<alloy_primitives::Address>, alloy_contract::Error> {
        let count = self
            .enabledTokenCount()
            .block(block_id)
            .call()
            .await?
            .to::<u64>();
        if count == 0 {
            return Ok(alloc::vec::Vec::new());
        }
        let mut multicall = self
            .provider()
            .multicall()
            .dynamic::<ZonePortal::enabledTokenAtCall>()
            .block(block_id);
        for i in 0..count {
            multicall = multicall.add_dynamic(self.enabledTokenAt(alloy_primitives::U256::from(i)));
        }
        multicall.aggregate().await.map_err(|err| match err {
            alloy_provider::MulticallError::TransportError(err) => err.into(),
            alloy_provider::MulticallError::DecodeError(err) => err.into(),
            err => {
                alloy_provider::transport::TransportErrorKind::custom_str(&err.to_string()).into()
            }
        })
    }

    /// Returns all sequencer addresses currently registered on this [`ZonePortal`].
    ///
    /// Calls [`sequencerCount`](ZonePortal::sequencerCountCall) followed by a Multicall3
    /// batch of [`sequencerAt`](ZonePortal::sequencerAtCall) reads.
    pub async fn sequencers(
        &self,
    ) -> Result<alloc::vec::Vec<alloy_primitives::Address>, alloy_contract::Error> {
        self.sequencers_at(alloy_rpc_types_eth::BlockId::latest())
            .await
    }

    /// Returns all sequencer addresses registered at `block_id`.
    ///
    /// The index reads go through Multicall3 so they execute in a single EVM call and observe
    /// one state snapshot even when `block_id` is a moving tag like `latest`.
    pub async fn sequencers_at(
        &self,
        block_id: alloy_rpc_types_eth::BlockId,
    ) -> Result<alloc::vec::Vec<alloy_primitives::Address>, alloy_contract::Error> {
        let count = self
            .sequencerCount()
            .block(block_id)
            .call()
            .await?
            .to::<u64>();
        if count == 0 {
            return Ok(alloc::vec::Vec::new());
        }
        let mut multicall = self
            .provider()
            .multicall()
            .dynamic::<ZonePortal::sequencerAtCall>()
            .block(block_id);
        for i in 0..count {
            multicall = multicall.add_dynamic(self.sequencerAt(alloy_primitives::U256::from(i)));
        }
        multicall.aggregate().await.map_err(|err| match err {
            alloy_provider::MulticallError::TransportError(err) => err.into(),
            alloy_provider::MulticallError::DecodeError(err) => err.into(),
            err => {
                alloy_provider::transport::TransportErrorKind::custom_str(&err.to_string()).into()
            }
        })
    }

    /// Fetches the active sequencer encryption key and its index from one L1 snapshot.
    ///
    /// Reads the current L1 block number, then pins an atomic
    /// [`encryptionKeyAtBlock`](ZonePortal::encryptionKeyAtBlockCall) call to that block so a key
    /// rotation cannot pair a key with an index from a different state snapshot.
    /// Returns `(key, key_index)` where `key` is the
    /// [`sequencerEncryptionKeyReturn`](ZonePortal::sequencerEncryptionKeyReturn) and
    /// `key_index` is the zero-based index of the current key.
    pub async fn encryption_key(
        &self,
    ) -> Result<
        (
            ZonePortal::sequencerEncryptionKeyReturn,
            alloy_primitives::U256,
        ),
        alloy_contract::Error,
    > {
        let block_number = self.provider().get_block_number().await?;
        let key = self
            .encryptionKeyAtBlock(block_number)
            .block(alloy_rpc_types_eth::BlockId::number(block_number))
            .call()
            .await?;
        let mut compressed = [0; 33];
        compressed[0] = key.yParity;
        compressed[1..].copy_from_slice(key.x.as_slice());
        let verifying_key =
            k256::ecdsa::VerifyingKey::from_sec1_bytes(&compressed).map_err(|err| {
                alloy_contract::Error::TransportError(
                    alloy_transport::TransportErrorKind::custom_str(&format!(
                        "invalid Portal encryption public key: {err}"
                    )),
                )
            })?;
        Ok((
            ZonePortal::sequencerEncryptionKeyReturn {
                x: key.x,
                yParity: key.yParity,
                pubkey: Address::from_public_key(&verifying_key),
            },
            key.keyIndex,
        ))
    }
}

#[cfg(all(test, feature = "rpc"))]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use alloy_provider::{ProviderBuilder, bindings::IMulticall3};
    use alloy_sol_types::SolCall;
    use alloy_transport::mock::Asserter;
    use k256::elliptic_curve::sec1::ToEncodedPoint as _;

    #[tokio::test]
    async fn encryption_key_reads_key_and_index_from_one_snapshot() {
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let block_number = 42_u64;
        let private_key = k256::SecretKey::from_slice(&[0x11; 32]).unwrap();
        let compressed = private_key.public_key().to_encoded_point(true);
        let verifying_key =
            k256::ecdsa::VerifyingKey::from_sec1_bytes(compressed.as_bytes()).unwrap();
        let expected = ZonePortal::encryptionKeyAtBlockReturn {
            x: B256::from_slice(compressed.x().unwrap()),
            yParity: compressed.as_bytes()[0],
            keyIndex: U256::from(7),
        };

        asserter.push_success(&block_number);
        asserter.push_success(&Bytes::from(
            ZonePortal::encryptionKeyAtBlockCall::abi_encode_returns(&expected),
        ));

        let portal = ZonePortal::new(Address::ZERO, &provider);
        let (key, key_index) = portal.encryption_key().await.unwrap();

        assert_eq!(key.x, expected.x);
        assert_eq!(key.yParity, expected.yParity);
        assert_eq!(key.pubkey, Address::from_public_key(&verifying_key));
        assert_eq!(key_index, expected.keyIndex);
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test]
    async fn enabled_tokens_at_batches_index_reads_through_multicall() {
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let tokens = [Address::repeat_byte(0xaa), Address::repeat_byte(0xbb)];

        asserter.push_success(&Bytes::from(U256::from(tokens.len()).abi_encode()));
        asserter.push_success(&Bytes::from(
            IMulticall3::aggregateCall::abi_encode_returns(&IMulticall3::aggregateReturn {
                blockNumber: U256::ZERO,
                returnData: tokens
                    .iter()
                    .map(|token| token.abi_encode().into())
                    .collect(),
            }),
        ));

        let portal = ZonePortal::new(Address::ZERO, &provider);
        let enabled = portal
            .enabled_tokens_at(alloy_rpc_types_eth::BlockId::latest())
            .await
            .unwrap();

        assert_eq!(enabled, tokens);
        assert!(asserter.read_q().is_empty());
    }
}

impl ZonePortal::sequencerEncryptionKeyReturn {
    /// Normalize `yParity` to SEC1 compressed prefix (`0x02` or `0x03`).
    ///
    /// The contract may return `0`/`1` (parity bit) or `0x02`/`0x03` (SEC1 prefix).
    pub fn normalized_y_parity(&self) -> Option<u8> {
        match self.yParity {
            0x02 | 0x03 => Some(self.yParity),
            0 | 1 => Some(0x02 + self.yParity),
            _ => None,
        }
    }
}

impl core::fmt::Display for ZonePortal::ZonePortalErrors {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotSequencer(_) => f.write_str("NotSequencer"),
            Self::NotAdmin(_) => f.write_str("NotAdmin"),
            Self::NotPauseAuthority(_) => f.write_str("NotPauseAuthority"),
            Self::CapabilityAbdicated(_) => f.write_str("CapabilityAbdicated"),
            Self::AbdicationAlreadyScheduled(_) => f.write_str("AbdicationAlreadyScheduled"),
            Self::PortalIsPaused(_) => f.write_str("PortalIsPaused"),
            Self::NotPendingAdmin(_) => f.write_str("NotPendingAdmin"),
            Self::InvalidProof(_) => f.write_str("InvalidProof"),
            Self::InvalidTokenEnablementTransition(_) => {
                f.write_str("InvalidTokenEnablementTransition")
            }
            Self::InvalidTempoBlockNumber(_) => f.write_str("InvalidTempoBlockNumber"),
            Self::InvalidBouncebackRecipient(_) => f.write_str("InvalidBouncebackRecipient"),
            Self::TokenNotEnabled(_) => f.write_str("TokenNotEnabled"),
            Self::DepositBlockCapacityExceeded(_) => f.write_str("DepositBlockCapacityExceeded"),
            Self::InvalidCallbackTarget(_) => f.write_str("InvalidCallbackTarget"),
            Self::AccountNotAllowed(_) => f.write_str("AccountNotAllowed"),
            Self::InvalidLeader(_) => f.write_str("InvalidLeader"),
            Self::ActiveLeaderRemoved(_) => f.write_str("ActiveLeaderRemoved"),
            Self::LeaderAlreadyUpdatedThisBlock(_) => f.write_str("LeaderAlreadyUpdatedThisBlock"),
            Self::StaleLeadershipEpoch(_) => f.write_str("StaleLeadershipEpoch"),
            _ => f.write_str("ZonePortalError"),
        }
    }
}

impl Deposit {
    /// Build the event emitted after a successfully processed deposit.
    pub fn processed_event(
        &self,
        deposit_hash: B256,
        recipient: Address,
        memo: B256,
    ) -> ZoneInboxEvent {
        ZoneInboxEvent::deposit_processed(
            deposit_hash,
            self.sender,
            recipient,
            self.token,
            self.amount,
            memo,
        )
    }

    /// Build the event emitted after a failed deposit.
    pub fn failed_event(&self, deposit_hash: B256) -> ZoneInboxEvent {
        ZoneInboxEvent::deposit_failed(deposit_hash, self.sender, self.token, self.amount)
    }
}

impl Withdrawal {
    /// Build the authenticated-withdrawal sender plaintext `[sender(20) | tx_hash(32)]`.
    pub fn authenticated_sender_plaintext(sender: Address, tx_hash: B256) -> [u8; 52] {
        let mut plaintext = [0u8; 52];
        plaintext[..20].copy_from_slice(sender.as_slice());
        plaintext[20..].copy_from_slice(tx_hash.as_slice());
        plaintext
    }

    /// Compute the authenticated sender tag for one user withdrawal.
    ///
    /// The fallback nonce is public on L1 and unique per user withdrawal, so including it keeps
    /// multiple withdrawals from the same private transaction unlinkable. Deposit bounce-backs
    /// retain their canonical zero-sender tag.
    pub fn sender_tag(sender: Address, tx_hash: B256, fallback_nonce: u64) -> B256 {
        if sender.is_zero() && fallback_nonce == 0 {
            return keccak256(Self::authenticated_sender_plaintext(
                Address::ZERO,
                B256::ZERO,
            ));
        }

        let mut preimage = [0u8; 60];
        preimage[..52].copy_from_slice(&Self::authenticated_sender_plaintext(sender, tx_hash));
        preimage[52..].copy_from_slice(&fallback_nonce.to_be_bytes());
        keccak256(preimage)
    }

    /// Reconstruct the public L1-facing withdrawal from a zone-side withdrawal request event.
    pub fn from_requested_event(
        event: &IZoneOutbox::WithdrawalRequested,
        tx_hash: B256,
        encrypted_sender: Bytes,
    ) -> Self {
        Self {
            token: event.token,
            senderTag: Self::sender_tag(event.sender, tx_hash, event.fallbackNonce),
            to: event.to,
            amount: event.amount,
            memo: event.memo,
            gasLimit: event.gasLimit,
            fallbackNonce: event.fallbackNonce,
            callbackData: event.data.clone(),
            encryptedSender: encrypted_sender,
        }
    }

    /// Hash this withdrawal as one link in a withdrawal queue.
    pub fn hash_with_tail(&self, tail: B256) -> B256 {
        keccak256((self.clone(), tail).abi_encode_params())
    }

    /// Compute the withdrawal queue hash for a slice of withdrawals.
    ///
    /// The hash chain has the oldest withdrawal at the outermost layer for efficient FIFO removal:
    ///
    /// ```text
    /// hash = keccak256(encode(w[0], keccak256(encode(w[1], keccak256(encode(w[2], 0))))))
    /// ```
    ///
    /// Building proceeds from the newest (innermost) to the oldest (outermost).
    /// Returns `B256::ZERO` if `withdrawals` is empty.
    pub fn queue_hash(withdrawals: &[Self]) -> B256 {
        let mut hash = B256::ZERO;
        for withdrawal in withdrawals.iter().rev() {
            hash = withdrawal.hash_with_tail(hash);
        }
        hash
    }
}
