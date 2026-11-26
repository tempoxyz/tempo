//! Native port of the T15 ZonePortal runtime's deposit, batch submission and withdrawal paths
//! that the public-mix benchmark takes, over a portal proxy's storage.

use super::{access, charge, charge_precompile_input, overflow, revert};
use crate::{
    ADDRESS_REGISTRY_ADDRESS, STORAGE_CREDITS_ADDRESS, TIP403_REGISTRY_ADDRESS,
    ZONE_PORTAL_IMPL_ADDRESS,
    address_registry::AddressRegistry,
    error::{Result, TempoPrecompileError},
    storage::{ContractStorage, StorageCtx, StorageKey},
    storage_credits::StorageCredits,
    tip20::{ITIP20, TIP20Error, TIP20Token},
    tip403_registry::{AuthRole, TIP403Registry},
    zone_factory::portal::slots,
};
use alloy::{
    primitives::{Address, B256, U256, address, keccak256, uint},
    sol,
    sol_types::{
        SolEvent, SolType, SolValue,
        sol_data::{FixedBytes, Uint},
    },
};
use tempo_contracts::{
    precompiles::{IStorageCredits::Mode, ITIP403Registry::BlockedReason},
    zones::{
        BlockTransition, Deposit, DepositQueueTransition, TokenEnablementTransition, Withdrawal,
        ZonePortal,
    },
};
use tempo_primitives::TempoAddressExt;

/// The EIP-2935 block hash history contract.
const HISTORY_STORAGE_ADDRESS: Address = address!("0x0000F90827F1C53a10cb7A02335B175320002935");
/// Blocks the EIP-2935 contract serves, and the modulus of its ring buffer.
const HISTORY_SERVE_WINDOW: u64 = 8191;

/// keccak256 of the T15 ZonePortal runtime, the only implementation this port follows.

/// Opcode gas when `_snapshotCongestionTier` fixes this block's tier instead of reading it.
pub(super) const SNAPSHOT_WRITE_GAS: u64 = 150;
/// Opcode gas of the first append's checkpoint bootstrap.
pub(super) const BOOTSTRAP_GAS: u64 = 966;
/// Opcode gas of a checkpoint append every `DEPOSITS_PER_BUCKET` entries.
pub(super) const CHECKPOINT_GAS: u64 = 894;
/// Opcode gas of a pruning iteration that deletes a checkpoint, with the cursor advance that
/// follows. The benchmark deletes at most one checkpoint per run, so the two are measured
/// together.
pub(super) const PRUNE_DELETE_GAS: u64 = 513;
/// Opcode gas of one pruning iteration's check whether a checkpoint's successor is settled.
pub(super) const PRUNE_CHECK_GAS: u64 = 229;

const FIXED_DEPOSIT_GAS: u128 = 100_000;
const DEPOSITS_PER_BUCKET: u64 = 230;
const DEPOSITS_PER_CONGESTION_TIER: u64 = 230;
const CONGESTION_MAX_TIER: u64 = 32;
const CONGESTION_MAX_FEE: u128 = 100_000;
const DEPOSIT_BUCKETS_PRUNED_PER_CALL: u64 = 2;
const CHECKPOINT_CREATED_SLOTS: u64 = 1;
const BOOTSTRAP_CREATED_SLOTS: u64 = 3;
const MAX_UNPROCESSED_TOKEN_ENABLEMENTS: u64 = 8;
const MAX_WITHDRAWAL_GAS_LIMIT: u64 = 10_000_000;
const ENCRYPTION_KEY_GRACE_PERIOD: u64 = 86_400;
const ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE: usize = 64;
const TEMPO_BASE_FEE_SCALE: U256 = uint!(1_000_000_000_000_U256);
const WITHDRAWAL_NOT_ENTERED: U256 = U256::ZERO;
const WITHDRAWAL_PROCESSING: U256 = uint!(1_U256);
const CALLBACK_DEPOSIT_AVAILABLE: U256 = uint!(2_U256);
const CALLBACK_DEPOSIT_CONSUMED: U256 = uint!(3_U256);
const ROLE_SEQUENCER: u8 = 1;
const ROLE_ACCOUNT: u8 = 2;
const ROLE_CALLBACK_GATEWAY: u8 = 3;
/// `DepositType` discriminators in the deposit queue hash chain.
const DEPOSIT_TYPE_BOUNCE_BACK: u8 = 0;
const DEPOSIT_TYPE_DEPOSIT: u8 = 1;
/// `uint256.max`, the queue index of a batch without withdrawals.
const NO_QUEUE_INDEX: U256 = U256::MAX;
/// Slots per `DepositBucket` and per `EncryptionKeyEntry`.
const ENTRY_SLOTS: u64 = 2;
const SECP256K1_P: U256 =
    uint!(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F_U256);
const SECP256K1_HALF_PM1: U256 =
    uint!(0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFE17_U256);

const ADMIN: Field = Field::new(slots::ADMIN, slots::ADMIN_OFFSET, 20);
const ZONE_GAS_RATE: Field = Field::new(slots::ZONE_GAS_RATE, slots::ZONE_GAS_RATE_OFFSET, 16);
const WITHDRAWAL_BATCH_INDEX: Field = Field::new(
    slots::WITHDRAWAL_BATCH_INDEX,
    slots::WITHDRAWAL_BATCH_INDEX_OFFSET,
    8,
);
const BLOCK_HASH: Field = Field::word(slots::BLOCK_HASH);
const CURRENT_DEPOSIT_QUEUE_HASH: Field = Field::word(slots::CURRENT_DEPOSIT_QUEUE_HASH);
const DEPOSIT_COUNT: Field = Field::new(slots::DEPOSIT_COUNT, slots::DEPOSIT_COUNT_OFFSET, 8);
const LAST_PROCESSED_DEPOSIT_NUMBER: Field = Field::new(
    slots::LAST_PROCESSED_DEPOSIT_NUMBER,
    slots::LAST_PROCESSED_DEPOSIT_NUMBER_OFFSET,
    8,
);
const LAST_SYNCED_TEMPO_BLOCK_NUMBER: Field = Field::new(
    slots::LAST_SYNCED_TEMPO_BLOCK_NUMBER,
    slots::LAST_SYNCED_TEMPO_BLOCK_NUMBER_OFFSET,
    8,
);
const BOUNCEBACK_GAS: Field = Field::new(slots::BOUNCEBACK_GAS, slots::BOUNCEBACK_GAS_OFFSET, 8);
const ENCRYPTION_KEYS: Field = Field::word(slots::ENCRYPTION_KEYS);
const ENABLED_TOKENS: Field = Field::word(slots::ENABLED_TOKENS);
const WITHDRAWAL_QUEUE_HEAD: Field = Field::word(slots::WITHDRAWAL_QUEUE);
const WITHDRAWAL_QUEUE_TAIL: Field =
    Field::word(slots::WITHDRAWAL_QUEUE.saturating_add(uint!(1_U256)));
const WITHDRAWAL_QUEUE_SLOTS: U256 = slots::WITHDRAWAL_QUEUE.saturating_add(uint!(2_U256));
const WITHDRAWAL_REENTRANCY_STATUS: Field = Field::word(slots::WITHDRAWAL_REENTRANCY_STATUS);
const ZONE_ID: Field = Field::new(slots::ZONE_ID, slots::ZONE_ID_OFFSET, 4);
const VERIFIER: Field = Field::new(slots::VERIFIER, slots::VERIFIER_OFFSET, 20);
const SEQUENCER_SET_VERSION: Field = Field::new(
    slots::SEQUENCER_SET_VERSION,
    slots::SEQUENCER_SET_VERSION_OFFSET,
    8,
);
const SEQUENCER_THRESHOLD: Field = Field::new(
    slots::SEQUENCER_THRESHOLD,
    slots::SEQUENCER_THRESHOLD_OFFSET,
    1,
);
const ZONE_HEIGHT: Field = Field::word(slots::ZONE_HEIGHT);
const SEQUENCERS: Field = Field::word(slots::SEQUENCERS);
const IS_ACCESS_ENFORCED: Field = Field::new(
    slots::IS_ACCESS_ENFORCED,
    slots::IS_ACCESS_ENFORCED_OFFSET,
    1,
);
const IS_GATEWAY_ENFORCED: Field = Field::new(
    slots::IS_GATEWAY_ENFORCED,
    slots::IS_GATEWAY_ENFORCED_OFFSET,
    1,
);
const PAUSE_EXPIRY: Field = Field::new(slots::PAUSE_EXPIRY, slots::PAUSE_EXPIRY_OFFSET, 8);
const LAST_PROCESSED_ENABLED_TOKEN_COUNT: Field = Field::new(
    slots::LAST_PROCESSED_ENABLED_TOKEN_COUNT,
    slots::LAST_PROCESSED_ENABLED_TOKEN_COUNT_OFFSET,
    8,
);
const TOKEN_ENABLEMENT_CURSOR_INITIALIZED: Field = Field::new(
    slots::TOKEN_ENABLEMENT_CURSOR_INITIALIZED,
    slots::TOKEN_ENABLEMENT_CURSOR_INITIALIZED_OFFSET,
    1,
);
const DEPOSIT_BUCKETS: Field = Field::word(slots::DEPOSIT_BUCKETS);
const DEPOSIT_PRICE_BLOCK: Field = Field::new(
    slots::DEPOSIT_PRICE_BLOCK,
    slots::DEPOSIT_PRICE_BLOCK_OFFSET,
    8,
);
const DEPOSIT_PRICE_TIER: Field = Field::new(
    slots::DEPOSIT_PRICE_TIER,
    slots::DEPOSIT_PRICE_TIER_OFFSET,
    8,
);
const DEPOSIT_BUCKET_BASE: Field = Field::new(
    slots::DEPOSIT_BUCKET_BASE,
    slots::DEPOSIT_BUCKET_BASE_OFFSET,
    8,
);
const NEXT_DEPOSIT_BUCKET_TO_PRUNE: Field = Field::new(
    slots::NEXT_DEPOSIT_BUCKET_TO_PRUNE,
    slots::NEXT_DEPOSIT_BUCKET_TO_PRUNE_OFFSET,
    8,
);

sol! {
    /// A withdrawal bounce-back as the deposit queue hashes it.
    struct WithdrawalBounceBackDeposit {
        address token;
        address to;
        uint128 amount;
    }

    /// `WithdrawalQueueLib`'s error for a withdrawal that is not at the queue head.
    error InvalidWithdrawalProof();
}

/// A ZonePortal batch, with empty verifier config, proof and signatures.
pub(super) struct Batch {
    pub(super) tempo_block_number: u64,
    pub(super) recent_tempo_block_number: u64,
    pub(super) blocks: BlockTransition,
    pub(super) deposits: DepositQueueTransition,
    pub(super) tokens: TokenEnablementTransition,
    pub(super) withdrawal_queue_hash: B256,
    pub(super) next_zone_height: U256,
}

/// A portal proxy's storage, run as the T15 ZonePortal runtime runs over it.
pub(super) struct Portal {
    address: Address,
}

impl Portal {
    /// The portal proxy at `address`, after touching the implementation as the proxy's
    /// `DELEGATECALL` does. The bench's genesis installs the T15 runtime (T15_ZONE_PORTAL_RUNTIME)
    /// at the implementation address; its code hash is not checked here because the payload
    /// builder's state caches can report account info without it.
    pub(super) fn enter(address: Address) -> Result<Self> {
        StorageCtx.with_account_info(ZONE_PORTAL_IMPL_ADDRESS, |_| Ok(()))?;
        Ok(Self { address })
    }

    /// The portal address.
    pub(super) fn address(&self) -> Address {
        self.address
    }

    /// `deposit(address,uint128,uint256,DepositPayload,address)` called by `sender`.
    pub(super) fn deposit(&self, sender: Address, call: ZonePortal::deposit_0Call) -> Result<B256> {
        self.require_not_paused()?;
        let max_fee = self.operational_deposit_fee()?;
        let ZonePortal::deposit_0Call {
            token,
            amount,
            keyIndex: key_index,
            encrypted,
            tempoRefundRecipient: refund_recipient,
        } = call;

        if refund_recipient.is_zero() {
            return Err(revert(ZonePortal::InvalidBouncebackRecipient {}));
        }
        // ADDRESS_REGISTRY.isVirtualAddress(refund_recipient), a pure precompile call.
        access(ADDRESS_REGISTRY_ADDRESS)?;
        charge_precompile_input(36)?;
        if refund_recipient.is_virtual() || is_zone_deposit_address(refund_recipient) {
            return Err(revert(ZonePortal::InvalidBouncebackRecipient {}));
        }
        self.require_allowed_depositor(sender)?;
        self.require_allowed(refund_recipient)?;
        self.validate_deposits_active(token)?;

        // ITIP20(token).transferPolicyId()
        let tip20 = Self::enter_tip20(token, 4)?;
        let policy_id = tip20.transfer_policy_id()?;
        // TIP403_REGISTRY.isAuthorizedRecipient(policyId, refund_recipient)
        access(TIP403_REGISTRY_ADDRESS)?;
        charge_precompile_input(68)?;
        if !TIP403Registry::new().is_authorized_as(
            policy_id,
            refund_recipient,
            AuthRole::Recipient,
        )? {
            return Err(TIP20Error::policy_forbids().into());
        }

        if !matches!(encrypted.ephemeralPubkeyYParity, 2 | 3)
            || !is_valid_x(encrypted.ephemeralPubkeyX.into())
        {
            return Err(revert(ZonePortal::InvalidEphemeralPubkey {}));
        }
        if encrypted.ciphertext.len() != ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE {
            return Err(revert(ZonePortal::InvalidCiphertextLength {
                actual: U256::from(encrypted.ciphertext.len()),
                expected: U256::from(ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE),
            }));
        }
        self.validate_encryption_key(key_index)?;

        // _collectDepositFunds
        let (fee, net_amount) = self.charge_deposit_fee(amount, max_fee)?;
        let mut tip20 = Self::enter_tip20(token, 100)?;
        tip20.transfer_from(
            self.address,
            ITIP20::transferFromCall {
                from: sender,
                to: self.address,
                amount: U256::from(amount),
            },
        )?;
        if fee > 0 {
            let admin = to_address(self.get(ADMIN)?);
            Self::enter_tip20(token, 68)?.transfer(
                self.address,
                ITIP20::transferCall {
                    to: admin,
                    amount: U256::from(fee),
                },
            )?;
        }

        let deposit = Deposit {
            token,
            sender,
            amount: net_amount,
            tempoRefundRecipient: refund_recipient,
            keyIndex: key_index,
            encrypted,
        };
        let current = self.get(CURRENT_DEPOSIT_QUEUE_HASH)?;
        let new_hash = keccak256(<(Uint<8>, Deposit, FixedBytes<32>)>::abi_encode_params(&(
            DEPOSIT_TYPE_DEPOSIT,
            deposit.clone(),
            B256::from(current),
        )));
        let deposit_number = self.record_deposit(new_hash)?;

        let Deposit {
            amount: net_amount,
            keyIndex: key_index,
            encrypted,
            ..
        } = deposit;
        self.emit(ZonePortal::DepositMade {
            newCurrentDepositQueueHash: new_hash,
            sender,
            token,
            netAmount: net_amount,
            fee,
            keyIndex: key_index,
            ephemeralPubkeyX: encrypted.ephemeralPubkeyX,
            ephemeralPubkeyYParity: encrypted.ephemeralPubkeyYParity,
            ciphertext: encrypted.ciphertext,
            nonce: encrypted.nonce,
            tag: encrypted.tag,
            tempoRefundRecipient: refund_recipient,
            depositNumber: deposit_number,
        })?;
        Ok(new_hash)
    }

    /// `submitBatch` with the TIP-1096 token transition, called by `sender`.
    pub(super) fn submit_batch(&self, sender: Address, batch: &Batch) -> Result<()> {
        self.require_sequencer(sender)?;
        if batch.blocks.prevBlockHash != B256::from(self.get(BLOCK_HASH)?) {
            return Err(revert(ZonePortal::InvalidProof {}));
        }

        let block_number = StorageCtx.block_number();
        let anchor_block_number = if batch.recent_tempo_block_number == 0 {
            batch.tempo_block_number
        } else {
            if batch.recent_tempo_block_number <= batch.tempo_block_number {
                return Err(revert(ZonePortal::InvalidTempoBlockNumber {}));
            }
            batch.recent_tempo_block_number
        };
        if anchor_block_number > block_number {
            return Err(revert(ZonePortal::InvalidTempoBlockNumber {}));
        }
        let anchor_block_hash = block_hash(anchor_block_number, block_number)?;
        if anchor_block_hash.is_zero() {
            return Err(revert(ZonePortal::InvalidTempoBlockNumber {}));
        }

        if !self.verify_settlement(batch)? {
            return Err(revert(ZonePortal::InvalidQuorumCertificate {}));
        }

        let deposits = &batch.deposits;
        let last_processed = self.get_u64(LAST_PROCESSED_DEPOSIT_NUMBER)?;
        if deposits.prevDepositNumber != last_processed
            || deposits.nextDepositNumber < deposits.prevDepositNumber
            || deposits.nextDepositNumber > self.get_u64(DEPOSIT_COUNT)?
        {
            return Err(revert(ZonePortal::InvalidDepositTransition {}));
        }

        let tokens = &batch.tokens;
        let enabled_count = self.get(ENABLED_TOKENS)?.saturating_to::<u64>();
        let cursor_initialized = !self.get(TOKEN_ENABLEMENT_CURSOR_INITIALIZED)?.is_zero();
        let expected_prev = if cursor_initialized {
            self.get_u64(LAST_PROCESSED_ENABLED_TOKEN_COUNT)?
        } else {
            0
        };
        if tokens.prevProcessedTokenCount != expected_prev
            || tokens.nextProcessedTokenCount < tokens.prevProcessedTokenCount
            || tokens.nextProcessedTokenCount > enabled_count
        {
            return Err(revert(ZonePortal::InvalidTokenEnablementTransition {}));
        }
        if !cursor_initialized
            && tokens.nextProcessedTokenCount != 0
            && enabled_count - tokens.nextProcessedTokenCount > MAX_UNPROCESSED_TOKEN_ENABLEMENTS
        {
            return Err(revert(ZonePortal::InvalidTokenEnablementTransition {}));
        }

        // IVerifier(verifier).verify(...): the benchmark's verifier is the settlement fixture,
        // whose fallback accepts every proof.
        self.get(ZONE_ID)?;
        let verifier = to_address(self.get(VERIFIER)?);
        if verifier != sender {
            return Err(TempoPrecompileError::Fatal(
                "native submitBatch supports only the settlement fixture as verifier".into(),
            ));
        }
        access(verifier)?;

        let batch_index = self
            .get_u64(WITHDRAWAL_BATCH_INDEX)?
            .checked_add(1)
            .ok_or_else(overflow)?;
        self.set(WITHDRAWAL_BATCH_INDEX, U256::from(batch_index))?;
        self.set(BLOCK_HASH, batch.blocks.nextBlockHash.into())?;
        self.set(
            LAST_SYNCED_TEMPO_BLOCK_NUMBER,
            U256::from(batch.tempo_block_number),
        )?;
        self.settle_deposits(deposits.nextDepositNumber)?;
        if cursor_initialized || tokens.nextProcessedTokenCount != 0 {
            self.set(
                LAST_PROCESSED_ENABLED_TOKEN_COUNT,
                U256::from(tokens.nextProcessedTokenCount),
            )?;
            self.set(TOKEN_ENABLEMENT_CURSOR_INITIALIZED, U256::ONE)?;
        }
        self.set(ZONE_HEIGHT, batch.next_zone_height)?;

        let queue_index = if batch.withdrawal_queue_hash.is_zero() {
            NO_QUEUE_INDEX
        } else {
            let tail = self.get(WITHDRAWAL_QUEUE_TAIL)?;
            self.store(
                tail.mapping_slot(WITHDRAWAL_QUEUE_SLOTS),
                batch.withdrawal_queue_hash.into(),
            )?;
            self.set(
                WITHDRAWAL_QUEUE_TAIL,
                tail.checked_add(U256::ONE).ok_or_else(overflow)?,
            )?;
            tail
        };

        self.emit(ZonePortal::BatchSubmitted_1 {
            withdrawalBatchIndex: self.get_u64(WITHDRAWAL_BATCH_INDEX)?,
            withdrawalQueueIndex: queue_index,
            nextProcessedDepositQueueHash: deposits.nextProcessedHash,
            nextBlockHash: self.get(BLOCK_HASH)?.into(),
            withdrawalQueueHash: batch.withdrawal_queue_hash,
            lastProcessedDepositNumber: self.get_u64(LAST_PROCESSED_DEPOSIT_NUMBER)?,
            lastProcessedEnabledTokenCount: self.get_u64(LAST_PROCESSED_ENABLED_TOKEN_COUNT)?,
        })
    }

    /// `processWithdrawals` (T15 ABI) called by `sender` with one plain withdrawal whose queue
    /// slot it exhausts, as the settlement fixture calls it.
    pub(super) fn process_withdrawal(
        &self,
        sender: Address,
        withdrawal: &Withdrawal,
    ) -> Result<()> {
        self.require_sequencer(sender)?;
        self.require_not_paused()?;
        if self.get(WITHDRAWAL_REENTRANCY_STATUS)? != WITHDRAWAL_NOT_ENTERED {
            return Err(revert(ZonePortal::ReentrantWithdrawal {}));
        }
        self.set(WITHDRAWAL_REENTRANCY_STATUS, WITHDRAWAL_PROCESSING)?;
        let link = withdrawal_link(withdrawal, B256::ZERO);
        self.prune_deposit_buckets()?;

        // _withdrawalQueue.dequeue(withdrawal, 0)
        let head = self.get(WITHDRAWAL_QUEUE_HEAD)?;
        let head_slot = head.mapping_slot(WITHDRAWAL_QUEUE_SLOTS);
        if link != B256::from(self.load(head_slot)?) {
            return Err(revert(InvalidWithdrawalProof {}));
        }
        self.store(head_slot, U256::ZERO)?;
        self.set(
            WITHDRAWAL_QUEUE_HEAD,
            head.checked_add(U256::ONE).ok_or_else(overflow)?,
        )?;

        let token = withdrawal.token;
        if withdrawal.fallbackNonce == 0 {
            return Err(TempoPrecompileError::Fatal(
                "native processWithdrawals does not support deposit bounce-backs".into(),
            ));
        }
        if withdrawal.gasLimit > MAX_WITHDRAWAL_GAS_LIMIT {
            self.enqueue_bounce_back(token, withdrawal.amount, withdrawal.fallbackNonce)?;
            self.emit_withdrawal_processed(withdrawal, false)?;
            return self.set(WITHDRAWAL_REENTRANCY_STATUS, WITHDRAWAL_NOT_ENTERED);
        }
        if withdrawal.gasLimit != 0 {
            return Err(TempoPrecompileError::Fatal(
                "native processWithdrawals does not support callbacks".into(),
            ));
        }
        let success = (self.get(IS_GATEWAY_ENFORCED)?.is_zero()
            || self.role(withdrawal.to)? != ROLE_CALLBACK_GATEWAY)
            && self.is_allowed(withdrawal.to)?
            && self.try_transfer(token, withdrawal.to, withdrawal.amount)?;
        if !success {
            self.enqueue_bounce_back(token, withdrawal.amount, withdrawal.fallbackNonce)?;
        }
        self.emit_withdrawal_processed(withdrawal, success)?;
        self.set(WITHDRAWAL_REENTRANCY_STATUS, WITHDRAWAL_NOT_ENTERED)
    }

    fn emit_withdrawal_processed(&self, withdrawal: &Withdrawal, success: bool) -> Result<()> {
        self.emit(ZonePortal::WithdrawalProcessed {
            to: withdrawal.to,
            senderTag: withdrawal.senderTag,
            token: withdrawal.token,
            amount: withdrawal.amount,
            callbackSuccess: success,
        })
    }

    /// The portal's `currentDepositQueueHash`.
    pub(super) fn current_deposit_queue_hash(&self) -> Result<B256> {
        self.get(CURRENT_DEPOSIT_QUEUE_HASH).map(B256::from)
    }

    /// The portal's `zoneHeight`.
    pub(super) fn zone_height(&self) -> Result<U256> {
        self.get(ZONE_HEIGHT)
    }

    /// The portal's `blockHash`.
    pub(super) fn block_hash(&self) -> Result<B256> {
        self.get(BLOCK_HASH).map(B256::from)
    }

    /// The portal's `lastProcessedDepositNumber`.
    pub(super) fn last_processed_deposit_number(&self) -> Result<u64> {
        self.get_u64(LAST_PROCESSED_DEPOSIT_NUMBER)
    }

    /// The portal's `depositCount`.
    pub(super) fn deposit_count(&self) -> Result<u64> {
        self.get_u64(DEPOSIT_COUNT)
    }

    /// The portal's `lastProcessedEnabledTokenCount`.
    pub(super) fn last_processed_enabled_token_count(&self) -> Result<u64> {
        self.get_u64(LAST_PROCESSED_ENABLED_TOKEN_COUNT)
    }

    /// The portal's `tokenEnablementCursorInitialized`.
    pub(super) fn token_cursor_initialized(&self) -> Result<bool> {
        Ok(!self.get(TOKEN_ENABLEMENT_CURSOR_INITIALIZED)?.is_zero())
    }

    fn require_not_paused(&self) -> Result<()> {
        if StorageCtx.timestamp() < U256::from(self.get_u64(PAUSE_EXPIRY)?) {
            return Err(revert(ZonePortal::PortalIsPaused {}));
        }
        Ok(())
    }

    fn require_sequencer(&self, account: Address) -> Result<()> {
        if self.role(account)? != ROLE_SEQUENCER {
            return Err(revert(ZonePortal::NotSequencer {}));
        }
        Ok(())
    }

    fn role(&self, account: Address) -> Result<u8> {
        let word = self.load(account.mapping_slot(slots::ROLE))?;
        Ok(word.byte(0))
    }

    fn is_allowed(&self, account: Address) -> Result<bool> {
        Ok(self.get(IS_ACCESS_ENFORCED)?.is_zero() || self.role(account)? == ROLE_ACCOUNT)
    }

    fn require_allowed(&self, account: Address) -> Result<()> {
        if !self.is_allowed(account)? {
            return Err(revert(ZonePortal::AccountNotAllowed { account }));
        }
        Ok(())
    }

    fn require_allowed_depositor(&self, account: Address) -> Result<()> {
        if self.get(IS_ACCESS_ENFORCED)?.is_zero() {
            return Ok(());
        }
        if !self.get(IS_GATEWAY_ENFORCED)?.is_zero() && self.role(account)? == ROLE_CALLBACK_GATEWAY
        {
            return Ok(());
        }
        if self.role(account)? != ROLE_ACCOUNT {
            return Err(revert(ZonePortal::AccountNotAllowed { account }));
        }
        Ok(())
    }

    fn validate_deposits_active(&self, token: Address) -> Result<()> {
        let config = self.load(token.mapping_slot(slots::TOKEN_CONFIGS))?;
        if config.byte(0) == 0 {
            return Err(revert(ZonePortal::TokenNotEnabled {}));
        }
        if config.byte(1) == 0 {
            return Err(revert(ZonePortal::DepositsNotActive {}));
        }
        Ok(())
    }

    /// `isEncryptionKeyValid(keyIndex)`, reverting as `_deposit` does when it is not.
    fn validate_encryption_key(&self, key_index: U256) -> Result<()> {
        let count = self.get(ENCRYPTION_KEYS)?;
        if key_index >= count {
            return Err(revert(ZonePortal::InvalidEncryptionKeyIndex {
                keyIndex: key_index,
            }));
        }
        if key_index == count - U256::ONE {
            return Ok(());
        }
        let next_activation = self.encryption_key_activation(key_index + U256::ONE)?;
        let expiration = next_activation
            .checked_add(ENCRYPTION_KEY_GRACE_PERIOD)
            .ok_or_else(overflow)?;
        if StorageCtx.block_number() < expiration {
            return Ok(());
        }
        Err(revert(ZonePortal::EncryptionKeyExpired {
            keyIndex: key_index,
            activationBlock: self.encryption_key_activation(key_index)?,
            supersededAtBlock: next_activation,
        }))
    }

    fn encryption_key_activation(&self, key_index: U256) -> Result<u64> {
        let slot =
            array_slot(slots::ENCRYPTION_KEYS) + key_index * U256::from(ENTRY_SLOTS) + U256::ONE;
        Ok(field(self.load(slot)?, 1, 8).saturating_to())
    }

    fn operational_deposit_fee(&self) -> Result<u128> {
        let rate: u128 = self.get(ZONE_GAS_RATE)?.saturating_to();
        FIXED_DEPOSIT_GAS.checked_mul(rate).ok_or_else(overflow)
    }

    fn unsettled_congestion_tier(&self) -> Result<u64> {
        let unsettled = self
            .get_u64(DEPOSIT_COUNT)?
            .checked_sub(self.get_u64(LAST_PROCESSED_DEPOSIT_NUMBER)?)
            .ok_or_else(overflow)?;
        Ok(unsettled / DEPOSITS_PER_CONGESTION_TIER)
    }

    /// `_chargeDepositFee(amount, maxFee)`: the fee and the net amount.
    fn charge_deposit_fee(&self, amount: u128, max_fee: u128) -> Result<(u128, u128)> {
        let mut fee = self.operational_deposit_fee()?;
        if self.get(WITHDRAWAL_REENTRANCY_STATUS)? == CALLBACK_DEPOSIT_AVAILABLE {
            self.set(WITHDRAWAL_REENTRANCY_STATUS, CALLBACK_DEPOSIT_CONSUMED)?;
        } else {
            let tier = self.snapshot_congestion_tier()?;
            fee = fee.checked_add(congestion_fee(tier)).ok_or_else(overflow)?;
        }
        if fee > max_fee {
            return Err(revert(ZonePortal::FeeTooHigh {
                fee,
                maxFee: max_fee,
            }));
        }
        let minimum = fee
            .checked_add(self.bounceback_fee()?)
            .ok_or_else(overflow)?;
        if amount < minimum {
            return Err(revert(ZonePortal::DepositTooSmall {}));
        }
        Ok((fee, amount - fee))
    }

    fn bounceback_fee(&self) -> Result<u128> {
        let basefee = StorageCtx.with_block_env(|block| block.basefee);
        let gas_fee = U256::from(self.get_u64(BOUNCEBACK_GAS)?)
            .checked_mul(basefee)
            .ok_or_else(overflow)?;
        let scaled = gas_fee
            .checked_add(TEMPO_BASE_FEE_SCALE - U256::ONE)
            .ok_or_else(overflow)?
            / TEMPO_BASE_FEE_SCALE;
        // Solidity's `uint128(...)` truncates.
        Ok(scaled.wrapping_to())
    }

    /// `_snapshotCongestionTier`: this block's tier, fixed from the state before its first
    /// change.
    fn snapshot_congestion_tier(&self) -> Result<u64> {
        let block_number = StorageCtx.block_number();
        if self.get_u64(DEPOSIT_PRICE_BLOCK)? == block_number {
            return self.get_u64(DEPOSIT_PRICE_TIER);
        }
        charge(SNAPSHOT_WRITE_GAS)?;
        let tier = self.unsettled_congestion_tier()?;
        // The bytecode writes both fields of the slot in one SSTORE.
        let word = self.load(DEPOSIT_PRICE_BLOCK.slot)?;
        let word = DEPOSIT_PRICE_BLOCK.write(word, U256::from(block_number));
        self.store(
            DEPOSIT_PRICE_TIER.slot,
            DEPOSIT_PRICE_TIER.write(word, U256::from(tier)),
        )?;
        Ok(tier)
    }

    /// `_recordDeposit(newHash)`: appends one entry and returns its deposit number.
    fn record_deposit(&self, new_hash: B256) -> Result<u64> {
        if self.get(DEPOSIT_BUCKETS)?.is_zero() {
            charge(BOOTSTRAP_GAS)?;
            self.set_storage_credit_budget(BOOTSTRAP_CREATED_SLOTS)?;
            self.set(
                DEPOSIT_BUCKET_BASE,
                U256::from(self.get_u64(DEPOSIT_COUNT)?),
            )?;
            let current = self.get(CURRENT_DEPOSIT_QUEUE_HASH)?;
            self.push_deposit_bucket(current)?;
            self.set_storage_credit_refund_mode()?;
        }

        self.snapshot_congestion_tier()?;

        self.set(CURRENT_DEPOSIT_QUEUE_HASH, new_hash.into())?;
        let deposit_number = self
            .get_u64(DEPOSIT_COUNT)?
            .checked_add(1)
            .ok_or_else(overflow)?;
        self.set(DEPOSIT_COUNT, U256::from(deposit_number))?;

        if self.get(WITHDRAWAL_REENTRANCY_STATUS)? == WITHDRAWAL_NOT_ENTERED {
            self.prune_deposit_buckets()?;
        }

        let since_base = deposit_number
            .checked_sub(self.get_u64(DEPOSIT_BUCKET_BASE)?)
            .ok_or_else(overflow)?;
        if since_base % DEPOSITS_PER_BUCKET == 0 {
            charge(CHECKPOINT_GAS)?;
            self.set_storage_credit_budget(CHECKPOINT_CREATED_SLOTS)?;
            self.push_deposit_bucket(new_hash.into())?;
            self.set_storage_credit_refund_mode()?;
        }
        Ok(deposit_number)
    }

    /// `depositBuckets.push().hash = hash`.
    fn push_deposit_bucket(&self, hash: U256) -> Result<()> {
        let length = self.get(DEPOSIT_BUCKETS)?;
        self.set(DEPOSIT_BUCKETS, length + U256::ONE)?;
        let slot = array_slot(slots::DEPOSIT_BUCKETS) + length * U256::from(ENTRY_SLOTS);
        self.store(slot, hash)
    }

    /// `_pruneDepositBuckets`: deletes up to `DEPOSIT_BUCKETS_PRUNED_PER_CALL` checkpoints whose
    /// successor is settled.
    fn prune_deposit_buckets(&self) -> Result<()> {
        let first = self.get_u64(NEXT_DEPOSIT_BUCKET_TO_PRUNE)?;
        let end = first + DEPOSIT_BUCKETS_PRUNED_PER_CALL;
        let length = self.get(DEPOSIT_BUCKETS)?.saturating_to::<u64>();
        let base = self.get_u64(DEPOSIT_BUCKET_BASE)?;
        let settled = self.get_u64(LAST_PROCESSED_DEPOSIT_NUMBER)?;
        let mut next = first;
        while next < end {
            if next >= length {
                break;
            }
            charge(PRUNE_CHECK_GAS)?;
            if base + (next + 1) * DEPOSITS_PER_BUCKET > settled {
                break;
            }
            charge(PRUNE_DELETE_GAS)?;
            let slot = array_slot(slots::DEPOSIT_BUCKETS) + U256::from(next * ENTRY_SLOTS);
            self.store(slot, U256::ZERO)?;
            self.store(slot + U256::ONE, U256::ZERO)?;
            next += 1;
        }
        if next != first {
            self.set(NEXT_DEPOSIT_BUCKET_TO_PRUNE, U256::from(next))?;
        }
        Ok(())
    }

    /// `_settleDeposits(settled)`: advances settlement, may lower this block's tier, then
    /// prunes.
    fn settle_deposits(&self, settled: u64) -> Result<()> {
        self.snapshot_congestion_tier()?;
        self.set(LAST_PROCESSED_DEPOSIT_NUMBER, U256::from(settled))?;
        let tier = self.unsettled_congestion_tier()?;
        if tier < self.get_u64(DEPOSIT_PRICE_TIER)? {
            self.set(DEPOSIT_PRICE_TIER, U256::from(tier))?;
        }
        self.prune_deposit_buckets()
    }

    /// `_verifySettlement` for a batch without signatures.
    fn verify_settlement(&self, batch: &Batch) -> Result<bool> {
        let threshold = self.get(SEQUENCER_THRESHOLD)?;
        // No signatures: below a nonzero threshold, and never above the sequencer count.
        if batch.next_zone_height <= self.get(ZONE_HEIGHT)? || !threshold.is_zero() {
            return Ok(false);
        }
        self.get(SEQUENCERS)?;
        // The attestation digest commits to these; with no signatures nothing else reads them.
        self.get(ZONE_ID)?;
        self.get(SEQUENCER_SET_VERSION)?;
        self.get(WITHDRAWAL_BATCH_INDEX)?;
        self.get(VERIFIER)?;
        Ok(true)
    }

    /// `_tryTransfer(token, to, amount)`.
    fn try_transfer(&self, token: Address, to: Address, amount: u128) -> Result<bool> {
        // try ADDRESS_REGISTRY.resolveRecipient(to)
        access(ADDRESS_REGISTRY_ADDRESS)?;
        charge_precompile_input(36)?;
        let Some(recipient) = caught(AddressRegistry::new().resolve_recipient(to))? else {
            return Ok(false);
        };
        // try TIP403_REGISTRY.validateReceivePolicy(token, address(this), recipient)
        access(TIP403_REGISTRY_ADDRESS)?;
        charge_precompile_input(100)?;
        let Some(blocked) =
            caught(TIP403Registry::new().validate_receive_policy(token, self.address, recipient))?
        else {
            return Ok(false);
        };
        if blocked.is_some_and(|reason| reason != BlockedReason::NONE) {
            return Ok(false);
        }
        // try ITIP20(token).transfer(to, amount)
        let mut tip20 = Self::enter_tip20(token, 68)?;
        let checkpoint = StorageCtx.checkpoint();
        let transferred = caught(tip20.transfer(
            self.address,
            ITIP20::transferCall {
                to,
                amount: U256::from(amount),
            },
        ))?;
        if transferred.is_some() {
            checkpoint.commit();
        }
        Ok(transferred.unwrap_or(false))
    }

    /// `_enqueueBounceBack(token, amount, fallbackNonce)`.
    fn enqueue_bounce_back(&self, token: Address, amount: u128, fallback_nonce: u64) -> Result<()> {
        let deposit = WithdrawalBounceBackDeposit {
            token,
            to: Address::from_word(B256::from(U256::from(fallback_nonce))),
            amount,
        };
        let current = self.get(CURRENT_DEPOSIT_QUEUE_HASH)?;
        let new_hash = keccak256(
            <(Uint<8>, WithdrawalBounceBackDeposit, FixedBytes<32>)>::abi_encode_params(&(
                DEPOSIT_TYPE_BOUNCE_BACK,
                deposit,
                B256::from(current),
            )),
        );
        let deposit_number = self.record_deposit(new_hash)?;
        self.emit(ZonePortal::WithdrawalBounceBack {
            newCurrentDepositQueueHash: new_hash,
            fallbackNonce: fallback_nonce,
            token,
            amount,
            depositNumber: deposit_number,
        })
    }

    /// The TIP-20 precompile at `token` as the EVM enters it for a call with `len` bytes of
    /// calldata.
    fn enter_tip20(token: Address, len: usize) -> Result<TIP20Token> {
        access(token)?;
        let tip20 = TIP20Token::from_address(token).map_err(|_| {
            TempoPrecompileError::Fatal("native portal supports only TIP-20 tokens".into())
        })?;
        charge_precompile_input(len)?;
        if !tip20.is_initialized()? {
            return Err(TIP20Error::uninitialized().into());
        }
        Ok(tip20)
    }

    /// `STORAGE_CREDITS.setBudget(credits)`.
    fn set_storage_credit_budget(&self, credits: u64) -> Result<()> {
        access(STORAGE_CREDITS_ADDRESS)?;
        charge_precompile_input(36)?;
        StorageCredits::new().set_budget(self.address, credits)
    }

    /// `STORAGE_CREDITS.setMode(Mode.Refund)`.
    fn set_storage_credit_refund_mode(&self) -> Result<()> {
        access(STORAGE_CREDITS_ADDRESS)?;
        charge_precompile_input(36)?;
        StorageCredits::new().set_mode(self.address, Mode::Refund)
    }

    fn emit(&self, event: impl SolEvent) -> Result<()> {
        StorageCtx.emit_event(self.address, event.encode_log_data())
    }

    fn load(&self, slot: U256) -> Result<U256> {
        StorageCtx.sload(self.address, slot)
    }

    fn store(&self, slot: U256, value: U256) -> Result<()> {
        StorageCtx.sstore(self.address, slot, value)
    }

    fn get(&self, field: Field) -> Result<U256> {
        Ok(field.read(self.load(field.slot)?))
    }

    fn get_u64(&self, field: Field) -> Result<u64> {
        Ok(self.get(field)?.saturating_to())
    }

    /// Writes one field, keeping the rest of its slot, as a Solidity assignment does.
    fn set(&self, field: Field, value: U256) -> Result<()> {
        let word = self.load(field.slot)?;
        self.store(field.slot, field.write(word, value))
    }
}

/// A value packed into a storage slot.
#[derive(Debug, Clone, Copy)]
struct Field {
    slot: U256,
    offset: usize,
    bytes: usize,
}

impl Field {
    const fn new(slot: U256, offset: usize, bytes: usize) -> Self {
        Self {
            slot,
            offset,
            bytes,
        }
    }

    const fn word(slot: U256) -> Self {
        Self::new(slot, 0, 32)
    }

    fn mask(self) -> U256 {
        if self.bytes == 32 {
            U256::MAX
        } else {
            (U256::ONE << (self.bytes * 8)) - U256::ONE
        }
    }

    fn read(self, word: U256) -> U256 {
        (word >> (self.offset * 8)) & self.mask()
    }

    fn write(self, word: U256, value: U256) -> U256 {
        let shift = self.offset * 8;
        (word & !(self.mask() << shift)) | ((value & self.mask()) << shift)
    }
}

/// Reads `bytes` bytes at byte `offset` of `word`.
fn field(word: U256, offset: usize, bytes: usize) -> U256 {
    Field::new(U256::ZERO, offset, bytes).read(word)
}

fn to_address(word: U256) -> Address {
    Address::from_word(word.into())
}

/// The first slot of the dynamic array whose length is at `slot`.
fn array_slot(slot: U256) -> U256 {
    keccak256(slot.to_be_bytes::<32>()).into()
}

/// The value of a precompile call a Solidity `try` makes, or `None` when it fails.
fn caught<T>(result: Result<T>) -> Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(
            error @ (TempoPrecompileError::Fatal(_)
            | TempoPrecompileError::Database(_)
            | TempoPrecompileError::OutOfGas),
        ) => Err(error),
        Err(_) => Ok(None),
    }
}

/// `WithdrawalQueueLib.hashWithTail(withdrawal, tail)`.
pub(super) fn withdrawal_link(withdrawal: &Withdrawal, tail: B256) -> B256 {
    if withdrawal.senderOrg != 0 {
        return keccak256((withdrawal.clone(), tail).abi_encode_params());
    }
    // The bytes of `abi.encode(LegacyWithdrawal, tail)`: the tuple offset, the tail, then the
    // legacy fields encoded as parameters.
    let fields = (
        withdrawal.token,
        withdrawal.senderTag,
        withdrawal.to,
        withdrawal.amount,
        withdrawal.memo,
        withdrawal.gasLimit,
        withdrawal.fallbackNonce,
        withdrawal.callbackData.clone(),
        withdrawal.encryptedSender.clone(),
    )
        .abi_encode_params();
    keccak256(
        [
            U256::from(0x40).to_be_bytes::<32>().as_slice(),
            tail.as_slice(),
            &fields,
        ]
        .concat(),
    )
}

/// TIP-1094: whether `account` has the zone deposit address format, for any zone.
fn is_zone_deposit_address(account: Address) -> bool {
    account.as_slice()[4..13] == [0xfc; 9]
}

fn congestion_fee(tier: u64) -> u128 {
    CONGESTION_MAX_FEE * u128::from(tier.min(CONGESTION_MAX_TIER)) / u128::from(CONGESTION_MAX_TIER)
}

/// `Secp256k1Lib.isValidX(x)`: whether `x` is the X coordinate of a secp256k1 point, by
/// Euler's criterion on `x^3 + 7` (the bytecode's MODEXP call).
fn is_valid_x(x: U256) -> bool {
    if x.is_zero() || x >= SECP256K1_P {
        return false;
    }
    let rhs = x
        .mul_mod(x, SECP256K1_P)
        .mul_mod(x, SECP256K1_P)
        .add_mod(U256::from(7), SECP256K1_P);
    rhs.pow_mod(SECP256K1_HALF_PM1, SECP256K1_P) == U256::ONE
}

/// `getBlockHash(number)`: the EIP-2935 history contract's answer at block `block_number`, read
/// from its storage as its code does, or zero where its call reverts.
fn block_hash(number: u64, block_number: u64) -> Result<B256> {
    access(HISTORY_STORAGE_ADDRESS)?;
    if number >= block_number || block_number - number > HISTORY_SERVE_WINDOW {
        return Ok(B256::ZERO);
    }
    StorageCtx
        .sload(
            HISTORY_STORAGE_ADDRESS,
            U256::from(number % HISTORY_SERVE_WINDOW),
        )
        .map(B256::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::b256;
    use tempo_contracts::zones::DepositPayload;

    /// Values from a public-mix run on the bytecode: the first deposit's `DepositMade` queue hash.
    #[test]
    fn deposit_queue_hash_matches_bytecode() {
        let user = address!("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        let deposit = Deposit {
            token: address!("0x20c0000000000000000000000000000000000000"),
            sender: user,
            amount: 1,
            tempoRefundRecipient: user,
            keyIndex: U256::ZERO,
            encrypted: DepositPayload {
                ephemeralPubkeyX: b256!(
                    "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                ),
                ephemeralPubkeyYParity: 2,
                ciphertext: vec![0x11; 64].into(),
                nonce: alloy::primitives::FixedBytes::repeat_byte(0x11),
                tag: alloy::primitives::FixedBytes::repeat_byte(0x11),
            },
        };
        let hash = keccak256(<(Uint<8>, Deposit, FixedBytes<32>)>::abi_encode_params(&(
            DEPOSIT_TYPE_DEPOSIT,
            deposit,
            B256::ZERO,
        )));
        assert_eq!(
            hash,
            b256!("0xd4fdae5ece6c9cc75f0cb4a5f66047257c94870cf7b73d265227c1200229fd6a")
        );
        assert!(is_valid_x(
            b256!("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").into()
        ));
    }

    /// Values from a public-mix run on the bytecode: the fixture's `BatchSubmitted` withdrawal
    /// queue hash.
    #[test]
    fn withdrawal_link_matches_bytecode() {
        let withdrawal = Withdrawal {
            token: address!("0x20c0000000000000000000000000000000000000"),
            senderTag: B256::ZERO,
            to: address!("0x14dc79964da2c08b23698b3d3cc7ca32193d9955"),
            amount: 1,
            memo: B256::ZERO,
            gasLimit: 0,
            fallbackNonce: 1,
            callbackData: Default::default(),
            encryptedSender: Default::default(),
            senderOrg: 0,
        };
        assert_eq!(
            withdrawal_link(&withdrawal, B256::ZERO),
            b256!("0xf0f0203b0ccd8694df0feba2132d25bde0c7c42dd4d5a323dbcfad93ca837d1e")
        );
    }
}
