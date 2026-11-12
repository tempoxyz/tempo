//! Native `ZoneInbox` precompile.
//!
//! The Inbox advances the Zone's finalized Tempo checkpoint and consumes the canonical L1 deposit
//! queue. The implementation shares one execution-local [`L1State`] with `TempoState` and the
//! Zone EVM database adapter: `finalizeTempo` selects the child anchor used by sequencer
//! admission and every subsequent deposit, policy, and portal read.
//!
//! Runtime execution processes a contiguous prefix of the portal deposit queue and reads its
//! canonical head at the selected child anchor. The batch proof, not this precompile, proves that
//! the post-state processed hash is an ancestor of that head by validating the unprocessed suffix.
//! Observing the head read in the execution witness is not sufficient without that explicit proof
//! constraint.

mod dispatch;

#[cfg(test)]
mod tests;

use alloc::vec::Vec;

use alloy_primitives::{Address, B256, FixedBytes, U256, keccak256};
use alloy_sol_types::{SolCall, SolValue, abi::AbiDecoderConfig};
use tempo_contracts::zones::{
    DecryptionData, Deposit, DepositType, EnabledToken, IZoneInbox, IZoneOutbox,
    LegacyTempoAdvanced, QueuedDeposit, TempoAdvanced, VirtualDeposit, VirtualDepositFailureReason,
    WithdrawalBounceBackDeposit, ZoneDepositAddress, ZoneInboxError, ZoneInboxEvent,
};
use tempo_precompiles::{
    PATH_USD_ADDRESS,
    error::TempoPrecompileError,
    storage::{Handler, Mapping, Slot, StorageCtx},
    tip20::{ISSUER_ROLE, ITIP20, TIP20Error, TIP20Token},
    tip403_registry::TIP403Registry,
};
use tempo_precompiles_macros::contract;
use zone_primitives::constants::{ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS};

use crate::{
    ZonePrecompileError, ZoneResult, address_registry, aes_gcm, chaum_pedersen,
    ecies::{ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE, hkdf_info, hkdf_sha256},
    ff1,
    outbox::ZoneOutbox,
    storage::{L1State, L1StorageReader},
    tempo_state::TempoState,
};

/// ABI selector for the block-opening `advanceTempo` system call.
pub const ADVANCE_TEMPO_SELECTOR: [u8; 4] = IZoneInbox::advanceTempoCall::SELECTOR;
/// ABI selector for the checkpoint-only `advanceTempoHeaders` system call.
pub const ADVANCE_TEMPO_HEADERS_SELECTOR: [u8; 4] = IZoneInbox::advanceTempoHeadersCall::SELECTOR;

/// Zone-side bridge Inbox state and deposit-processing logic.
#[contract(addr = ZONE_INBOX_ADDRESS)]
pub struct ZoneInbox {
    /// Hash-chain head after the last processed L1 deposit.
    processed_deposit_queue_hash: B256,
    /// Monotonic number of deposits consumed from the L1 queue.
    processed_deposit_number: u64,
    /// Withdrawal bounce-back mints that failed and can be claimed later.
    withdrawal_bounce_backs: Mapping<Address, Mapping<Address, u128>>,
    /// Append-only token-enablement commitment already applied by this zone.
    processed_token_enablement_hash: B256,
    /// Number of entries from the portal's append-only enabled-token array applied by this zone.
    processed_enabled_token_count: u64,
}

impl ZoneInbox {
    /// Initialize the precompile account marker without changing protocol storage.
    pub fn initialize(&mut self) -> tempo_precompiles::Result<()> {
        self.__initialize()
    }

    fn advance_tempo<P: L1StorageReader>(
        &mut self,
        l1: &L1State<P>,
        portal: Address,
        caller: Address,
        call: IZoneInbox::advanceTempoCall,
    ) -> ZoneResult<()> {
        if !caller.is_zero() {
            return Err(ZoneInboxError::only_sequencer().into());
        }

        let deposit_count = u64::try_from(call.deposits.len())
            .map_err(|_| TempoPrecompileError::under_overflow())?;
        let deposits = decode_deposits(call.deposits, StorageCtx.spec().is_t15())?;

        let mut tempo_state = TempoState::new();

        // Step 1: Advance Tempo state and select the child anchor used by all L1-backed reads.
        tempo_state.finalize_checkpoints(l1, &[call.header])?;
        let tempo_block_number = tempo_state.tempo_block_number()?;

        let has_token_enablements = !call.enabledTokens.is_empty();
        let enabled_token_count = call.enabledTokens.len();
        let previous_token_count = StorageCtx
            .spec()
            .is_t13()
            .then(|| self.processed_enabled_token_count.read())
            .transpose()?;
        let mut next_token_enablement_hash = self.processed_token_enablement_hash.read()?;
        for enabled in &call.enabledTokens {
            next_token_enablement_hash = enabled.hash_with_previous(next_token_enablement_hash);
        }

        let portal_enabled_token_count = if !portal.is_zero() {
            if l1.read_portal(|portal| &portal.token_enablement_hash)? != next_token_enablement_hash
            {
                return Err(ZoneInboxError::invalid_token_enablement_hash().into());
            }
            // T13 adds the count cursor after zones may already have applied a historical token
            // prefix. Bootstrap that prefix once; afterward the hash check authenticates the
            // supplied suffix, so the stored count can advance locally.
            if previous_token_count == Some(0) {
                Some(l1.read_portal_vec_len(|portal| &portal.enabled_tokens)?)
            } else {
                None
            }
        } else {
            None
        };

        self.enable_tokens(call.enabledTokens)?;
        if has_token_enablements {
            self.processed_token_enablement_hash
                .write(next_token_enablement_hash)?;
        }
        let processed_enabled_token_count = if let Some(previous_token_count) = previous_token_count
        {
            let next_token_count = if let Some(portal_count) = portal_enabled_token_count {
                u64::try_from(portal_count).map_err(|_| TempoPrecompileError::under_overflow())?
            } else {
                previous_token_count
                    .checked_add(
                        u64::try_from(enabled_token_count)
                            .map_err(|_| TempoPrecompileError::under_overflow())?,
                    )
                    .ok_or_else(TempoPrecompileError::under_overflow)?
            };
            self.processed_enabled_token_count.write(next_token_count)?;
            next_token_count
        } else {
            0
        };

        // Step 2: Process deposits and build hash chain
        let tempo_block_hash = tempo_state.tempo_block_hash()?;
        let mut current_hash = self.processed_deposit_queue_hash.read()?;
        let mut decryptions = call.decryptions.into_iter();
        let mut outbox = ZoneOutbox::new();
        let zone_id = address_registry::zone_id(portal);

        for queued in deposits {
            current_hash = queued.hash_with_tail(current_hash)?;

            match queued {
                DecodedQueuedDeposit::WithdrawalBounceBack(deposit) => {
                    self.process_withdrawal_bounce_back(&mut outbox, deposit)
                }
                DecodedQueuedDeposit::Deposit(deposit) => {
                    let Some(decryption) = decryptions.next() else {
                        return Err(ZoneInboxError::missing_decryption_data().into());
                    };
                    let key = read_encryption_key(l1, deposit.keyIndex)?;
                    self.process_deposit(
                        &mut outbox,
                        portal,
                        current_hash,
                        deposit,
                        decryption,
                        key,
                    )
                }
                DecodedQueuedDeposit::ZoneVirtual {
                    deposit,
                    rejected: true,
                } => self.fail_virtual_deposit(
                    &mut outbox,
                    current_hash,
                    deposit,
                    Address::ZERO,
                    VirtualDepositFailureReason::Rejected,
                ),
                DecodedQueuedDeposit::ZoneVirtual {
                    deposit,
                    rejected: false,
                } => self.process_virtual_deposit(&mut outbox, zone_id, current_hash, deposit),
            }?;
        }

        if decryptions.next().is_some() {
            return Err(ZoneInboxError::extra_decryption_data().into());
        }

        // Step 3: Bind the canonical Tempo queue head into the execution witness.
        //
        // `current_hash` may be an ancestor of this value when the sequencer processes only a
        // bounded prefix of pending deposits. The batch proof validates that hashing the
        // unprocessed suffix from `current_hash` reaches `tempo_current_hash`; requiring equality
        // here would incorrectly forbid partial processing.
        //
        // NOTE: A zero portal denotes the explicit no-L1 mode used by local development and offline
        // execution. There is no canonical queue to bind in that mode.
        if !portal.is_zero() {
            let tempo_current_hash = l1.read_portal(|portal| &portal.current_deposit_queue_hash)?;
            if tempo_current_hash != current_hash {
                return Err(ZoneInboxError::invalid_deposit_queue_hash().into());
            }
        }

        // Step 4: Update state
        self.processed_deposit_queue_hash.write(current_hash)?;
        let previous_number = self.processed_deposit_number.read()?;
        let processed_number = previous_number
            .checked_add(deposit_count)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.processed_deposit_number.write(processed_number)?;

        if StorageCtx.spec().is_t13() {
            self.emit_event(TempoAdvanced {
                tempoBlockHash: tempo_block_hash,
                tempoBlockNumber: tempo_block_number,
                depositsProcessed: U256::from(deposit_count),
                newProcessedDepositQueueHash: current_hash,
                lastProcessedDepositNumber: processed_number,
                lastProcessedEnabledTokenCount: processed_enabled_token_count,
            })?;
        } else {
            self.emit_event(LegacyTempoAdvanced {
                tempoBlockHash: tempo_block_hash,
                tempoBlockNumber: tempo_block_number,
                depositsProcessed: U256::from(deposit_count),
                newProcessedDepositQueueHash: current_hash,
                lastProcessedDepositNumber: processed_number,
            })?;
        }

        Ok(())
    }

    /// Authenticate a bounded consecutive header range without observing Tempo state or applying
    /// any portal work. Transaction ordering makes this the only transaction in its Zone block.
    fn advance_tempo_headers<P: L1StorageReader>(
        &mut self,
        l1: &L1State<P>,
        caller: Address,
        call: IZoneInbox::advanceTempoHeadersCall,
    ) -> ZoneResult<()> {
        if !caller.is_zero() {
            return Err(ZoneInboxError::only_sequencer().into());
        }
        let mut tempo_state = TempoState::new();
        tempo_state.finalize_checkpoints(l1, &call.headers)
    }

    fn enable_tokens(&mut self, tokens: Vec<EnabledToken>) -> ZoneResult<()> {
        for enabled in tokens {
            // Since TIP-20 initialization writes the default policy ID into the L1-mirrored
            // TIP-403 registry, we cache the L1 value beforehand.
            let mut policy_registry = TIP403Registry::new();
            let l1_policy = policy_registry.token_transfer_policies[enabled.token].read()?;

            let mut token = TIP20Token::from_address(enabled.token)?;
            token.initialize(
                ZONE_INBOX_ADDRESS,
                &enabled.name,
                &enabled.symbol,
                &enabled.currency,
                PATH_USD_ADDRESS,
                ZONE_INBOX_ADDRESS,
            )?;
            token.grant_role_internal(ZONE_INBOX_ADDRESS, ISSUER_ROLE)?;
            token.grant_role_internal(ZONE_OUTBOX_ADDRESS, ISSUER_ROLE)?;
            policy_registry.token_transfer_policies[enabled.token].write(l1_policy)?;

            self.emit_event(enabled.enabled_event())?;
        }
        Ok(())
    }

    fn process_deposit(
        &mut self,
        outbox: &mut ZoneOutbox,
        portal: Address,
        current_hash: B256,
        deposit: Deposit,
        decryption: DecryptionData,
        key: (B256, u8),
    ) -> ZoneResult<()> {
        let Some((to, memo)) = recover_encrypted_payload(portal, &deposit, &decryption, key)?
        else {
            return self.fail_deposit(outbox, current_hash, deposit);
        };

        if self.try_mint(deposit.token, to, deposit.amount)? {
            self.emit_event(deposit.processed_event(current_hash, to, memo))?;
        } else {
            self.fail_deposit(outbox, current_hash, deposit)?;
        }
        Ok(())
    }

    fn fail_deposit(
        &mut self,
        outbox: &mut ZoneOutbox,
        current_hash: B256,
        deposit: Deposit,
    ) -> ZoneResult<()> {
        outbox.enqueue_deposit_bounce_back(
            ZONE_INBOX_ADDRESS,
            IZoneOutbox::enqueueDepositBounceBackCall {
                token: deposit.token,
                amount: deposit.amount,
                tempoRefundRecipient: deposit.tempoRefundRecipient,
            },
        )?;
        self.emit_event(deposit.failed_event(current_hash))?;
        Ok(())
    }

    /// TIP-1094: decrypt the deposit address, look up its master ID and mint to the registered
    /// recipient, or refund `originator` on Tempo. No sequencer input reaches this path.
    fn process_virtual_deposit(
        &mut self,
        outbox: &mut ZoneOutbox,
        zone_id: u32,
        current_hash: B256,
        deposit: VirtualDeposit,
    ) -> ZoneResult<()> {
        let resolved = match self.resolve_virtual_deposit(zone_id, deposit.destination)? {
            Ok(resolved) => resolved,
            Err((reason, to)) => {
                return self.fail_virtual_deposit(outbox, current_hash, deposit, to, reason);
            }
        };

        let memo = deposit.hasMemo.then_some(deposit.memo);
        if !self.try_mint_with_memo(deposit.token, resolved.recipient, deposit.amount, memo)? {
            return self.fail_virtual_deposit(
                outbox,
                current_hash,
                deposit,
                resolved.recipient,
                VirtualDepositFailureReason::MintFailed,
            );
        }

        self.emit_event(ZoneInboxEvent::virtual_deposit_processed(
            current_hash,
            deposit.originator,
            resolved.recipient,
            deposit.token,
            deposit.amount,
            resolved.version,
            resolved.master_id,
            resolved.user_tag,
            deposit.memo,
        ))?;
        Ok(())
    }

    /// Resolves a deposit address to its registered recipient. A recipient failure returns the
    /// committed failure reason with the recipient if one was found; system failures (gas,
    /// missing witnesses) propagate as errors and never become a refund.
    fn resolve_virtual_deposit(
        &mut self,
        zone_id: u32,
        destination: Address,
    ) -> ZoneResult<Result<ResolvedVirtualDeposit, (VirtualDepositFailureReason, Address)>> {
        let Some(address) = ZoneDepositAddress::decode(&destination)
            .filter(|address| address.version != 0 && address.zone_id == zone_id)
        else {
            return Ok(Err((
                VirtualDepositFailureReason::InvalidAddress,
                Address::ZERO,
            )));
        };
        let Some(key) = self.virtual_address_key(address.version)? else {
            return Ok(Err((
                VirtualDepositFailureReason::KeyUnconfigured,
                Address::ZERO,
            )));
        };

        ff1::charge_gas()?;
        let plaintext = ff1::decrypt(&key.0, address.version, zone_id, address.ciphertext.0);
        let master_id = FixedBytes::<4>::from_slice(&plaintext[..4]);
        let user_tag = FixedBytes::<2>::from_slice(&plaintext[4..]);

        let recipient = address_registry::recipient_of(master_id)?;
        if recipient.is_zero() {
            return Ok(Err((
                VirtualDepositFailureReason::UnregisteredMaster,
                Address::ZERO,
            )));
        }
        if !address_registry::is_valid_recipient(&recipient) {
            return Ok(Err((
                VirtualDepositFailureReason::InvalidMaster,
                Address::ZERO,
            )));
        }
        Ok(Ok(ResolvedVirtualDeposit {
            recipient,
            version: address.version,
            master_id,
            user_tag,
        }))
    }

    fn fail_virtual_deposit(
        &mut self,
        outbox: &mut ZoneOutbox,
        current_hash: B256,
        deposit: VirtualDeposit,
        to: Address,
        reason: VirtualDepositFailureReason,
    ) -> ZoneResult<()> {
        outbox.enqueue_deposit_bounce_back(
            ZONE_INBOX_ADDRESS,
            IZoneOutbox::enqueueDepositBounceBackCall {
                token: deposit.token,
                amount: deposit.amount,
                tempoRefundRecipient: deposit.originator,
            },
        )?;
        self.emit_event(ZoneInboxEvent::virtual_deposit_failed(
            current_hash,
            deposit.originator,
            to,
            deposit.token,
            deposit.amount,
            reason,
        ))?;
        Ok(())
    }

    /// TIP-1094 key initialization: versions start at 1, run in order and are set exactly once.
    ///
    /// TODO(tip-1094): the block validator and prover must also bind this call to the block
    /// witness, allow at most one per block, and require it right after `advanceTempo`.
    fn initialize_virtual_address_key(
        &mut self,
        caller: Address,
        version: u8,
        key: B256,
    ) -> ZoneResult<()> {
        if !caller.is_zero() {
            return Err(ZoneInboxError::only_sequencer().into());
        }
        let in_order = match version {
            0 => false,
            1 => true,
            _ => self.virtual_address_key(version - 1)?.is_some(),
        };
        if !in_order || self.virtual_address_key(version)?.is_some() {
            return Err(ZoneInboxError::invalid_address_key_version(version).into());
        }
        let (flag_slot, key_slot) = address_key_slots(version)?;
        Slot::<U256>::new(flag_slot, self.address).write(U256::ONE)?;
        Slot::<B256>::new(key_slot, self.address).write(key)?;
        self.emit_event(ZoneInboxEvent::virtual_address_key_initialized(version))?;
        Ok(())
    }

    /// The committed key for `version`, or `None` when that version is not initialized.
    fn virtual_address_key(&self, version: u8) -> tempo_precompiles::Result<Option<B256>> {
        let (flag_slot, key_slot) = address_key_slots(version)?;
        if Slot::<U256>::new(flag_slot, self.address).read()?.is_zero() {
            return Ok(None);
        }
        Slot::<B256>::new(key_slot, self.address).read().map(Some)
    }

    fn process_withdrawal_bounce_back(
        &mut self,
        outbox: &mut ZoneOutbox,
        deposit: WithdrawalBounceBackDeposit,
    ) -> ZoneResult<()> {
        let fallback_nonce = u64::from_be_bytes(
            deposit.to.as_slice()[12..]
                .try_into()
                .expect("address suffix is eight bytes"),
        );
        let recipient = outbox.consume_fallback_recipient(ZONE_INBOX_ADDRESS, fallback_nonce)?;
        if self.try_mint(deposit.token, recipient, deposit.amount)? {
            self.emit_event(deposit.withdrawal_bounce_back_processed_event(recipient))?;
        } else {
            let slot = self.withdrawal_bounce_backs[deposit.token][recipient].slot();
            Slot::<U256>::new(slot, self.address).sinc(U256::from(deposit.amount))?;
            self.emit_event(deposit.withdrawal_bounce_back_pending_event(recipient))?;
        }
        Ok(())
    }

    /// Mint with Solidity `try/catch` semantics: ordinary reverts are caught while fatal and
    /// out-of-gas failures abort the outer Inbox call.
    fn try_mint(&mut self, token: Address, to: Address, amount: u128) -> ZoneResult<bool> {
        self.try_mint_with_memo(token, to, amount, None)
    }

    /// [`Self::try_mint`], minting with `mintWithMemo` when a memo is given.
    fn try_mint_with_memo(
        &mut self,
        token: Address,
        to: Address,
        amount: u128,
        memo: Option<B256>,
    ) -> ZoneResult<bool> {
        match self.mint(token, to, amount, memo) {
            Ok(()) => Ok(true),
            Err(err) if err.is_system_error() => Err(err.into()),
            Err(_) => Ok(false),
        }
    }

    /// Mints bridged `amount` of `token` to `to`, with `mintWithMemo` when `memo` is given,
    /// discarding any changes on failure.
    ///
    /// Reverts with `PolicyForbids` when `to`'s receive policy blocks the Inbox, and otherwise
    /// with the token's own mint error.
    /// +T13: Bridged assets use TIP-403 `Recipient` authorization rather than `MintRecipient`.
    fn mint(
        &mut self,
        token: Address,
        to: Address,
        amount: u128,
        memo: Option<B256>,
    ) -> Result<(), TempoPrecompileError> {
        // TODO: Resolve virtual addresses through `AddressRegistry`precompile once it activates.
        if TIP403Registry::new()
            .validate_receive_policy(token, ZONE_INBOX_ADDRESS, to)?
            .is_some()
        {
            return Err(TIP20Error::policy_forbids().into());
        }

        let checkpoint = self.storage.checkpoint();
        let mut token = TIP20Token::from_address(token)?;
        let amount = U256::from(amount);
        match memo {
            None => token.mint(ZONE_INBOX_ADDRESS, ITIP20::mintCall { to, amount })?,
            Some(memo) => token.mint_with_memo(
                ZONE_INBOX_ADDRESS,
                ITIP20::mintWithMemoCall { to, amount, memo },
            )?,
        }
        checkpoint.commit();
        Ok(())
    }

    fn claim_refund(&mut self, caller: Address, token: Address) -> ZoneResult<u128> {
        let amount = self.withdrawal_bounce_backs[token][caller].read()?;
        if self.storage.spec().is_t13() && amount == 0 {
            return Err(ZoneInboxError::no_refund().into());
        }
        // +T15: Revert with the mint's own error, such as `ContractPaused` for a token paused on
        // Tempo.
        if self.storage.spec().is_t15() {
            self.mint(token, caller, amount, None)?;
        } else if !self.try_mint(token, caller, amount)? {
            return Err(TempoPrecompileError::from(TIP20Error::policy_forbids()).into());
        }

        self.withdrawal_bounce_backs[token][caller].delete()?;
        self.emit_event(ZoneInboxEvent::refund_claimed(caller, token, amount))?;
        Ok(amount)
    }

    fn view_refund<P: L1StorageReader>(
        &self,
        l1: &L1State<P>,
        msg_sender: Address,
        token: Address,
        owner: Address,
    ) -> ZoneResult<u128> {
        if msg_sender != owner
            && !l1.has_portal_role(
                msg_sender,
                tempo_contracts::zones::ZonePortal::Role::Sequencer,
            )?
        {
            return Err(ZonePrecompileError::Inbox(ZoneInboxError::Unauthorized(
                IZoneInbox::Unauthorized {},
            )));
        }
        Ok(self.withdrawal_bounce_backs[token][owner].read()?)
    }

    /// Returns the hash-chain head after the last processed L1 deposit.
    pub fn processed_deposit_queue_hash(&self) -> tempo_precompiles::Result<B256> {
        self.processed_deposit_queue_hash.read()
    }

    /// Returns the number of L1 deposits consumed by the Zone.
    pub fn processed_deposit_number(&self) -> tempo_precompiles::Result<u64> {
        self.processed_deposit_number.read()
    }
}

/// A virtual deposit whose address resolved to a registered recipient.
struct ResolvedVirtualDeposit {
    recipient: Address,
    version: u8,
    master_id: FixedBytes<4>,
    user_tag: FixedBytes<2>,
}

/// TIP-1094 key slots for `version`: the initialized flag at
/// `keccak256(abi.encode(uint256(v), uint256(S)))` and the key in the next slot.
fn address_key_slots(version: u8) -> tempo_precompiles::Result<(U256, U256)> {
    let mut data = [0u8; 64];
    data[31] = version;
    data[32..].copy_from_slice(keccak256(b"tempo.zvda.addressKeys").as_slice());
    let flag: U256 = StorageCtx::default().keccak256(&data)?.into();
    Ok((flag, flag.wrapping_add(U256::ONE)))
}

/// TIP-1094 key slots (initialized flag, key) for `version` in `ZONE_INBOX_ADDRESS` storage,
/// computed without a storage context for node-side reads. Must equal `address_key_slots`.
pub fn virtual_address_key_slots(version: u8) -> (U256, U256) {
    let mut data = [0u8; 64];
    data[31] = version;
    data[32..].copy_from_slice(keccak256(b"tempo.zvda.addressKeys").as_slice());
    let flag: U256 = keccak256(data).into();
    (flag, flag.wrapping_add(U256::ONE))
}

/// Resolves a virtual deposit's destination to the recipient `advanceTempo` would credit, reading
/// committed zone storage through `read(address, slot)` at the parent of the block that will
/// process it.
///
/// Returns `None` when the inbox refunds the deposit on its own (invalid or foreign address,
/// uninitialized key version, unregistered or invalid master). Sequencers use this to apply their
/// deposit allowlist and set `QueuedDeposit.rejected`; it mirrors `resolve_virtual_deposit`.
pub fn virtual_deposit_recipient<E>(
    portal: Address,
    destination: Address,
    mut read: impl FnMut(Address, U256) -> Result<U256, E>,
) -> Result<Option<Address>, E> {
    let zone_id = address_registry::zone_id(portal);
    let Some(address) = ZoneDepositAddress::decode(&destination)
        .filter(|address| address.version != 0 && address.zone_id == zone_id)
    else {
        return Ok(None);
    };
    let (flag_slot, key_slot) = virtual_address_key_slots(address.version);
    if read(ZONE_INBOX_ADDRESS, flag_slot)?.is_zero() {
        return Ok(None);
    }
    let key = B256::from(read(ZONE_INBOX_ADDRESS, key_slot)?);
    let plaintext = ff1::decrypt(&key.0, address.version, zone_id, address.ciphertext.0);
    let master_id = FixedBytes::<4>::from_slice(&plaintext[..4]);
    let recipient = Address::from_word(B256::from(read(
        tempo_contracts::zones::ZONE_ADDRESS_REGISTRY_ADDRESS,
        address_registry::recipient_storage_slot(master_id),
    )?));
    Ok(
        (!recipient.is_zero() && address_registry::is_valid_recipient(&recipient))
            .then_some(recipient),
    )
}

/// A queue entry whose nested ABI payload has been validated before execution begins.
enum DecodedQueuedDeposit {
    WithdrawalBounceBack(WithdrawalBounceBackDeposit),
    Deposit(Deposit),
    /// `rejected` is the sequencer's verdict: a rejected virtual deposit is refunded without being
    /// resolved. The flag is read only for virtual deposits; encrypted deposits are rejected by
    /// withholding decryption data, and bounce-backs cannot be rejected.
    ZoneVirtual {
        deposit: VirtualDeposit,
        rejected: bool,
    },
}

impl DecodedQueuedDeposit {
    fn hash_with_tail(&self, tail: B256) -> tempo_precompiles::Result<B256> {
        let encoded = match self {
            Self::WithdrawalBounceBack(deposit) => {
                (DepositType::WithdrawalBounceBack, deposit.clone(), tail).abi_encode_params()
            }
            Self::Deposit(deposit) => {
                (DepositType::Deposit, deposit.clone(), tail).abi_encode_params()
            }
            Self::ZoneVirtual { deposit, .. } => {
                (DepositType::ZoneVirtual, deposit.clone(), tail).abi_encode_params()
            }
        };
        StorageCtx::default().keccak256(&encoded)
    }
}

fn decode_deposits(
    deposits: Vec<QueuedDeposit>,
    virtual_deposits: bool,
) -> ZoneResult<Vec<DecodedQueuedDeposit>> {
    // Nested deposits must match their canonical L1 event encoding on every hardfork.
    let config = AbiDecoderConfig::new().strict(true);

    deposits
        .into_iter()
        .map(|queued| {
            let rejected = queued.rejected;
            match queued.depositType {
                DepositType::WithdrawalBounceBack => {
                    WithdrawalBounceBackDeposit::abi_decode_with_config(&queued.depositData, config)
                        .map(DecodedQueuedDeposit::WithdrawalBounceBack)
                }
                DepositType::Deposit => {
                    Deposit::abi_decode_with_config(&queued.depositData, config)
                        .map(DecodedQueuedDeposit::Deposit)
                }
                DepositType::ZoneVirtual if virtual_deposits => {
                    VirtualDeposit::abi_decode_with_config(&queued.depositData, config)
                        .map(|deposit| DecodedQueuedDeposit::ZoneVirtual { deposit, rejected })
                }
                _ => return Err(ZonePrecompileError::MalformedCalldata),
            }
            .map_err(|_| ZonePrecompileError::MalformedCalldata)
        })
        .collect()
}

fn recover_encrypted_payload(
    portal: Address,
    deposit: &Deposit,
    decryption: &DecryptionData,
    (key_x, key_y_parity): (B256, u8),
) -> ZoneResult<Option<(Address, B256)>> {
    chaum_pedersen::charge_gas()?;
    if !chaum_pedersen::verify(
        &deposit.encrypted.ephemeralPubkeyX.0,
        deposit.encrypted.ephemeralPubkeyYParity,
        &decryption.sharedSecret.0,
        decryption.sharedSecretYParity,
        &key_x.0,
        key_y_parity,
        &decryption.cpProof,
    ) {
        return Ok(None);
    }

    let info = hkdf_info(
        &portal,
        &deposit.keyIndex,
        &deposit.encrypted.ephemeralPubkeyX,
        &deposit.sender,
    );
    let key = hkdf_sha256(&decryption.sharedSecret.0, b"ecies-aes-key", &info);
    aes_gcm::charge_gas(deposit.encrypted.ciphertext.len(), 0)?;
    let (plaintext, valid) = aes_gcm::decrypt(
        &key,
        &deposit.encrypted.nonce.0,
        &deposit.encrypted.ciphertext,
        &[],
        &deposit.encrypted.tag.0,
    );
    if !valid || plaintext.len() != ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE {
        return Ok(None);
    }

    Ok(Some((
        Address::from_slice(&plaintext[..20]),
        B256::from_slice(&plaintext[20..52]),
    )))
}

fn read_encryption_key<P: L1StorageReader>(
    l1: &L1State<P>,
    key_index: U256,
) -> ZoneResult<(B256, u8)> {
    let index = usize::try_from(key_index).map_err(|_| TempoPrecompileError::under_overflow())?;
    let x = l1.read_portal(|portal| &portal.encryption_keys[index].x)?;
    if x.is_zero() {
        return Err(ZoneInboxError::invalid_shared_secret_proof().into());
    }
    let y_parity = l1.read_portal(|portal| &portal.encryption_keys[index].y_parity)?;
    Ok((x, y_parity))
}
