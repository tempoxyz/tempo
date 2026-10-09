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

use alloy_evm::precompiles::DynPrecompile;
use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::{SolCall, SolValue, abi::AbiDecoderConfig};
use tempo_precompiles::{
    PATH_USD_ADDRESS,
    error::TempoPrecompileError,
    storage::{Handler, Mapping, Slot, StorageCtx},
    tip20::{ISSUER_ROLE, ITIP20, TIP20Error, TIP20Token},
    tip403_registry::TIP403Registry,
};
use tempo_precompiles_macros::contract;
use tempo_zone_contracts::{
    DecryptionData, Deposit, DepositType, EnabledToken, IZoneInbox, IZoneOutbox,
    LegacyTempoAdvanced, QueuedDeposit, TempoAdvanced, WithdrawalBounceBackDeposit, ZoneInboxError,
    ZoneInboxEvent,
};
use zone_primitives::constants::{ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS};

use crate::{
    ZonePrecompileError, ZoneResult, aes_gcm, chaum_pedersen,
    ecies::{ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE, hkdf_info, hkdf_sha256},
    execution::NoCallRules,
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

    /// Create the direct-call-only native Inbox precompile.
    pub fn create<P>(l1: L1State<P>, env: &crate::ZonePrecompileEnv) -> DynPrecompile
    where
        P: L1StorageReader,
    {
        crate::execution::create_precompile("ZoneInbox", env, NoCallRules, move |data, caller| {
            Self::new().call(&l1, data, caller)
        })
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
        let deposits = decode_deposits(call.deposits)?;

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
        let ensure_logic_err = |err: TempoPrecompileError| {
            if err.is_system_error() {
                Err(err)
            } else {
                Ok(false)
            }
        };

        // TODO: Resolve virtual addresses through `AddressRegistry`precompile once it activates.
        let can_receive = TIP403Registry::new()
            .validate_receive_policy(token, ZONE_INBOX_ADDRESS, to)
            .map(|reason| reason.is_none())
            .or_else(ensure_logic_err)?;

        if !can_receive {
            return Ok(false);
        }

        let checkpoint = self.storage.checkpoint();
        let success = TIP20Token::from_address(token)
            .and_then(|mut token| {
                token.mint(
                    ZONE_INBOX_ADDRESS,
                    ITIP20::mintCall {
                        to,
                        amount: U256::from(amount),
                    },
                )
            })
            .map(|_| true)
            .or_else(ensure_logic_err)?;

        if success {
            checkpoint.commit();
        }

        Ok(success)
    }

    fn claim_refund(&mut self, caller: Address, token: Address) -> ZoneResult<u128> {
        let amount = self.withdrawal_bounce_backs[token][caller].read()?;
        if !self.try_mint(token, caller, amount)? {
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
                tempo_zone_contracts::ZonePortal::Role::Sequencer,
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

/// A queue entry whose nested ABI payload has been validated before execution begins.
enum DecodedQueuedDeposit {
    WithdrawalBounceBack(WithdrawalBounceBackDeposit),
    Deposit(Deposit),
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
        };
        StorageCtx::default().keccak256(&encoded)
    }
}

fn decode_deposits(deposits: Vec<QueuedDeposit>) -> ZoneResult<Vec<DecodedQueuedDeposit>> {
    // Nested deposits must match their canonical L1 event encoding on every hardfork.
    let config = AbiDecoderConfig::new().strict(true);

    deposits
        .into_iter()
        .map(|queued| {
            match queued.depositType {
                DepositType::WithdrawalBounceBack => {
                    WithdrawalBounceBackDeposit::abi_decode_with_config(&queued.depositData, config)
                        .map(DecodedQueuedDeposit::WithdrawalBounceBack)
                }
                DepositType::Deposit => {
                    Deposit::abi_decode_with_config(&queued.depositData, config)
                        .map(DecodedQueuedDeposit::Deposit)
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
