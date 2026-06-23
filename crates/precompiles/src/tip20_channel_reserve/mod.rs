//! TIP-1034 TIP-20 channel reserve precompile.
//!
//! Channels lock TIP-20 deposits from a payer and let the payee claim signed
//! cumulative vouchers. A channel is identified by its descriptor, the current
//! chain, this precompile address, and a transaction-derived nonce hash that
//! prevents accidental replay of `open` calls across transactions.

pub mod dispatch;

use crate::{
    error::{Result, TempoPrecompileError},
    signature_verifier::SignatureVerifier,
    storage::{Handler, Mapping},
    storage_credits::StorageCredits,
    tip20::{ITIP20, Recipient, TIP20Token, is_tip20_prefix},
    tip403_registry::AuthRole,
};
use alloy::{
    primitives::{Address, B256, U256, aliases::U96, keccak256},
    sol_types::SolValue,
};
use std::sync::LazyLock;
use tempo_chainspec::constants::{mainnet::MAINNET_CHAIN_ID, moderato::MODERATO_CHAIN_ID};
pub use tempo_contracts::precompiles::{
    ITIP20ChannelReserve, TIP20_CHANNEL_RESERVE_ADDRESS, TIP20ChannelReserveError,
    TIP20ChannelReserveEvent,
};
use tempo_precompiles_macros::{Storable, contract};
use tempo_primitives::TempoAddressExt;

/// 15 minute grace period between `requestClose` and `withdraw`.
pub const CLOSE_GRACE_PERIOD: u64 = 15 * 60;

/// EIP-712 type hash for signed cumulative payment vouchers.
static VOUCHER_TYPEHASH: LazyLock<B256> =
    LazyLock::new(|| keccak256(b"Voucher(bytes32 channelId,uint96 cumulativeAmount)"));
/// EIP-712 domain type hash used by [`TIP20ChannelReserve::domain_separator`].
static EIP712_DOMAIN_TYPEHASH: LazyLock<B256> = LazyLock::new(|| {
    keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
});
/// EIP-712 domain name hash for the reserve voucher domain.
static NAME_HASH: LazyLock<B256> = LazyLock::new(|| keccak256(b"TIP20 Channel Reserve"));
/// EIP-712 domain version hash for the reserve voucher domain.
static VERSION_HASH: LazyLock<B256> = LazyLock::new(|| keccak256(b"1"));

/// EIP-712 domain separator for the reserve voucher domain on mainnet.
static DOMAIN_SEPARATOR_MAINNET: LazyLock<B256> =
    LazyLock::new(|| domain_separator_inner(MAINNET_CHAIN_ID));
/// EIP-712 domain separator for the reserve voucher domain on testnet.
static DOMAIN_SEPARATOR_TESTNET: LazyLock<B256> =
    LazyLock::new(|| domain_separator_inner(MODERATO_CHAIN_ID));

/// Packed persistent state for one channel.
///
/// `deposit` being non-zero is the existence marker. `settled` is the cumulative amount
/// already transferred to the payee. `close_requested_at` is zero until the payer starts
/// the unilateral close timer.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct PackedChannelState {
    settled: U96,
    deposit: U96,
    close_requested_at: u32,
}

impl PackedChannelState {
    /// Returns whether this storage slot contains an active channel.
    fn exists(self) -> bool {
        !self.deposit.is_zero()
    }

    /// Returns the payer's close request timestamp, if the close timer is active.
    fn close_requested_at(self) -> Option<u32> {
        (self.close_requested_at != 0).then_some(self.close_requested_at)
    }

    /// Converts packed native storage to the public Solidity ABI shape.
    fn to_sol(self) -> ITIP20ChannelReserve::ChannelState {
        ITIP20ChannelReserve::ChannelState {
            settled: self.settled,
            deposit: self.deposit,
            closeRequestedAt: self.close_requested_at,
        }
    }
}

#[contract(addr = TIP20_CHANNEL_RESERVE_ADDRESS)]
pub struct TIP20ChannelReserve {
    /// Persistent channel state keyed by `compute_channel_id_inner`.
    channel_states: Mapping<B256, PackedChannelState>,
    /// Per-payer reusable credits for deleted packed channel-state slots.
    channel_storage_credits: Mapping<Address, u64>,

    // WARNING: transient storage slots must remain after persistent storage fields until the
    // `contract` macro supports independent persistent/transient layouts.
    /// Transient same-transaction guard that prevents close-and-reopen with the same id.
    opened_this_tx: Mapping<B256, bool>,
    /// Transient per-transaction entropy seeded by the EVM handler before calls can open channels.
    channel_open_context_hash: B256,
}

impl TIP20ChannelReserve {
    /// Initializes the precompile storage layout.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Seeds the enclosing transaction's replay-protected context hash for `open` calls.
    ///
    /// The handler seeds `keccak256(encode_for_signing || sender)` for every real transaction
    /// type. The value is stored in transient storage so batched `open` calls share the same
    /// transaction-derived hash and the context is automatically cleared before the next
    /// transaction. If this is not called, `open` reads zero from transient storage and reverts.
    pub fn set_channel_open_context_hash(&mut self, hash: B256) -> Result<()> {
        self.channel_open_context_hash.t_write(hash)
    }

    /// Returns the number of reusable channel storage credits owned by `payer`.
    pub fn storage_credits(&self, payer: Address) -> Result<u64> {
        self.channel_storage_credits[payer].read()
    }

    /// Opens a channel and pulls the initial deposit from the payer into reserve.
    ///
    /// Payees and integrators must independently decide whether any nonzero operator is acceptable
    /// before relying on the channel.
    ///
    /// Payees cannot be zero or TIP-20 addresses. Virtual payees require a non-virtual operator.
    /// This prevents channels whose payee cannot receive direct payouts or submit vouchers itself.
    pub fn open(
        &mut self,
        msg_sender: Address,
        call: ITIP20ChannelReserve::openCall,
    ) -> Result<B256> {
        if call.payee.is_zero()
            || is_tip20_prefix(call.payee)
            || (call.payee.is_virtual() && (call.operator.is_zero() || call.operator.is_virtual()))
        {
            return Err(TIP20ChannelReserveError::invalid_payee().into());
        }

        let mut token = TIP20Token::from_address(call.token)?;

        let deposit = call.deposit;
        if deposit.is_zero() {
            return Err(TIP20ChannelReserveError::zero_deposit().into());
        }

        let expiring_nonce_hash = self.enclosing_channel_open_context_hash()?;
        let channel_id = self.compute_channel_id_inner(
            msg_sender,
            call.payee,
            call.operator,
            call.token,
            call.salt,
            call.authorizedSigner,
            expiring_nonce_hash,
        )?;
        if self.channel_states[channel_id].read()?.exists()
            || self.opened_this_tx[channel_id].t_read()?
        {
            return Err(TIP20ChannelReserveError::channel_already_exists().into());
        }

        token.ensure_authorized_as(Recipient::resolve(call.payee)?.target, AuthRole::Recipient)?;
        token.system_transfer_from(self.address, msg_sender, U256::from(call.deposit))?;

        self.write_channel_state_spending_credit(
            msg_sender,
            channel_id,
            PackedChannelState {
                settled: U96::ZERO,
                deposit,
                close_requested_at: 0,
            },
        )?;
        self.opened_this_tx[channel_id].t_write(true)?;

        self.emit_event(TIP20ChannelReserveEvent::ChannelOpened(
            ITIP20ChannelReserve::ChannelOpened {
                channelId: channel_id,
                payer: msg_sender,
                payee: call.payee,
                operator: call.operator,
                token: call.token,
                authorizedSigner: call.authorizedSigner,
                salt: call.salt,
                expiringNonceHash: expiring_nonce_hash,
                deposit: call.deposit,
            },
        ))?;

        Ok(channel_id)
    }

    /// Settles an increasing cumulative voucher, paying only the unsettled delta to the payee.
    ///
    /// The payee can call directly. If an operator was set when the channel was opened, that
    /// operator can submit the payee's voucher and route the payment to the descriptor payee.
    pub fn settle(
        &mut self,
        msg_sender: Address,
        call: ITIP20ChannelReserve::settleCall,
    ) -> Result<()> {
        let channel_id = self.channel_id(&call.descriptor)?;
        let mut state = self.load_existing_state(channel_id)?;

        Self::ensure_payee_or_operator(msg_sender, &call.descriptor)?;

        let cumulative = call.cumulativeAmount;
        if cumulative > state.deposit {
            return Err(TIP20ChannelReserveError::amount_exceeds_deposit().into());
        }
        if cumulative <= state.settled {
            return Err(TIP20ChannelReserveError::amount_not_increasing().into());
        }

        self.validate_voucher(
            &call.descriptor,
            channel_id,
            call.cumulativeAmount,
            &call.signature,
        )?;

        let delta = cumulative
            .checked_sub(state.settled)
            .expect("cumulative amount already checked to be increasing");

        let mut token = TIP20Token::from_address(call.descriptor.token)?;
        token.ensure_authorized_as(call.descriptor.payer, AuthRole::Sender)?;

        state.settled = cumulative;
        self.channel_states[channel_id].write(state)?;

        token.transfer(
            self.address,
            ITIP20::transferCall {
                to: call.descriptor.payee,
                amount: U256::from(delta),
            },
        )?;

        self.emit_event(TIP20ChannelReserveEvent::Settled(
            ITIP20ChannelReserve::Settled {
                channelId: channel_id,
                payer: call.descriptor.payer,
                payee: call.descriptor.payee,
                cumulativeAmount: call.cumulativeAmount,
                deltaPaid: delta,
                newSettled: cumulative,
            },
        ))?;

        Ok(())
    }

    /// Adds deposit to an existing channel and cancels a pending close request.
    ///
    /// A zero top-up is allowed and only cancels a pending close request.
    pub fn top_up(
        &mut self,
        msg_sender: Address,
        call: ITIP20ChannelReserve::topUpCall,
    ) -> Result<()> {
        let channel_id = self.channel_id(&call.descriptor)?;
        let mut state = self.load_existing_state(channel_id)?;

        if msg_sender != call.descriptor.payer {
            return Err(TIP20ChannelReserveError::not_payer().into());
        }

        let additional = call.additionalDeposit;
        let had_close_request = state.close_requested_at().is_some();

        if additional.is_zero() && !had_close_request {
            return Ok(());
        }

        if !additional.is_zero() {
            let next_deposit = state
                .deposit
                .checked_add(additional)
                .ok_or_else(TIP20ChannelReserveError::deposit_overflow)?;

            state.deposit = next_deposit;
            let mut token = TIP20Token::from_address(call.descriptor.token)?;
            token.ensure_authorized_as(
                Recipient::resolve(call.descriptor.payee)?.target,
                AuthRole::Recipient,
            )?;
            token.system_transfer_from(
                self.address,
                msg_sender,
                U256::from(call.additionalDeposit),
            )?;
        }
        if had_close_request {
            state.close_requested_at = 0;
        }

        self.channel_states[channel_id].write(state)?;
        if had_close_request {
            self.emit_event(TIP20ChannelReserveEvent::CloseRequestCancelled(
                ITIP20ChannelReserve::CloseRequestCancelled {
                    channelId: channel_id,
                    payer: call.descriptor.payer,
                    payee: call.descriptor.payee,
                },
            ))?;
        }
        self.emit_event(TIP20ChannelReserveEvent::TopUp(
            ITIP20ChannelReserve::TopUp {
                channelId: channel_id,
                payer: call.descriptor.payer,
                payee: call.descriptor.payee,
                additionalDeposit: call.additionalDeposit,
                newDeposit: state.deposit,
            },
        ))?;

        Ok(())
    }

    /// Starts the payer's unilateral close timer.
    ///
    /// Repeated calls are idempotent while the timer is active.
    pub fn request_close(
        &mut self,
        msg_sender: Address,
        call: ITIP20ChannelReserve::requestCloseCall,
    ) -> Result<()> {
        let channel_id = self.channel_id(&call.descriptor)?;
        let mut state = self.load_existing_state(channel_id)?;

        if msg_sender != call.descriptor.payer {
            return Err(TIP20ChannelReserveError::not_payer().into());
        }
        if state.close_requested_at().is_some() {
            return Ok(());
        }

        let close_requested_at = self.now_u32();
        state.close_requested_at = close_requested_at;
        self.channel_states[channel_id].write(state)?;
        self.emit_event(TIP20ChannelReserveEvent::CloseRequested(
            ITIP20ChannelReserve::CloseRequested {
                channelId: channel_id,
                payer: call.descriptor.payer,
                payee: call.descriptor.payee,
                closeGraceEnd: U256::from(self.now() + CLOSE_GRACE_PERIOD),
            },
        ))?;

        Ok(())
    }

    /// Closes a channel from the payee side and refunds any uncaptured deposit to the payer.
    ///
    /// The payee can call directly. If an operator was set when the channel was opened, that
    /// operator can close the channel and route any capture to the descriptor payee.
    ///
    /// `captureAmount` can be below `cumulativeAmount` but cannot be below what has already
    /// settled. A new voucher is only required when the close captures more than `settled`.
    pub fn close(
        &mut self,
        msg_sender: Address,
        call: ITIP20ChannelReserve::closeCall,
    ) -> Result<()> {
        let channel_id = self.channel_id(&call.descriptor)?;
        let state = self.load_existing_state(channel_id)?;

        Self::ensure_payee_or_operator(msg_sender, &call.descriptor)?;

        let cumulative = call.cumulativeAmount;
        let capture = call.captureAmount;
        let previous_settled = state.settled;
        if capture < previous_settled || capture > cumulative {
            return Err(TIP20ChannelReserveError::capture_amount_invalid().into());
        }
        if capture > state.deposit {
            return Err(TIP20ChannelReserveError::amount_exceeds_deposit().into());
        }

        if capture > previous_settled {
            self.validate_voucher(
                &call.descriptor,
                channel_id,
                call.cumulativeAmount,
                &call.signature,
            )?;
        }

        let delta = capture
            .checked_sub(previous_settled)
            .expect("capture amount already checked against previous settled amount");
        let refund = state
            .deposit
            .checked_sub(capture)
            .expect("capture amount already checked against deposit");

        self.delete_channel_state_and_credit_payer(channel_id, call.descriptor.payer)?;

        let mut token = TIP20Token::from_address(call.descriptor.token)?;
        if !delta.is_zero() {
            token.ensure_authorized_as(call.descriptor.payer, AuthRole::Sender)?;
            token.transfer(
                self.address,
                ITIP20::transferCall {
                    to: call.descriptor.payee,
                    amount: U256::from(delta),
                },
            )?;
        }
        if !refund.is_zero() {
            token.transfer(
                self.address,
                ITIP20::transferCall {
                    to: call.descriptor.payer,
                    amount: U256::from(refund),
                },
            )?;
        }

        self.emit_event(TIP20ChannelReserveEvent::ChannelClosed(
            ITIP20ChannelReserve::ChannelClosed {
                channelId: channel_id,
                payer: call.descriptor.payer,
                payee: call.descriptor.payee,
                settledToPayee: capture,
                refundedToPayer: refund,
            },
        ))?;

        Ok(())
    }

    /// Withdraws the payer's remaining deposit after the close grace period has elapsed.
    pub fn withdraw(
        &mut self,
        msg_sender: Address,
        call: ITIP20ChannelReserve::withdrawCall,
    ) -> Result<()> {
        let channel_id = self.channel_id(&call.descriptor)?;
        let state = self.load_existing_state(channel_id)?;

        if msg_sender != call.descriptor.payer {
            return Err(TIP20ChannelReserveError::not_payer().into());
        }

        let close_ready = state
            .close_requested_at()
            .is_some_and(|requested_at| self.now() >= u64::from(requested_at) + CLOSE_GRACE_PERIOD);
        if !close_ready {
            return Err(TIP20ChannelReserveError::close_not_ready().into());
        }

        let refund = state
            .deposit
            .checked_sub(state.settled)
            .expect("settled is always <= deposit");

        self.delete_channel_state_and_credit_payer(channel_id, call.descriptor.payer)?;
        if !refund.is_zero() {
            TIP20Token::from_address(call.descriptor.token)?.transfer(
                self.address,
                ITIP20::transferCall {
                    to: call.descriptor.payer,
                    amount: U256::from(refund),
                },
            )?;
        }
        self.emit_event(TIP20ChannelReserveEvent::ChannelClosed(
            ITIP20ChannelReserve::ChannelClosed {
                channelId: channel_id,
                payer: call.descriptor.payer,
                payee: call.descriptor.payee,
                settledToPayee: state.settled,
                refundedToPayer: refund,
            },
        ))?;

        Ok(())
    }

    /// Returns a descriptor with its current on-chain state.
    pub fn get_channel(
        &self,
        call: ITIP20ChannelReserve::getChannelCall,
    ) -> Result<ITIP20ChannelReserve::Channel> {
        let channel_id = self.channel_id(&call.descriptor)?;
        Ok(ITIP20ChannelReserve::Channel {
            descriptor: call.descriptor,
            state: self.channel_states[channel_id].read()?.to_sol(),
        })
    }

    /// Returns the current state for a channel id, or the zero state for an empty slot.
    pub fn get_channel_state(
        &self,
        call: ITIP20ChannelReserve::getChannelStateCall,
    ) -> Result<ITIP20ChannelReserve::ChannelState> {
        Ok(self.channel_states[call.channelId].read()?.to_sol())
    }

    /// Returns current states for multiple channel ids.
    pub fn get_channel_states_batch(
        &self,
        call: ITIP20ChannelReserve::getChannelStatesBatchCall,
    ) -> Result<Vec<ITIP20ChannelReserve::ChannelState>> {
        call.channelIds
            .into_iter()
            .map(|channel_id| {
                self.channel_states[channel_id]
                    .read()
                    .map(PackedChannelState::to_sol)
            })
            .collect()
    }

    /// Computes the deterministic channel id for a full channel descriptor.
    pub fn compute_channel_id(
        &self,
        call: ITIP20ChannelReserve::computeChannelIdCall,
    ) -> Result<B256> {
        self.compute_channel_id_inner(
            call.payer,
            call.payee,
            call.operator,
            call.token,
            call.salt,
            call.authorizedSigner,
            call.expiringNonceHash,
        )
    }

    /// Returns the EIP-712 digest that the payer or authorized signer must sign.
    pub fn get_voucher_digest(
        &self,
        call: ITIP20ChannelReserve::getVoucherDigestCall,
    ) -> Result<B256> {
        self.get_voucher_digest_inner(call.channelId, call.cumulativeAmount)
    }

    /// Returns the EIP-712 domain separator for this chain and precompile address.
    pub fn domain_separator(&self) -> Result<B256> {
        let hash = match self.storage.chain_id() {
            MAINNET_CHAIN_ID => *DOMAIN_SEPARATOR_MAINNET,
            MODERATO_CHAIN_ID => *DOMAIN_SEPARATOR_TESTNET,
            chain_id => domain_separator_inner(chain_id),
        };

        Ok(hash)
    }

    /// Deletes a packed channel-state slot and credits its payer for any minted storage credits.
    fn delete_channel_state_and_credit_payer(
        &mut self,
        channel_id: B256,
        payer: Address,
    ) -> Result<()> {
        let (_, credits) = StorageCredits::new()
            .track_minted_credits(self.address, || self.channel_states[channel_id].delete())?;
        self.credit_channel_storage_slots(payer, credits)
    }

    /// Credits `payer` for deleted packed channel-state slots.
    fn credit_channel_storage_slots(&mut self, payer: Address, slots: u64) -> Result<()> {
        if slots == 0 {
            return Ok(());
        }

        let current = self.channel_storage_credits[payer].read()?;
        let updated = current.saturating_add(slots);

        if current == 0 {
            let mut storage_credits = StorageCredits::new();
            let (_, delta) = storage_credits.with_budget(self.address, 1, || {
                self.channel_storage_credits[payer].write(updated)
            })?;

            if delta != -1 {
                return Err(TempoPrecompileError::Fatal(format!(
                    "channel storage credit bookkeeping spend mismatch: reserved 1, delta {delta}"
                )));
            }

            Ok(())
        } else {
            self.channel_storage_credits[payer].write(updated)
        }
    }

    /// Creates a packed channel-state slot, consuming one payer-attributed credit when available.
    fn write_channel_state_spending_credit(
        &mut self,
        payer: Address,
        channel_id: B256,
        state: PackedChannelState,
    ) -> Result<()> {
        if !self.storage.spec().is_t7() {
            return self.channel_states[channel_id].write(state);
        }

        let current = self.channel_storage_credits[payer].read()?;
        if current == 0 {
            return self.channel_states[channel_id].write(state);
        }

        self.channel_storage_credits[payer].delete()?;

        let mut storage_credits = StorageCredits::new();
        let (_, delta) = storage_credits.with_budget(self.address, current, || {
            self.channel_states[channel_id].write(state)
        })?;
        let spent_credits = if delta < 0 { (-delta) as u64 } else { 0 };

        if spent_credits != 1 {
            return Err(TempoPrecompileError::Fatal(format!(
                "channel storage credit spend mismatch: reserved 1, spent {spent_credits}"
            )));
        }

        self.credit_channel_storage_slots(payer, current.saturating_sub(spent_credits))?;
        Ok(())
    }

    /// Returns the current block timestamp as `u64`.
    fn now(&self) -> u64 {
        self.storage.timestamp().saturating_to::<u64>()
    }

    /// Returns the current block timestamp as the packed close-request representation.
    fn now_u32(&self) -> u32 {
        self.storage.timestamp().saturating_to::<u32>()
    }

    /// Computes the channel id from a descriptor.
    fn channel_id(&self, descriptor: &ITIP20ChannelReserve::ChannelDescriptor) -> Result<B256> {
        self.compute_channel_id_inner(
            descriptor.payer,
            descriptor.payee,
            descriptor.operator,
            descriptor.token,
            descriptor.salt,
            descriptor.authorizedSigner,
            descriptor.expiringNonceHash,
        )
    }

    /// Ensures the caller is the payee or the descriptor's nonzero operator.
    fn ensure_payee_or_operator(
        msg_sender: Address,
        descriptor: &ITIP20ChannelReserve::ChannelDescriptor,
    ) -> Result<()> {
        if msg_sender != descriptor.payee
            && (descriptor.operator.is_zero() || msg_sender != descriptor.operator)
        {
            return Err(TIP20ChannelReserveError::not_payee_or_operator().into());
        }
        Ok(())
    }

    /// Loads the transaction-scoped nonce hash seeded by the handler.
    fn enclosing_channel_open_context_hash(&self) -> Result<B256> {
        let hash = self.channel_open_context_hash.t_read()?;
        if hash.is_zero() {
            return Err(TIP20ChannelReserveError::expiring_nonce_hash_not_set().into());
        }
        Ok(hash)
    }

    /// Computes the channel id including chain and precompile domain separation.
    #[expect(clippy::too_many_arguments)]
    fn compute_channel_id_inner(
        &self,
        payer: Address,
        payee: Address,
        operator: Address,
        token: Address,
        salt: B256,
        authorized_signer: Address,
        expiring_nonce_hash: B256,
    ) -> Result<B256> {
        self.storage.keccak256(
            &(
                payer,
                payee,
                operator,
                token,
                salt,
                authorized_signer,
                expiring_nonce_hash,
                self.address,
                U256::from(self.storage.chain_id()),
            )
                .abi_encode(),
        )
    }

    /// Loads an active channel or returns `ChannelNotFound`.
    fn load_existing_state(&self, channel_id: B256) -> Result<PackedChannelState> {
        let state = self.channel_states[channel_id].read()?;
        if !state.exists() {
            return Err(TIP20ChannelReserveError::channel_not_found().into());
        }
        Ok(state)
    }

    /// Returns the address authorized to sign vouchers for this descriptor.
    fn expected_signer(&self, descriptor: &ITIP20ChannelReserve::ChannelDescriptor) -> Address {
        if descriptor.authorizedSigner.is_zero() {
            descriptor.payer
        } else {
            descriptor.authorizedSigner
        }
    }

    /// Validates a voucher signature against the descriptor's expected signer.
    fn validate_voucher(
        &self,
        descriptor: &ITIP20ChannelReserve::ChannelDescriptor,
        channel_id: B256,
        cumulative_amount: U96,
        signature: &alloy::primitives::Bytes,
    ) -> Result<()> {
        let digest = self.get_voucher_digest_inner(channel_id, cumulative_amount)?;
        let signer = SignatureVerifier::new()
            .recover(digest, signature.clone())
            .map_err(|_| TIP20ChannelReserveError::invalid_signature())?;
        if signer != self.expected_signer(descriptor) {
            return Err(TIP20ChannelReserveError::invalid_signature().into());
        }
        Ok(())
    }

    /// Computes the EIP-712 voucher digest.
    fn get_voucher_digest_inner(&self, channel_id: B256, cumulative_amount: U96) -> Result<B256> {
        let struct_hash = self
            .storage
            .keccak256(&(*VOUCHER_TYPEHASH, channel_id, cumulative_amount).abi_encode())?;
        let domain_separator = self.domain_separator()?;

        let mut digest_input = [0u8; 66];
        digest_input[0] = 0x19;
        digest_input[1] = 0x01;
        digest_input[2..34].copy_from_slice(domain_separator.as_slice());
        digest_input[34..66].copy_from_slice(struct_hash.as_slice());
        self.storage.keccak256(&digest_input)
    }
}

/// Computes the EIP-712 domain separator.
///
/// NOTE: This keccak is unmetered because it is not computed at tx runtime.
fn domain_separator_inner(chain_id: u64) -> B256 {
    keccak256(
        (
            *EIP712_DOMAIN_TYPEHASH,
            *NAME_HASH,
            *VERSION_HASH,
            U256::from(chain_id),
            TIP20_CHANNEL_RESERVE_ADDRESS,
        )
            .abi_encode(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Precompile,
        address_registry::AddressRegistry,
        storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{
            TIP20Setup, VIRTUAL_MASTER, assert_full_coverage, check_selector_coverage,
            register_virtual_master,
        },
        tip403_registry::{ITIP403Registry, TIP403Registry},
    };
    use alloy::{
        primitives::{Bytes, Signature},
        sol_types::SolCall,
    };
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{
        ITIP20ChannelReserve::ITIP20ChannelReserveCalls, TIP20Error,
    };

    fn descriptor(
        payer: Address,
        payee: Address,
        operator: Address,
        token: Address,
        salt: B256,
        authorized_signer: Address,
        expiring_nonce_hash: B256,
    ) -> ITIP20ChannelReserve::ChannelDescriptor {
        ITIP20ChannelReserve::ChannelDescriptor {
            payer,
            payee,
            operator,
            token,
            salt,
            authorizedSigner: authorized_signer,
            expiringNonceHash: expiring_nonce_hash,
        }
    }

    fn open_call(
        payee: Address,
        operator: Address,
        token: Address,
        deposit: u128,
        salt: B256,
        authorized_signer: Address,
    ) -> ITIP20ChannelReserve::openCall {
        ITIP20ChannelReserve::openCall {
            payee,
            operator,
            token,
            deposit: U96::from(deposit),
            salt,
            authorizedSigner: authorized_signer,
        }
    }

    fn seed_expiring_nonce_hash(reserve: &mut TIP20ChannelReserve) -> Result<B256> {
        let hash = B256::random();
        reserve.set_channel_open_context_hash(hash)?;
        Ok(hash)
    }

    fn install_blacklist_policy(
        token: &mut TIP20Token,
        admin: Address,
    ) -> Result<(TIP403Registry, u64, u64)> {
        let mut registry = TIP403Registry::new();
        registry.initialize()?;
        let blacklist = |registry: &mut TIP403Registry| {
            registry.create_policy(
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::BLACKLIST,
                },
            )
        };
        let sender_policy = blacklist(&mut registry)?;
        let recipient_policy = blacklist(&mut registry)?;
        let compound_policy = registry.create_compound_policy(
            admin,
            ITIP403Registry::createCompoundPolicyCall {
                senderPolicyId: sender_policy,
                recipientPolicyId: recipient_policy,
                mintRecipientPolicyId: 1,
            },
        )?;
        token.change_transfer_policy_id(
            admin,
            ITIP20::changeTransferPolicyIdCall {
                newPolicyId: compound_policy,
            },
        )?;
        Ok((registry, sender_policy, recipient_policy))
    }

    fn set_blacklisted(
        registry: &mut TIP403Registry,
        admin: Address,
        policy_id: u64,
        account: Address,
        restricted: bool,
    ) -> Result<()> {
        registry.modify_policy_blacklist(
            admin,
            ITIP403Registry::modifyPolicyBlacklistCall {
                policyId: policy_id,
                account,
                restricted,
            },
        )
    }

    #[test]
    fn test_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T7);
        StorageCtx::enter(&mut storage, || {
            let mut reserve = TIP20ChannelReserve::new();
            let unsupported = check_selector_coverage(
                &mut reserve,
                ITIP20ChannelReserveCalls::SELECTORS,
                "ITIP20ChannelReserve",
                ITIP20ChannelReserveCalls::name_by_selector,
            );
            assert_full_coverage([unsupported]);
            Ok(())
        })
    }

    #[test]
    fn test_open_requires_expiring_nonce_hash() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
        let payer = Address::random();
        let payee = Address::random();

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::path_usd(payer)
                .with_issuer(payer)
                .with_mint(payer, U256::from(100u128))
                .apply()?;
            let mut reserve = TIP20ChannelReserve::new();
            reserve.initialize()?;

            let result = reserve.open(
                payer,
                open_call(
                    payee,
                    Address::ZERO,
                    token.address(),
                    1,
                    B256::random(),
                    Address::ZERO,
                ),
            );
            assert_eq!(
                result.unwrap_err(),
                TIP20ChannelReserveError::expiring_nonce_hash_not_set().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_open_rejects_invalid_payees() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
        let payer = Address::random();

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::path_usd(payer)
                .with_issuer(payer)
                .with_mint(payer, U256::from(100u128))
                .apply()?;
            let (_, virtual_payee) = register_virtual_master(&mut AddressRegistry::new())?;
            let mut reserve = TIP20ChannelReserve::new();
            reserve.initialize()?;
            seed_expiring_nonce_hash(&mut reserve)?;

            for invalid_payee in &[token.address(), virtual_payee] {
                for invalid_operator_for_virtual_payee in &[Address::ZERO, virtual_payee] {
                    let result = reserve.open(
                        payer,
                        open_call(
                            *invalid_payee,
                            *invalid_operator_for_virtual_payee,
                            token.address(),
                            1,
                            B256::random(),
                            Address::ZERO,
                        ),
                    );
                    assert_eq!(
                        result.unwrap_err(),
                        TIP20ChannelReserveError::invalid_payee().into()
                    );
                }
            }

            // Virtual payees are valid when a non-virtual operator is set to submit vouchers on their behalf.
            reserve.open(
                payer,
                open_call(
                    virtual_payee,
                    Address::random(),
                    token.address(),
                    1,
                    B256::random(),
                    Address::ZERO,
                ),
            )?;
            Ok(())
        })
    }

    #[test]
    fn test_virtual_payee_admission_checks_resolved_master() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
        let payer = Address::random();
        let admin = payer;
        let operator = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::path_usd(admin)
                .with_issuer(admin)
                .with_mint(payer, U256::from(1_000u128))
                .apply()?;
            let (mut registry, _sender_policy, recipient_policy) =
                install_blacklist_policy(&mut token, admin)?;
            let (_, virtual_payee) = register_virtual_master(&mut AddressRegistry::new())?;
            let mut reserve = TIP20ChannelReserve::new();
            reserve.initialize()?;

            // Admission must check the effective recipient, not just the virtual alias.
            set_blacklisted(&mut registry, admin, recipient_policy, VIRTUAL_MASTER, true)?;
            seed_expiring_nonce_hash(&mut reserve)?;
            let res = reserve.open(
                payer,
                open_call(
                    virtual_payee,
                    operator,
                    token.address(),
                    100,
                    B256::random(),
                    Address::ZERO,
                ),
            );
            assert_eq!(res.unwrap_err(), TIP20Error::policy_forbids().into());

            // Top-ups must enforce the same resolved-recipient admission check.
            set_blacklisted(
                &mut registry,
                admin,
                recipient_policy,
                VIRTUAL_MASTER,
                false,
            )?;
            let salt = B256::random();
            let expiring_nonce_hash = seed_expiring_nonce_hash(&mut reserve)?;
            reserve.open(
                payer,
                open_call(
                    virtual_payee,
                    operator,
                    token.address(),
                    100,
                    salt,
                    Address::ZERO,
                ),
            )?;
            let descriptor = descriptor(
                payer,
                virtual_payee,
                operator,
                token.address(),
                salt,
                Address::ZERO,
                expiring_nonce_hash,
            );

            set_blacklisted(&mut registry, admin, recipient_policy, VIRTUAL_MASTER, true)?;
            let res = reserve.top_up(
                payer,
                ITIP20ChannelReserve::topUpCall {
                    descriptor,
                    additionalDeposit: U96::from(1),
                },
            );
            assert_eq!(res.unwrap_err(), TIP20Error::policy_forbids().into());
            Ok(())
        })
    }

    #[test]
    fn test_tip403_logical_payer_payee_policy_checks() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
        let payer_signer = PrivateKeySigner::random();
        let payer = payer_signer.address();
        let payee = Address::random();
        let admin = payer;

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::path_usd(admin)
                .with_issuer(admin)
                .with_mint(payer, U256::from(1_000u128))
                .apply()?;
            let (mut registry, sender_policy, recipient_policy) =
                install_blacklist_policy(&mut token, admin)?;
            let mut reserve = TIP20ChannelReserve::new();
            reserve.initialize()?;

            // A blocked recipient cannot be used as the payee for a new channel.
            set_blacklisted(&mut registry, admin, recipient_policy, payee, true)?;
            seed_expiring_nonce_hash(&mut reserve)?;
            let res = reserve.open(
                payer,
                open_call(
                    payee,
                    Address::ZERO,
                    token.address(),
                    100,
                    B256::random(),
                    Address::ZERO,
                ),
            );
            assert_eq!(res.unwrap_err(), TIP20Error::policy_forbids().into());

            // Unblock the payee so we can fund a channel for later sender-side checks.
            set_blacklisted(&mut registry, admin, recipient_policy, payee, false)?;
            let salt = B256::random();
            let expiring_nonce_hash = seed_expiring_nonce_hash(&mut reserve)?;
            let channel_id = reserve.open(
                payer,
                open_call(
                    payee,
                    Address::ZERO,
                    token.address(),
                    100,
                    salt,
                    Address::ZERO,
                ),
            )?;
            let descriptor = descriptor(
                payer,
                payee,
                Address::ZERO,
                token.address(),
                salt,
                Address::ZERO,
                expiring_nonce_hash,
            );

            // Top-ups also reject channels whose payee can no longer receive.
            set_blacklisted(&mut registry, admin, recipient_policy, payee, true)?;
            let res = reserve.top_up(
                payer,
                ITIP20ChannelReserve::topUpCall {
                    descriptor: descriptor.clone(),
                    additionalDeposit: U96::from(1),
                },
            );
            assert_eq!(res.unwrap_err(), TIP20Error::policy_forbids().into());

            // Once funded, vouchers cannot transmit new value if the payer is blocked.
            set_blacklisted(&mut registry, admin, recipient_policy, payee, false)?;
            set_blacklisted(&mut registry, admin, sender_policy, payer, true)?;
            let digest =
                reserve.get_voucher_digest(ITIP20ChannelReserve::getVoucherDigestCall {
                    channelId: channel_id,
                    cumulativeAmount: U96::from(10),
                })?;
            let signature =
                Bytes::copy_from_slice(&payer_signer.sign_hash_sync(&digest)?.as_bytes());

            // Settle enforces the logical payer-as-sender check, not just reserve -> payee.
            let res = reserve.settle(
                payee,
                ITIP20ChannelReserve::settleCall {
                    descriptor: descriptor.clone(),
                    cumulativeAmount: U96::from(10),
                    signature: signature.clone(),
                },
            );
            assert_eq!(res.unwrap_err(), TIP20Error::policy_forbids().into());

            // Close enforces the same check when it would pay additional value to the payee.
            let res = reserve.close(
                payee,
                ITIP20ChannelReserve::closeCall {
                    descriptor,
                    cumulativeAmount: U96::from(10),
                    captureAmount: U96::from(10),
                    signature,
                },
            );
            assert_eq!(res.unwrap_err(), TIP20Error::policy_forbids().into());

            Ok(())
        })
    }

    #[test]
    fn test_open_settle_close_flow_deletes_state_and_same_tx_reopen_guard() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
        let payer_signer = PrivateKeySigner::random();
        let payer = payer_signer.address();
        let payee = Address::random();
        let salt = B256::random();

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::path_usd(payer)
                .with_issuer(payer)
                .with_mint(payer, U256::from(1_000u128))
                .apply()?;

            let mut reserve = TIP20ChannelReserve::new();
            reserve.initialize()?;
            let expiring_nonce_hash = seed_expiring_nonce_hash(&mut reserve)?;

            let channel_id = reserve.open(
                payer,
                open_call(
                    payee,
                    Address::ZERO,
                    token.address(),
                    300,
                    salt,
                    Address::ZERO,
                ),
            )?;

            let digest =
                reserve.get_voucher_digest(ITIP20ChannelReserve::getVoucherDigestCall {
                    channelId: channel_id,
                    cumulativeAmount: U96::from(120),
                })?;
            let signature =
                Bytes::copy_from_slice(&payer_signer.sign_hash_sync(&digest)?.as_bytes());

            let channel_descriptor = descriptor(
                payer,
                payee,
                Address::ZERO,
                token.address(),
                salt,
                Address::ZERO,
                expiring_nonce_hash,
            );
            reserve.settle(
                payee,
                ITIP20ChannelReserve::settleCall {
                    descriptor: channel_descriptor.clone(),
                    cumulativeAmount: U96::from(120),
                    signature,
                },
            )?;

            let close_digest =
                reserve.get_voucher_digest(ITIP20ChannelReserve::getVoucherDigestCall {
                    channelId: channel_id,
                    cumulativeAmount: U96::from(500),
                })?;
            let close_signature =
                Bytes::copy_from_slice(&payer_signer.sign_hash_sync(&close_digest)?.as_bytes());
            reserve.close(
                payee,
                ITIP20ChannelReserve::closeCall {
                    descriptor: channel_descriptor,
                    cumulativeAmount: U96::from(500),
                    captureAmount: U96::from(200),
                    signature: close_signature,
                },
            )?;

            let state = reserve.get_channel_state(ITIP20ChannelReserve::getChannelStateCall {
                channelId: channel_id,
            })?;
            assert!(state.deposit.is_zero());
            assert!(state.settled.is_zero());
            assert_eq!(state.closeRequestedAt, 0);

            let reopen_result = reserve.open(
                payer,
                open_call(
                    payee,
                    Address::ZERO,
                    token.address(),
                    1,
                    salt,
                    Address::ZERO,
                ),
            );
            assert_eq!(
                reopen_result.unwrap_err(),
                TIP20ChannelReserveError::channel_already_exists().into()
            );

            let new_expiring_nonce_hash = seed_expiring_nonce_hash(&mut reserve)?;
            let reopened_channel_id = reserve.open(
                payer,
                open_call(
                    payee,
                    Address::ZERO,
                    token.address(),
                    1,
                    salt,
                    Address::ZERO,
                ),
            )?;
            assert_ne!(channel_id, reopened_channel_id);
            assert_ne!(expiring_nonce_hash, new_expiring_nonce_hash);

            let reopened_state =
                reserve.get_channel_state(ITIP20ChannelReserve::getChannelStateCall {
                    channelId: reopened_channel_id,
                })?;
            assert_eq!(reopened_state.deposit, U96::from(1));

            Ok(())
        })
    }

    #[test]
    fn test_expiring_nonce_hash_and_operator_participate_in_channel_id() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
        let payer = Address::random();
        let payee = Address::random();
        let operator = Address::random();
        let salt = B256::random();

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::path_usd(payer)
                .with_issuer(payer)
                .with_mint(payer, U256::from(100u128))
                .apply()?;
            let reserve = TIP20ChannelReserve::new();

            let hash_a = B256::random();
            let hash_b = B256::random();
            let without_operator =
                reserve.compute_channel_id(ITIP20ChannelReserve::computeChannelIdCall {
                    payer,
                    payee,
                    operator: Address::ZERO,
                    token: token.address(),
                    salt,
                    authorizedSigner: Address::ZERO,
                    expiringNonceHash: hash_a,
                })?;
            let with_operator =
                reserve.compute_channel_id(ITIP20ChannelReserve::computeChannelIdCall {
                    payer,
                    payee,
                    operator,
                    token: token.address(),
                    salt,
                    authorizedSigner: Address::ZERO,
                    expiringNonceHash: hash_a,
                })?;
            let with_other_hash =
                reserve.compute_channel_id(ITIP20ChannelReserve::computeChannelIdCall {
                    payer,
                    payee,
                    operator: Address::ZERO,
                    token: token.address(),
                    salt,
                    authorizedSigner: Address::ZERO,
                    expiringNonceHash: hash_b,
                })?;

            assert_ne!(without_operator, with_operator);
            assert_ne!(without_operator, with_other_hash);
            Ok(())
        })
    }

    #[test]
    fn test_multiple_opens_same_transaction() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
        let payer = Address::random();
        let payee = Address::random();
        let salt = B256::random();

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::path_usd(payer)
                .with_issuer(payer)
                .with_mint(payer, U256::from(100u128))
                .apply()?;
            let mut reserve = TIP20ChannelReserve::new();
            reserve.initialize()?;

            let hash = seed_expiring_nonce_hash(&mut reserve)?;
            let first = reserve.open(
                payer,
                open_call(
                    payee,
                    Address::ZERO,
                    token.address(),
                    10,
                    salt,
                    Address::ZERO,
                ),
            )?;
            let second = reserve.open(
                payer,
                open_call(
                    payee,
                    Address::ZERO,
                    token.address(),
                    10,
                    B256::random(),
                    Address::ZERO,
                ),
            )?;
            assert_ne!(first, second);

            let other_hash = seed_expiring_nonce_hash(&mut reserve)?;
            let same_descriptor_other_tx_hash = reserve.open(
                payer,
                open_call(
                    payee,
                    Address::ZERO,
                    token.address(),
                    10,
                    salt,
                    Address::ZERO,
                ),
            )?;
            assert_ne!(first, same_descriptor_other_tx_hash);
            assert_ne!(hash, other_hash);

            Ok(())
        })
    }

    #[test]
    fn test_settle_allows_operator_and_rejects_unrelated_sender() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
        let payer_signer = PrivateKeySigner::random();
        let payer = payer_signer.address();
        let payee = Address::random();
        let operator = Address::random();

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::path_usd(payer)
                .with_issuer(payer)
                .with_mint(payer, U256::from(200u128))
                .apply()?;
            let mut reserve = TIP20ChannelReserve::new();
            reserve.initialize()?;

            let salt = B256::random();
            let expiring_nonce_hash = seed_expiring_nonce_hash(&mut reserve)?;
            let channel_id = reserve.open(
                payer,
                open_call(payee, operator, token.address(), 100, salt, Address::ZERO),
            )?;
            let channel_descriptor = descriptor(
                payer,
                payee,
                operator,
                token.address(),
                salt,
                Address::ZERO,
                expiring_nonce_hash,
            );
            let digest =
                reserve.get_voucher_digest(ITIP20ChannelReserve::getVoucherDigestCall {
                    channelId: channel_id,
                    cumulativeAmount: U96::from(40),
                })?;
            let signature =
                Bytes::copy_from_slice(&payer_signer.sign_hash_sync(&digest)?.as_bytes());

            reserve.settle(
                operator,
                ITIP20ChannelReserve::settleCall {
                    descriptor: channel_descriptor,
                    cumulativeAmount: U96::from(40),
                    signature,
                },
            )?;
            let state = reserve.get_channel_state(ITIP20ChannelReserve::getChannelStateCall {
                channelId: channel_id,
            })?;
            assert_eq!(state.settled, U96::from(40));

            let salt = B256::random();
            let expiring_nonce_hash = seed_expiring_nonce_hash(&mut reserve)?;
            reserve.open(
                payer,
                open_call(
                    payee,
                    Address::ZERO,
                    token.address(),
                    10,
                    salt,
                    Address::ZERO,
                ),
            )?;
            let descriptor_without_operator = descriptor(
                payer,
                payee,
                Address::ZERO,
                token.address(),
                salt,
                Address::ZERO,
                expiring_nonce_hash,
            );
            let result = reserve.settle(
                Address::random(),
                ITIP20ChannelReserve::settleCall {
                    descriptor: descriptor_without_operator,
                    cumulativeAmount: U96::from(1),
                    signature: Bytes::copy_from_slice(&Signature::test_signature().as_bytes()),
                },
            );
            assert_eq!(
                result.unwrap_err(),
                TIP20ChannelReserveError::not_payee_or_operator().into()
            );

            Ok(())
        })
    }

    #[test]
    fn test_close_allows_operator_and_rejects_unrelated_sender() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
        let payer_signer = PrivateKeySigner::random();
        let payer = payer_signer.address();
        let payee = Address::random();
        let operator = Address::random();

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::path_usd(payer)
                .with_issuer(payer)
                .with_mint(payer, U256::from(300u128))
                .apply()?;
            let mut reserve = TIP20ChannelReserve::new();
            reserve.initialize()?;

            let salt = B256::random();
            let expiring_nonce_hash = seed_expiring_nonce_hash(&mut reserve)?;
            let channel_id = reserve.open(
                payer,
                open_call(payee, operator, token.address(), 100, salt, Address::ZERO),
            )?;
            let channel_descriptor = descriptor(
                payer,
                payee,
                operator,
                token.address(),
                salt,
                Address::ZERO,
                expiring_nonce_hash,
            );
            let digest =
                reserve.get_voucher_digest(ITIP20ChannelReserve::getVoucherDigestCall {
                    channelId: channel_id,
                    cumulativeAmount: U96::from(80),
                })?;
            let signature =
                Bytes::copy_from_slice(&payer_signer.sign_hash_sync(&digest)?.as_bytes());

            reserve.close(
                operator,
                ITIP20ChannelReserve::closeCall {
                    descriptor: channel_descriptor,
                    cumulativeAmount: U96::from(80),
                    captureAmount: U96::from(40),
                    signature,
                },
            )?;
            let state = reserve.get_channel_state(ITIP20ChannelReserve::getChannelStateCall {
                channelId: channel_id,
            })?;
            assert!(state.deposit.is_zero());
            assert!(state.settled.is_zero());
            assert_eq!(state.closeRequestedAt, 0);

            let salt = B256::random();
            let expiring_nonce_hash = seed_expiring_nonce_hash(&mut reserve)?;
            reserve.open(
                payer,
                open_call(
                    payee,
                    Address::ZERO,
                    token.address(),
                    10,
                    salt,
                    Address::ZERO,
                ),
            )?;
            let descriptor_without_operator = descriptor(
                payer,
                payee,
                Address::ZERO,
                token.address(),
                salt,
                Address::ZERO,
                expiring_nonce_hash,
            );
            let result = reserve.close(
                Address::random(),
                ITIP20ChannelReserve::closeCall {
                    descriptor: descriptor_without_operator,
                    cumulativeAmount: U96::from(1),
                    captureAmount: U96::from(1),
                    signature: Bytes::copy_from_slice(&Signature::test_signature().as_bytes()),
                },
            );
            assert_eq!(
                result.unwrap_err(),
                TIP20ChannelReserveError::not_payee_or_operator().into()
            );

            Ok(())
        })
    }

    #[test]
    fn test_zero_top_up_without_close_request_is_noop() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
        let payer = Address::random();
        let payee = Address::random();
        let salt = B256::random();

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::path_usd(payer)
                .with_issuer(payer)
                .with_mint(payer, U256::from(1_000u128))
                .apply()?;
            let mut reserve = TIP20ChannelReserve::new();
            reserve.initialize()?;

            let expiring_nonce_hash = seed_expiring_nonce_hash(&mut reserve)?;
            let descriptor = descriptor(
                payer,
                payee,
                Address::ZERO,
                token.address(),
                salt,
                Address::ZERO,
                expiring_nonce_hash,
            );
            reserve.open(
                payer,
                open_call(
                    payee,
                    Address::ZERO,
                    token.address(),
                    100,
                    salt,
                    Address::ZERO,
                ),
            )?;
            reserve.clear_emitted_events();

            reserve.top_up(
                payer,
                ITIP20ChannelReserve::topUpCall {
                    descriptor: descriptor.clone(),
                    additionalDeposit: U96::ZERO,
                },
            )?;

            let channel =
                reserve.get_channel(ITIP20ChannelReserve::getChannelCall { descriptor })?;
            assert_eq!(channel.state.closeRequestedAt, 0);
            assert_eq!(channel.state.deposit, 100);
            assert!(
                StorageCtx
                    .get_events(TIP20_CHANNEL_RESERVE_ADDRESS)
                    .is_empty()
            );

            Ok(())
        })
    }

    #[test]
    fn test_top_up_cancels_close_request() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
        let payer = Address::random();
        let payee = Address::random();
        let salt = B256::random();

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::path_usd(payer)
                .with_issuer(payer)
                .with_mint(payer, U256::from(1_000u128))
                .apply()?;
            let mut reserve = TIP20ChannelReserve::new();
            reserve.initialize()?;

            let expiring_nonce_hash = seed_expiring_nonce_hash(&mut reserve)?;
            let descriptor = descriptor(
                payer,
                payee,
                Address::ZERO,
                token.address(),
                salt,
                Address::ZERO,
                expiring_nonce_hash,
            );
            reserve.open(
                payer,
                open_call(
                    payee,
                    Address::ZERO,
                    token.address(),
                    100,
                    salt,
                    Address::ZERO,
                ),
            )?;

            reserve.storage.set_timestamp(U256::from(1_000u64));
            reserve.request_close(
                payer,
                ITIP20ChannelReserve::requestCloseCall {
                    descriptor: descriptor.clone(),
                },
            )?;
            let requested = reserve.get_channel(ITIP20ChannelReserve::getChannelCall {
                descriptor: descriptor.clone(),
            })?;
            assert_eq!(requested.state.closeRequestedAt, 1_000);

            reserve.top_up(
                payer,
                ITIP20ChannelReserve::topUpCall {
                    descriptor: descriptor.clone(),
                    additionalDeposit: U96::from(25),
                },
            )?;

            let channel =
                reserve.get_channel(ITIP20ChannelReserve::getChannelCall { descriptor })?;
            assert_eq!(channel.state.closeRequestedAt, 0);
            assert_eq!(channel.state.deposit, 125);

            Ok(())
        })
    }

    #[test]
    fn test_dispatch_rejects_static_mutation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
        StorageCtx::enter(&mut storage, || {
            let mut reserve = TIP20ChannelReserve::new();
            let result = reserve.call(
                &ITIP20ChannelReserve::openCall {
                    payee: Address::random(),
                    operator: Address::ZERO,
                    token: TIP20_CHANNEL_RESERVE_ADDRESS,
                    deposit: U96::from(1),
                    salt: B256::ZERO,
                    authorizedSigner: Address::ZERO,
                }
                .abi_encode(),
                Address::ZERO,
            );
            assert!(result.is_ok());
            Ok(())
        })
    }

    #[test]
    fn test_settle_rejects_invalid_signature() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
        let payer = Address::random();
        let payee = Address::random();
        let salt = B256::random();

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::path_usd(payer)
                .with_issuer(payer)
                .with_mint(payer, U256::from(100u128))
                .apply()?;
            let mut reserve = TIP20ChannelReserve::new();
            reserve.initialize()?;
            let expiring_nonce_hash = seed_expiring_nonce_hash(&mut reserve)?;
            reserve.open(
                payer,
                open_call(
                    payee,
                    Address::ZERO,
                    token.address(),
                    100,
                    salt,
                    Address::ZERO,
                ),
            )?;

            let result = reserve.settle(
                payee,
                ITIP20ChannelReserve::settleCall {
                    descriptor: descriptor(
                        payer,
                        payee,
                        Address::ZERO,
                        token.address(),
                        salt,
                        Address::ZERO,
                        expiring_nonce_hash,
                    ),
                    cumulativeAmount: U96::from(10),
                    signature: Bytes::copy_from_slice(
                        &Signature::test_signature().as_bytes()[..64],
                    ),
                },
            );
            assert_eq!(
                result.unwrap_err(),
                TIP20ChannelReserveError::invalid_signature().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_settle_rejects_keychain_signature_wrapper() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
        let payer = Address::random();
        let payee = Address::random();
        let salt = B256::random();

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::path_usd(payer)
                .with_issuer(payer)
                .with_mint(payer, U256::from(100u128))
                .apply()?;
            let mut reserve = TIP20ChannelReserve::new();
            reserve.initialize()?;
            let expiring_nonce_hash = seed_expiring_nonce_hash(&mut reserve)?;
            reserve.open(
                payer,
                open_call(
                    payee,
                    Address::ZERO,
                    token.address(),
                    100,
                    salt,
                    Address::ZERO,
                ),
            )?;

            let mut keychain_signature = Vec::new();
            keychain_signature.push(0x03);
            keychain_signature.extend_from_slice(Address::random().as_slice());
            keychain_signature.extend_from_slice(Signature::test_signature().as_bytes().as_slice());

            let result = reserve.settle(
                payee,
                ITIP20ChannelReserve::settleCall {
                    descriptor: descriptor(
                        payer,
                        payee,
                        Address::ZERO,
                        token.address(),
                        salt,
                        Address::ZERO,
                        expiring_nonce_hash,
                    ),
                    cumulativeAmount: U96::from(10),
                    signature: keychain_signature.into(),
                },
            );
            assert_eq!(
                result.unwrap_err(),
                TIP20ChannelReserveError::invalid_signature().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_withdraw_after_grace_deletes_state() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
        let payer = Address::random();
        let payee = Address::random();
        let salt = B256::random();

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::path_usd(payer)
                .with_issuer(payer)
                .with_mint(payer, U256::from(100u128))
                .apply()?;
            let mut reserve = TIP20ChannelReserve::new();
            reserve.initialize()?;
            let expiring_nonce_hash = seed_expiring_nonce_hash(&mut reserve)?;
            let channel_id = reserve.open(
                payer,
                open_call(
                    payee,
                    Address::ZERO,
                    token.address(),
                    100,
                    salt,
                    Address::ZERO,
                ),
            )?;
            let descriptor = descriptor(
                payer,
                payee,
                Address::ZERO,
                token.address(),
                salt,
                Address::ZERO,
                expiring_nonce_hash,
            );

            reserve.storage.set_timestamp(U256::from(1_000u64));
            reserve.request_close(
                payer,
                ITIP20ChannelReserve::requestCloseCall {
                    descriptor: descriptor.clone(),
                },
            )?;
            reserve
                .storage
                .set_timestamp(U256::from(1_000u64 + CLOSE_GRACE_PERIOD));
            reserve.withdraw(payer, ITIP20ChannelReserve::withdrawCall { descriptor })?;

            let state = reserve.get_channel_state(ITIP20ChannelReserve::getChannelStateCall {
                channelId: channel_id,
            })?;
            assert!(state.deposit.is_zero());
            assert!(state.settled.is_zero());
            assert_eq!(state.closeRequestedAt, 0);

            Ok(())
        })
    }

    #[test]
    fn test_withdraw_requires_close_request() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
        let payer = Address::random();
        let payee = Address::random();
        let salt = B256::random();

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::path_usd(payer)
                .with_issuer(payer)
                .with_mint(payer, U256::from(100u128))
                .apply()?;
            let mut reserve = TIP20ChannelReserve::new();
            reserve.initialize()?;
            let expiring_nonce_hash = seed_expiring_nonce_hash(&mut reserve)?;
            let descriptor = descriptor(
                payer,
                payee,
                Address::ZERO,
                token.address(),
                salt,
                Address::ZERO,
                expiring_nonce_hash,
            );
            reserve.open(
                payer,
                open_call(
                    payee,
                    Address::ZERO,
                    token.address(),
                    100,
                    salt,
                    Address::ZERO,
                ),
            )?;

            let result = reserve.withdraw(payer, ITIP20ChannelReserve::withdrawCall { descriptor });
            assert_eq!(
                result.unwrap_err(),
                TIP20ChannelReserveError::close_not_ready().into()
            );
            Ok(())
        })
    }
}
