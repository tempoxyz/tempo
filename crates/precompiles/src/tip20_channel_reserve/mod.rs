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
use keccak_const::Keccak256;
use tempo_chainspec::constants::{mainnet::MAINNET_CHAIN_ID, moderato::MODERATO_CHAIN_ID};
pub use tempo_contracts::precompiles::{
    ITIP20ChannelReserve, TIP20_CHANNEL_RESERVE_ADDRESS, TIP20ChannelReserveError,
    TIP20ChannelReserveEvent,
};
use tempo_contracts::zones::ZoneDepositAddress;
use tempo_precompiles_macros::{Storable, contract};
use tempo_primitives::{TempoAddressExt, transaction::tt_signature::TempoSignature};

/// 15 minute grace period between `requestClose` and `withdraw`.
pub const CLOSE_GRACE_PERIOD: u64 = 15 * 60;

const TIP20_CHANNEL_RESERVE_RECEIVE_POLICY_SLOT: U256 = {
    let mut buf = [0u8; 64];
    let addr = TIP20_CHANNEL_RESERVE_ADDRESS.0.0;
    let mut i = 0;
    while i < 20 {
        buf[12 + i] = addr[i];
        i += 1;
    }
    let slot = crate::tip403_registry::slots::RECEIVE_POLICIES.to_be_bytes::<32>();
    let mut j = 0;
    while j < 32 {
        buf[32 + j] = slot[j];
        j += 1;
    }
    U256::from_be_bytes(Keccak256::new().update(&buf).finalize())
};

/// EIP-712 type hash for signed cumulative payment vouchers.
const VOUCHER_TYPEHASH: B256 = B256::new(
    Keccak256::new()
        .update(b"Voucher(bytes32 channelId,uint96 cumulativeAmount)")
        .finalize(),
);
/// EIP-712 domain type hash used by [`TIP20ChannelReserve::domain_separator`].
const EIP712_DOMAIN_TYPEHASH: B256 = B256::new(
    Keccak256::new()
        .update(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        )
        .finalize(),
);
/// EIP-712 domain name hash for the reserve voucher domain.
const NAME_HASH: B256 = B256::new(Keccak256::new().update(b"TIP20 Channel Reserve").finalize());
/// EIP-712 domain version hash for the reserve voucher domain.
const VERSION_HASH: B256 = B256::new(Keccak256::new().update(b"1").finalize());

/// EIP-712 domain separator for the reserve voucher domain on mainnet.
const DOMAIN_SEPARATOR_MAINNET: B256 = const_domain_separator(MAINNET_CHAIN_ID);
/// EIP-712 domain separator for the reserve voucher domain on testnet.
const DOMAIN_SEPARATOR_TESTNET: B256 = const_domain_separator(MODERATO_CHAIN_ID);

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
    /// Whether TIP-1028 should see the logical payer during capture.
    ///
    /// This field occupies previously unused bytes in the packed slot. Channels created before
    /// T12 decode it as false and retain the reserve sender accepted when they were funded.
    uses_logical_receive_policy_sender: bool,
    /// Whether the descriptor's `salt` is the voucher signer's configuration commitment from
    /// `open` (TIP-1166).
    ///
    /// This field occupies previously unused bytes in the packed slot, so channels opened before
    /// T15 decode it as false.
    has_opening_commitment: bool,
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

    /// Returns the sender presented to the payee's TIP-1028 receive policy.
    fn receive_policy_sender(self, payer: Address) -> Address {
        if self.uses_logical_receive_policy_sender {
            payer
        } else {
            TIP20_CHANNEL_RESERVE_ADDRESS
        }
    }

    #[inline]
    fn exists_in_word(word: U256) -> bool {
        // `deposit` occupies bytes 12..24 (bits 96..192) of the packed LSB-first slot.
        let limbs = word.as_limbs();
        (limbs[1] >> 32) != 0 || limbs[2] != 0
    }

    #[inline]
    fn to_word_direct(self) -> U256 {
        // Packed LSB-first layout: settled (0..12), deposit (12..24), close_requested_at (24..28),
        // uses_logical_receive_policy_sender (28), has_opening_commitment (29).
        let settled_le = self.settled.to_le_bytes::<12>();
        let deposit_le = self.deposit.to_le_bytes::<12>();
        let close_le = self.close_requested_at.to_le_bytes();
        let mut le = [0u8; 32];
        le[0..12].copy_from_slice(&settled_le);
        le[12..24].copy_from_slice(&deposit_le);
        le[24..28].copy_from_slice(&close_le);
        le[28] = u8::from(self.uses_logical_receive_policy_sender);
        le[29] = u8::from(self.has_opening_commitment);
        U256::from_le_bytes(le)
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
    /// Persistent channel state keyed by [`ITIP20ChannelReserve::ChannelDescriptor::id`].
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

    /// Creates and initializes the precompile, for tests that don't exercise initialization.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn initialized() -> Result<Self> {
        let mut this = Self::new();
        this.initialize()?;
        Ok(this)
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

    /// Writes `channel_open_context_hash` directly without constructing `TIP20ChannelReserve`.
    #[inline]
    pub fn set_channel_open_context_hash_direct(hash: B256) -> Result<()> {
        crate::storage::Slot::<B256>::new(
            slots::CHANNEL_OPEN_CONTEXT_HASH,
            crate::TIP20_CHANNEL_RESERVE_ADDRESS,
        )
        .t_write(hash)
    }

    #[inline]
    pub(crate) fn try_execute_open_direct<T>(
        storage: &mut crate::storage::evm::EvmPrecompileStorageProvider<'_, '_, '_, T>,
        calldata: &[u8],
        msg_sender: Address,
        frame_depth: u16,
        nested_calls: &std::rc::Rc<std::cell::Cell<u16>>,
    ) -> Option<evm2::precompiles::PrecompileResult>
    where
        T: evm2::EvmTypes<BlockEnvExt = tempo_primitives::TempoBlockExt>,
        T::EvmExt: crate::storage::evm::EvmStorageExt,
    {
        use crate::{
            account_keychain::AccountKeychain,
            storage::{
                PrecompileStorageProvider as _, StorageCtx, StorageKey as _,
                evm::{EvmStorageExt as _, Frame},
            },
            tip20::{TIP20_CHANNEL_RESERVE_BALANCE_SLOT, TIP20Error, TIP20Event, TIP20Token},
            tip403_registry::{ALLOW_ALL_POLICY_ID, AuthRole, TIP403Registry},
        };
        use alloy::sol_types::SolCall as _;

        let spec = storage.spec();
        if !spec.is_t12() || storage.is_static() || calldata.len() != 196 {
            return None;
        }
        if calldata[..4] != ITIP20ChannelReserve::openCall::SELECTOR
            || calldata[4..16] != [0u8; 12]
            || calldata[36..48] != [0u8; 12]
            || calldata[68..80] != [0u8; 12]
            || calldata[100..120] != [0u8; 20]
            || calldata[164..176] != [0u8; 12]
        {
            return None;
        }

        let payee = Address::from_slice(&calldata[16..36]);
        let operator = Address::from_slice(&calldata[48..68]);
        let token = Address::from_slice(&calldata[80..100]);
        let deposit = U96::from_be_slice(&calldata[120..132]);
        let salt = B256::from_slice(&calldata[132..164]);
        let authorized_signer = Address::from_slice(&calldata[176..196]);

        let is_t15 = spec.is_t15();
        if payee.is_zero()
            || is_tip20_prefix(payee)
            || payee.is_virtual()
            || (is_t15 && ZoneDepositAddress::is_reserved(&payee))
            || !token.is_tip20()
            || deposit.is_zero()
        {
            return None;
        }

        if crate::input_cost(spec, 196)
            .and_then(|cost| storage.deduct_gas(cost))
            .is_err()
        {
            return Some(Err(evm2::precompiles::PrecompileHalt::OutOfGas.into()));
        }
        if let Err(err) = storage.preserve_storage_credits_direct(TIP20_CHANNEL_RESERVE_ADDRESS) {
            return Some(err.into_precompile_result());
        }

        let signer = if authorized_signer.is_zero() {
            msg_sender
        } else {
            authorized_signer
        };
        if !is_t15
            && let Err(err) =
                StorageCtx::enter(storage, || Self::new().ensure_voucher_signer_active(signer))
        {
            return Some(err.into_precompile_result());
        }

        let expiring_nonce_hash = match storage.tload_direct(
            TIP20_CHANNEL_RESERVE_ADDRESS,
            slots::CHANNEL_OPEN_CONTEXT_HASH,
        ) {
            Ok(word) => B256::from(word),
            Err(err) => return Some(err.into_precompile_result()),
        };
        if expiring_nonce_hash.is_zero() {
            return Some(
                TempoPrecompileError::from(TIP20ChannelReserveError::expiring_nonce_hash_not_set())
                    .into_precompile_result(),
            );
        }

        let descriptor = ITIP20ChannelReserve::ChannelDescriptor {
            payer: msg_sender,
            payee,
            operator,
            token,
            salt,
            authorizedSigner: authorized_signer,
            expiringNonceHash: expiring_nonce_hash,
        };
        let preimage = descriptor.id_preimage_bytes(storage.chain_id());
        let channel_id = match storage.keccak256(&preimage) {
            Ok(id) => id,
            Err(err) => return Some(err.into_precompile_result()),
        };

        let channel_state_slot = channel_id.mapping_slot(slots::CHANNEL_STATES);
        let raw_state =
            match storage.sload_direct(TIP20_CHANNEL_RESERVE_ADDRESS, channel_state_slot) {
                Ok(w) => w,
                Err(err) => return Some(err.into_precompile_result()),
            };
        if PackedChannelState::exists_in_word(raw_state) {
            return Some(
                TempoPrecompileError::from(TIP20ChannelReserveError::channel_already_exists())
                    .into_precompile_result(),
            );
        }
        let opened_slot = channel_id.mapping_slot(slots::OPENED_THIS_TX);
        match storage.tload_direct(TIP20_CHANNEL_RESERVE_ADDRESS, opened_slot) {
            Ok(w) if !w.is_zero() => {
                return Some(
                    TempoPrecompileError::from(TIP20ChannelReserveError::channel_already_exists())
                        .into_precompile_result(),
                );
            }
            Ok(_) => {}
            Err(err) => return Some(err.into_precompile_result()),
        }

        let opening_commitment = if is_t15 {
            match storage.config_commitment(signer) {
                Ok(c) => c,
                Err(err) => return Some(err.into_precompile_result()),
            }
        } else {
            B256::ZERO
        };
        if !opening_commitment.is_zero() && salt != opening_commitment {
            return Some(
                TempoPrecompileError::from(TIP20ChannelReserveError::salt_not_signer_commitment(
                    signer,
                    opening_commitment,
                ))
                .into_precompile_result(),
            );
        }

        let policy_id = match TIP20Token::transfer_policy_id_on_provider(storage, token) {
            Ok(id) => id,
            Err(err) => return Some(err.into_precompile_result()),
        };
        if policy_id != ALLOW_ALL_POLICY_ID {
            let res = StorageCtx::enter(storage, || -> Result<()> {
                let registry = TIP403Registry::new();
                for &(user, role) in &[
                    (msg_sender, AuthRole::sender()),
                    (payee, AuthRole::recipient()),
                ] {
                    if !registry.is_authorized_as(policy_id, user, role)? {
                        return Err(TIP20Error::policy_forbids().into());
                    }
                }
                Ok(())
            });
            if let Err(err) = res {
                return Some(err.into_precompile_result());
            }
        }

        let (_, payee_rp_slot) = storage
            .evm_ext_mut()
            .cached_balance_and_receive_policy_slots(payee);
        let payee_rp_raw = match storage.sload_direct(crate::TIP403_REGISTRY_ADDRESS, payee_rp_slot)
        {
            Ok(v) => v,
            Err(err) => return Some(err.into_precompile_result()),
        };
        if !payee_rp_raw.is_zero() {
            let res = StorageCtx::enter(storage, || -> Result<()> {
                if TIP403Registry::check_receive_policy_from_raw(
                    token,
                    msg_sender,
                    payee,
                    payee_rp_raw,
                )?
                .is_some()
                {
                    return Err(TIP20Error::policy_forbids().into());
                }
                Ok(())
            });
            if let Err(err) = res {
                return Some(err.into_precompile_result());
            }
        }

        let paused_word = match storage.sload_direct(token, crate::tip20::slots::PAUSED) {
            Ok(v) => v,
            Err(err) => return Some(err.into_precompile_result()),
        };
        if !paused_word.is_zero() {
            return Some(
                TempoPrecompileError::from(TIP20Error::contract_paused()).into_precompile_result(),
            );
        }

        let deposit_u256 = U256::from(deposit);
        let tx_key_word = match storage.tload_direct(
            crate::ACCOUNT_KEYCHAIN_ADDRESS,
            crate::account_keychain::slots::TRANSACTION_KEY,
        ) {
            Ok(v) => v,
            Err(err) => return Some(err.into_precompile_result()),
        };
        if !tx_key_word.is_zero() {
            let tx_key = Address::from_word(tx_key_word.into());
            let res = StorageCtx::enter(storage, || {
                AccountKeychain::authorize_transfer_with_key(
                    tx_key,
                    msg_sender,
                    token,
                    deposit_u256,
                )
            });
            if let Err(err) = res {
                return Some(err.into_precompile_result());
            }
        }

        let reserve_rp_raw = match storage.sload_direct(
            crate::TIP403_REGISTRY_ADDRESS,
            TIP20_CHANNEL_RESERVE_RECEIVE_POLICY_SLOT,
        ) {
            Ok(v) => v,
            Err(err) => return Some(err.into_precompile_result()),
        };
        if !reserve_rp_raw.is_zero() {
            let res = StorageCtx::enter(storage, || -> Result<()> {
                if TIP403Registry::check_receive_policy_from_raw(
                    token,
                    msg_sender,
                    TIP20_CHANNEL_RESERVE_ADDRESS,
                    reserve_rp_raw,
                )?
                .is_some()
                {
                    return Err(TIP20Error::policy_forbids().into());
                }
                Ok(())
            });
            if let Err(err) = res {
                return Some(err.into_precompile_result());
            }
        }

        let from_slot = storage
            .evm_ext()
            .resolved_fee_balance_slot(msg_sender)
            .unwrap_or_else(|| storage.evm_ext_mut().cached_balance_slot(msg_sender));
        if let Err(err) = storage.sdelta_pair(
            token,
            from_slot,
            TIP20_CHANNEL_RESERVE_BALANCE_SLOT,
            deposit_u256,
        ) {
            let mapped: TempoPrecompileError = match err {
                TempoPrecompileError::StorageDeltaUnderflow(current) => {
                    TIP20Error::insufficient_balance(current, deposit_u256, token).into()
                }
                e if e == TempoPrecompileError::under_overflow() => {
                    TIP20Error::supply_cap_exceeded().into()
                }
                e => e,
            };
            return Some(mapped.into_precompile_result());
        }

        if let Err(err) = storage.emit_event_direct(
            token,
            alloy::primitives::IntoLogData::to_log_data(&TIP20Event::transfer(
                msg_sender,
                TIP20_CHANNEL_RESERVE_ADDRESS,
                deposit_u256,
            )),
        ) {
            return Some(err.into_precompile_result());
        }

        let state = PackedChannelState {
            settled: U96::ZERO,
            deposit,
            close_requested_at: 0,
            uses_logical_receive_policy_sender: true,
            has_opening_commitment: !opening_commitment.is_zero(),
        };
        let credit_slot = storage.evm_ext_mut().cached_channel_credit_slot(msg_sender);
        let encoded_state = state.to_word_direct();
        match storage.channel_reserve_write_if_no_credit(
            credit_slot,
            channel_state_slot,
            encoded_state,
        ) {
            Ok(None) => {}
            Ok(Some(current)) => {
                storage.set_frame(Frame {
                    address: TIP20_CHANNEL_RESERVE_ADDRESS,
                    depth: frame_depth,
                    nested_calls: nested_calls.clone(),
                });
                if let Err(err) = StorageCtx::enter(storage, || {
                    Self::new().write_channel_state_with_existing_credit(
                        msg_sender, channel_id, state, current,
                    )
                }) {
                    return Some(err.into_precompile_result());
                }
            }
            Err(err) => return Some(err.into_precompile_result()),
        }

        if let Err(err) =
            storage.tstore_direct(TIP20_CHANNEL_RESERVE_ADDRESS, opened_slot, U256::from(1u64))
        {
            return Some(err.into_precompile_result());
        }

        if let Err(err) = storage.emit_event_direct(
            TIP20_CHANNEL_RESERVE_ADDRESS,
            alloy::primitives::IntoLogData::to_log_data(&TIP20ChannelReserveEvent::ChannelOpened(
                ITIP20ChannelReserve::ChannelOpened {
                    channelId: channel_id,
                    payer: msg_sender,
                    payee,
                    operator,
                    token,
                    authorizedSigner: authorized_signer,
                    salt,
                    expiringNonceHash: expiring_nonce_hash,
                    deposit,
                },
            )),
        ) {
            return Some(err.into_precompile_result());
        }
        if state.has_opening_commitment
            && let Err(err) = storage.emit_event_direct(
                TIP20_CHANNEL_RESERVE_ADDRESS,
                alloy::primitives::IntoLogData::to_log_data(
                    &TIP20ChannelReserveEvent::OpeningCommitmentRecorded(
                        ITIP20ChannelReserve::OpeningCommitmentRecorded {
                            channelId: channel_id,
                            signer,
                            commitment: opening_commitment,
                        },
                    ),
                ),
            )
        {
            return Some(err.into_precompile_result());
        }

        Some(Ok(evm2::evm::precompile::PrecompileOutput::new(
            alloy::primitives::Bytes::copy_from_slice(channel_id.as_slice()),
        )))
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
    ///
    /// At T14, reverts with `RootKeyRetired` when the voucher signer has a configuration
    /// commitment. From T15 (TIP-1166), `salt` must equal that commitment instead, or the call
    /// reverts with `SaltNotSignerCommitment`, and the channel's vouchers are checked against
    /// it for the channel's lifetime.
    pub fn open(
        &mut self,
        msg_sender: Address,
        call: ITIP20ChannelReserve::openCall,
    ) -> Result<B256> {
        // +T15: A TIP-1094 zone deposit address cannot receive a channel payout: TIP-20 only routes
        // plain transfers to it, and it can never submit vouchers.
        if call.payee.is_zero()
            || is_tip20_prefix(call.payee)
            || (call.payee.is_virtual() && (call.operator.is_zero() || call.operator.is_virtual()))
            || (self.storage.spec().is_t15() && ZoneDepositAddress::is_reserved(&call.payee))
        {
            return Err(TIP20ChannelReserveError::invalid_payee().into());
        }

        let mut token = TIP20Token::from_address(call.token)?;

        let deposit = call.deposit;
        if deposit.is_zero() {
            return Err(TIP20ChannelReserveError::zero_deposit().into());
        }

        let signer = if call.authorizedSigner.is_zero() {
            msg_sender
        } else {
            call.authorizedSigner
        };
        let is_t15 = self.storage.spec().is_t15();
        if !is_t15 {
            self.ensure_voucher_signer_active(signer)?;
        }

        let expiring_nonce_hash = self.enclosing_channel_open_context_hash()?;
        let channel_id = self.channel_id(&ITIP20ChannelReserve::ChannelDescriptor {
            payer: msg_sender,
            payee: call.payee,
            operator: call.operator,
            token: call.token,
            salt: call.salt,
            authorizedSigner: call.authorizedSigner,
            expiringNonceHash: expiring_nonce_hash,
        })?;
        if self.channel_states[channel_id].read()?.exists()
            || self.opened_this_tx[channel_id].t_read()?
        {
            return Err(TIP20ChannelReserveError::channel_already_exists().into());
        }
        let opening_commitment = if is_t15 {
            self.storage.config_commitment(signer)?
        } else {
            B256::ZERO
        };
        if !opening_commitment.is_zero() && call.salt != opening_commitment {
            return Err(TIP20ChannelReserveError::salt_not_signer_commitment(
                signer,
                opening_commitment,
            )
            .into());
        }

        if self.storage.spec().is_t12() {
            let payee = Recipient::resolve(call.payee)?.target;
            token.ensure_transfer_authorized(msg_sender, payee)?;
            token.ensure_receive_policy_authorized(msg_sender, payee)?;
            token.channel_reserve_transfer(
                msg_sender,
                Recipient::direct(self.address),
                U256::from(call.deposit),
                msg_sender,
            )?;
        } else {
            token.ensure_authorized_as(&[(
                Recipient::resolve(call.payee)?.target,
                AuthRole::Recipient,
            )])?;
            token.system_transfer_from(self.address, msg_sender, U256::from(call.deposit))?;
        }

        let state = PackedChannelState {
            settled: U96::ZERO,
            deposit,
            close_requested_at: 0,
            uses_logical_receive_policy_sender: self.storage.spec().is_t12(),
            has_opening_commitment: !opening_commitment.is_zero(),
        };
        self.write_channel_state_spending_credit(msg_sender, channel_id, state)?;
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
        if state.has_opening_commitment {
            self.emit_event(TIP20ChannelReserveEvent::OpeningCommitmentRecorded(
                ITIP20ChannelReserve::OpeningCommitmentRecorded {
                    channelId: channel_id,
                    signer,
                    commitment: opening_commitment,
                },
            ))?;
        }

        Ok(channel_id)
    }

    /// Settles an increasing cumulative voucher, paying only the unsettled delta to the payee.
    ///
    /// The payee can call directly. If an operator was set when the channel was opened, that
    /// operator can submit the payee's voucher and route the payment to the descriptor payee.
    ///
    /// Settlement does not cancel or extend a pending close request. Payees should settle before
    /// its deadline.
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
            state,
            call.cumulativeAmount,
            &call.signature,
        )?;

        let delta = cumulative
            .checked_sub(state.settled)
            .expect("cumulative amount already checked to be increasing");

        let mut token = TIP20Token::from_address(call.descriptor.token)?;

        if self.storage.spec().is_t12() {
            let payee = Recipient::resolve(call.descriptor.payee)?;
            token.ensure_transfer_authorized(call.descriptor.payer, payee.target)?;
            token.channel_reserve_transfer(
                self.address,
                payee,
                U256::from(delta),
                state.receive_policy_sender(call.descriptor.payer),
            )?;

            state.settled = cumulative;
            self.channel_states[channel_id].write(state)?;
        } else {
            token.ensure_authorized_as(&[(call.descriptor.payer, AuthRole::Sender)])?;

            // Preserve the pre-T12 fallible-operation order. Although a later transfer failure
            // reverts this write, moving it changes consensus-visible gas on legacy forks.
            state.settled = cumulative;
            self.channel_states[channel_id].write(state)?;

            token.transfer(
                self.address,
                ITIP20::transferCall {
                    to: call.descriptor.payee,
                    amount: U256::from(delta),
                },
            )?;
        }

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
    ///
    /// At T14, a nonzero top-up reverts with `RootKeyRetired` when the voucher signer has a
    /// configuration commitment. From T15 (TIP-1166), it reverts when the signer's commitment
    /// differs from the one saved at open: with `SignerConfigChanged` when one was saved, and
    /// with `RootKeyRetired` when the signer had none at open.
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
            let signer = self.expected_signer(&call.descriptor);
            if self.storage.spec().is_t15() {
                // Old owners must not gain authority over new funds after a rotation, and an
                // unregistered signer's registration can't be told apart from one.
                let commitment = opening_commitment(&call.descriptor, state);
                if self.storage.config_commitment(signer)? != commitment {
                    return Err(if commitment.is_zero() {
                        TIP20ChannelReserveError::root_key_retired(signer)
                    } else {
                        TIP20ChannelReserveError::signer_config_changed(signer)
                    }
                    .into());
                }
            } else {
                self.ensure_voucher_signer_active(signer)?;
            }
            let next_deposit = state
                .deposit
                .checked_add(additional)
                .ok_or_else(TIP20ChannelReserveError::deposit_overflow)?;

            state.deposit = next_deposit;
            let mut token = TIP20Token::from_address(call.descriptor.token)?;
            if self.storage.spec().is_t12() {
                let payee = Recipient::resolve(call.descriptor.payee)?.target;
                token.ensure_transfer_authorized(msg_sender, payee)?;
                token.ensure_receive_policy_authorized(
                    state.receive_policy_sender(msg_sender),
                    payee,
                )?;
                token.channel_reserve_transfer(
                    msg_sender,
                    Recipient::direct(self.address),
                    U256::from(call.additionalDeposit),
                    msg_sender,
                )?;
            } else {
                token.ensure_authorized_as(&[(
                    Recipient::resolve(call.descriptor.payee)?.target,
                    AuthRole::Recipient,
                )])?;
                token.system_transfer_from(
                    self.address,
                    msg_sender,
                    U256::from(call.additionalDeposit),
                )?;
            }
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
    ///
    /// Payees should stop accepting vouchers and settle outstanding payments before the grace
    /// period expires. Repeated requests retain the original deadline.
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
                state,
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

        if self.storage.spec().is_t12() {
            let mut token = TIP20Token::from_address(call.descriptor.token)?;
            if !delta.is_zero() {
                let payee = Recipient::resolve(call.descriptor.payee)?;
                token.ensure_transfer_authorized(call.descriptor.payer, payee.target)?;
                token.channel_reserve_transfer(
                    self.address,
                    payee,
                    U256::from(delta),
                    state.receive_policy_sender(call.descriptor.payer),
                )?;
            }
            if !refund.is_zero() {
                token.channel_reserve_transfer(
                    self.address,
                    Recipient::resolve(call.descriptor.payer)?,
                    U256::from(refund),
                    self.address,
                )?;
            }

            // Commit terminal channel state only after both deliveries succeed. TIP-1028
            // rejections therefore leave the channel available for retry.
            self.delete_channel_state_and_credit_payer(channel_id, call.descriptor.payer)?;
        } else {
            // Preserve the pre-T12 fallible-operation order and gas behavior.
            self.delete_channel_state_and_credit_payer(channel_id, call.descriptor.payer)?;
            let mut token = TIP20Token::from_address(call.descriptor.token)?;

            if !delta.is_zero() {
                token.ensure_authorized_as(&[(call.descriptor.payer, AuthRole::Sender)])?;
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
    ///
    /// At the deadline, withdrawal may execute before settlement, making outstanding vouchers
    /// unredeemable.
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

        if self.storage.spec().is_t12() {
            if !refund.is_zero() {
                let mut token = TIP20Token::from_address(call.descriptor.token)?;
                token.channel_reserve_transfer(
                    self.address,
                    Recipient::resolve(call.descriptor.payer)?,
                    U256::from(refund),
                    self.address,
                )?;
            }
            // Commit terminal state only after a nonzero refund succeeds. A zero-refund
            // withdrawal has no fallible token delivery to wait for.
            self.delete_channel_state_and_credit_payer(channel_id, call.descriptor.payer)?;
        } else {
            // Preserve the pre-T12 fallible-operation order and gas behavior.
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
        self.channel_id(&ITIP20ChannelReserve::ChannelDescriptor {
            payer: call.payer,
            payee: call.payee,
            operator: call.operator,
            token: call.token,
            salt: call.salt,
            authorizedSigner: call.authorizedSigner,
            expiringNonceHash: call.expiringNonceHash,
        })
    }

    /// Returns the EIP-712 digest that the payer or authorized signer must sign.
    pub fn get_voucher_digest(
        &self,
        call: ITIP20ChannelReserve::getVoucherDigestCall,
    ) -> Result<B256> {
        self.get_voucher_digest_inner(call.channelId, call.cumulativeAmount)
    }

    /// Returns whether `settle` and `close` would accept the voucher signature (TIP-1166).
    ///
    /// Runs the same signature checks as `settle`, against the channel's snapshot, and charges the
    /// same gas. Reverts with `ChannelNotFound` if the channel doesn't exist. Doesn't check the
    /// amount against the channel's deposit or settled amount.
    pub fn verify_voucher(&self, call: ITIP20ChannelReserve::verifyVoucherCall) -> Result<bool> {
        let channel_id = self.channel_id(&call.descriptor)?;
        let state = self.load_existing_state(channel_id)?;
        match self.validate_voucher(
            &call.descriptor,
            channel_id,
            state,
            call.cumulativeAmount,
            &call.signature,
        ) {
            Ok(()) => Ok(true),
            Err(TempoPrecompileError::TIP20ChannelReserveError(
                TIP20ChannelReserveError::InvalidSignature(_),
            )) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Returns the EIP-712 domain separator for this chain and precompile address.
    pub fn domain_separator(&self) -> Result<B256> {
        Ok(domain_separator(self.storage.chain_id()))
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

        self.write_channel_state_with_existing_credit(payer, channel_id, state, current)
    }

    fn write_channel_state_with_existing_credit(
        &mut self,
        payer: Address,
        channel_id: B256,
        state: PackedChannelState,
        current: u64,
    ) -> Result<()> {
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
        let preimage = descriptor.id_preimage_bytes(self.storage.chain_id());
        self.storage.keccak256(&preimage)
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
    ///
    /// From T15 (TIP-1166), a configurable account signature of the signer is checked against the
    /// commitment the descriptor's salt holds, or against its version-0 address derivation when the
    /// signer had no commitment at open. A primitive signature is accepted only in that case.
    fn validate_voucher(
        &self,
        descriptor: &ITIP20ChannelReserve::ChannelDescriptor,
        channel_id: B256,
        state: PackedChannelState,
        cumulative_amount: U96,
        signature: &alloy::primitives::Bytes,
    ) -> Result<()> {
        let digest = self.get_voucher_digest_inner(channel_id, cumulative_amount)?;
        let expected_signer = self.expected_signer(descriptor);
        if self.storage.spec().is_t15() {
            let commitment = opening_commitment(descriptor, state);
            if let Ok(TempoSignature::ConfigurableAccount(signature)) =
                TempoSignature::from_bytes(signature)
            {
                let valid = SignatureVerifier::new()
                    .verify_configurable_signature_against(
                        expected_signer,
                        digest,
                        &signature,
                        commitment,
                        true,
                    )
                    .map_err(|error| {
                        if error.is_system_error() {
                            error
                        } else {
                            TIP20ChannelReserveError::invalid_signature().into()
                        }
                    })?;
                if !valid {
                    return Err(TIP20ChannelReserveError::invalid_signature().into());
                }
                return Ok(());
            }
            // A signer with a commitment at open had its root key retired (TIP-1113).
            if !commitment.is_zero() {
                return Err(TIP20ChannelReserveError::invalid_signature().into());
            }
        }
        let is_t15 = self.storage.spec().is_t15();
        let signer = SignatureVerifier::new()
            .recover(digest, signature)
            .map_err(|error| {
                // From T15, out-of-gas and other system errors propagate so that `verifyVoucher`
                // never reports an unperformed check as an invalid signature.
                if is_t15 && error.is_system_error() {
                    error
                } else {
                    TIP20ChannelReserveError::invalid_signature().into()
                }
            })?;
        if signer != expected_signer {
            return Err(TIP20ChannelReserveError::invalid_signature().into());
        }
        // No retirement check: migrating must not let the payer void vouchers the payee holds.
        Ok(())
    }

    /// Rejects a retired root key (TIP-1113) as the voucher signer for new deposit.
    ///
    /// Vouchers stay valid after their signer migrates, so a retired key keeps authority over
    /// funds already in its channels but must not gain authority over new funds.
    fn ensure_voucher_signer_active(&self, signer: Address) -> Result<()> {
        if self.storage.is_retired_root(signer)? {
            return Err(TIP20ChannelReserveError::root_key_retired(signer).into());
        }
        Ok(())
    }

    /// Computes the EIP-712 voucher digest.
    fn get_voucher_digest_inner(&self, channel_id: B256, cumulative_amount: U96) -> Result<B256> {
        voucher_digest_with(
            channel_id,
            cumulative_amount,
            self.storage.chain_id(),
            |data| self.storage.keccak256(data),
        )
    }
}

/// Returns the EIP-712 digest of a `cumulative_amount` voucher on `channel_id` for `chain_id`.
pub fn voucher_digest(channel_id: B256, cumulative_amount: U96, chain_id: u64) -> B256 {
    voucher_digest_with(channel_id, cumulative_amount, chain_id, |data| {
        Ok(keccak256(data))
    })
    .expect("plain keccak never fails")
}

/// Returns the EIP-712 voucher digest, hashing its struct and digest input with `keccak`.
pub fn voucher_digest_with(
    channel_id: B256,
    cumulative_amount: U96,
    chain_id: u64,
    keccak: impl Fn(&[u8]) -> Result<B256>,
) -> Result<B256> {
    let struct_hash = keccak(&(VOUCHER_TYPEHASH, channel_id, cumulative_amount).abi_encode())?;
    let mut input = [0u8; 66];
    input[0] = 0x19;
    input[1] = 0x01;
    input[2..34].copy_from_slice(domain_separator(chain_id).as_slice());
    input[34..66].copy_from_slice(struct_hash.as_slice());
    keccak(&input)
}

/// Returns the EIP-712 domain separator for chain `chain_id`, precomputed for mainnet and testnet.
fn domain_separator(chain_id: u64) -> B256 {
    match chain_id {
        MAINNET_CHAIN_ID => DOMAIN_SEPARATOR_MAINNET,
        MODERATO_CHAIN_ID => DOMAIN_SEPARATOR_TESTNET,
        chain_id => domain_separator_inner(chain_id),
    }
}

/// Returns the voucher signer's commitment at open, which the descriptor's salt holds, or zero if
/// the signer had none (TIP-1166).
fn opening_commitment(
    descriptor: &ITIP20ChannelReserve::ChannelDescriptor,
    state: PackedChannelState,
) -> B256 {
    if state.has_opening_commitment {
        descriptor.salt
    } else {
        B256::ZERO
    }
}

/// Computes a fixed-chain domain separator at compile time using ABI-padded fields.
const fn const_domain_separator(chain_id: u64) -> B256 {
    B256::new(
        Keccak256::new()
            .update(EIP712_DOMAIN_TYPEHASH.as_slice())
            .update(NAME_HASH.as_slice())
            .update(VERSION_HASH.as_slice())
            .update(&U256::from_limbs([chain_id, 0, 0, 0]).to_be_bytes::<32>())
            .update(&[0; 12])
            .update(&TIP20_CHANNEL_RESERVE_ADDRESS.into_array())
            .finalize(),
    )
}

/// Computes the EIP-712 domain separator.
///
/// NOTE: This keccak is unmetered because it is not computed at tx runtime.
fn domain_separator_inner(chain_id: u64) -> B256 {
    keccak256(
        (
            EIP712_DOMAIN_TYPEHASH,
            NAME_HASH,
            VERSION_HASH,
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
            TIP20Setup, TIP403Setup, VIRTUAL_MASTER, assert_full_coverage, check_selector_coverage,
            register_virtual_master, with_storage,
        },
        tip403_registry::{ALLOW_ALL_POLICY_ID, ITIP403Registry, TIP403Registry},
    };
    use alloy::{
        primitives::{Bytes, IntoLogData, Signature},
        sol_types::{SolCall, SolEvent},
    };
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{
        ITIP20ChannelReserve::ITIP20ChannelReserveCalls, TIP20Error,
    };
    use tempo_primitives::transaction::{
        ConfigurableAccountConfig, ConfigurableAccountOwner, ConfigurableAccountSignature,
        configurable_account_digest, tt_signature::PrimitiveSignature,
    };
    use test_case::test_case;

    #[test]
    fn const_domain_separators_match_abi_encoding() {
        assert_eq!(
            DOMAIN_SEPARATOR_MAINNET,
            domain_separator_inner(MAINNET_CHAIN_ID)
        );
        assert_eq!(
            DOMAIN_SEPARATOR_TESTNET,
            domain_separator_inner(MODERATO_CHAIN_ID)
        );
        for chain_id in [0, 1, 1337, u64::MAX] {
            assert_eq!(
                const_domain_separator(chain_id),
                domain_separator_inner(chain_id)
            );
        }
    }

    #[test_case(MAINNET_CHAIN_ID)]
    #[test_case(MODERATO_CHAIN_ID)]
    #[test_case(1337)]
    fn free_channel_id_and_voucher_digest_match_the_precompile(chain_id: u64) -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(chain_id);
        let descriptor = descriptor(
            Address::random(),
            Address::random(),
            Address::random(),
            Address::random(),
            B256::repeat_byte(0x01),
            Address::ZERO,
            B256::repeat_byte(0x02),
        );
        let cumulative_amount = U96::from(1_000);
        StorageCtx::enter(&mut storage, || {
            let reserve = TIP20ChannelReserve::new();
            let channel_id = reserve.channel_id(&descriptor)?;
            assert_eq!(descriptor.id(chain_id), channel_id);
            assert_eq!(
                voucher_digest(channel_id, cumulative_amount, chain_id),
                reserve.get_voucher_digest(ITIP20ChannelReserve::getVoucherDigestCall {
                    channelId: channel_id,
                    cumulativeAmount: cumulative_amount,
                })?
            );
            Ok(())
        })
    }

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

    fn install_blacklist_policy(token: &mut TIP20Token, admin: Address) -> Result<(u64, u64)> {
        let sender_policy = TIP403Setup::blacklist(admin).apply()?;
        let recipient_policy = TIP403Setup::blacklist(admin).apply()?;
        token.change_transfer_policy_id(
            admin,
            ITIP20::changeTransferPolicyIdCall {
                newPolicyId: TIP403Setup::compound(
                    sender_policy,
                    recipient_policy,
                    ALLOW_ALL_POLICY_ID,
                )
                .apply()?,
            },
        )?;
        Ok((sender_policy, recipient_policy))
    }

    fn set_blacklisted(
        admin: Address,
        policy_id: u64,
        account: Address,
        restricted: bool,
    ) -> Result<()> {
        TIP403Registry::new().modify_policy_blacklist(
            admin,
            ITIP403Registry::modifyPolicyBlacklistCall {
                policyId: policy_id,
                account,
                restricted,
            },
        )
    }

    fn install_recipient_whitelist_policy(
        token: &mut TIP20Token,
        admin: Address,
        recipients: &[Address],
    ) -> Result<()> {
        let recipient_policy = TIP403Setup::whitelist(admin)
            .with_members(recipients.iter().copied())
            .apply()?;
        let compound_policy =
            TIP403Setup::compound(ALLOW_ALL_POLICY_ID, recipient_policy, ALLOW_ALL_POLICY_ID)
                .apply()?;
        token.change_transfer_policy_id(
            admin,
            ITIP20::changeTransferPolicyIdCall {
                newPolicyId: compound_policy,
            },
        )
    }

    fn install_receive_sender_blacklist(receiver: Address, blocked_sender: Address) -> Result<u64> {
        let sender_policy = TIP403Setup::blacklist(receiver)
            .with_members([blocked_sender])
            .apply()?;
        TIP403Registry::new().set_receive_policy(
            receiver,
            ITIP403Registry::setReceivePolicyCall {
                senderPolicyId: sender_policy,
                tokenFilterId: ALLOW_ALL_POLICY_ID,
                recoveryAuthority: Address::ZERO,
            },
        )?;
        Ok(sender_policy)
    }

    #[test]
    fn test_selector_coverage() -> eyre::Result<()> {
        with_storage(TempoHardfork::T15, || {
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
            let mut reserve = TIP20ChannelReserve::initialized()?;

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
            let mut reserve = TIP20ChannelReserve::initialized()?;
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
    fn test_open_rejects_zone_deposit_address_payees_from_t15() -> eyre::Result<()> {
        let deposit_address = ZoneDepositAddress {
            zone_id: 1,
            version: 1,
            ciphertext: alloy::primitives::fixed_bytes!("010203040506"),
        }
        .encode();
        for (spec, rejected) in [(TempoHardfork::T14, false), (TempoHardfork::T15, true)] {
            let mut storage = HashMapStorageProvider::new_with_spec(1, spec);
            let payer = Address::random();
            StorageCtx::enter(&mut storage, || {
                let token = TIP20Setup::path_usd(payer)
                    .with_issuer(payer)
                    .with_mint(payer, U256::from(100u128))
                    .apply()?;
                let mut reserve = TIP20ChannelReserve::initialized()?;
                seed_expiring_nonce_hash(&mut reserve)?;
                let result = reserve.open(
                    payer,
                    open_call(
                        deposit_address,
                        Address::ZERO,
                        token.address(),
                        1,
                        B256::random(),
                        Address::ZERO,
                    ),
                );
                if rejected {
                    assert_eq!(
                        result.unwrap_err(),
                        TIP20ChannelReserveError::invalid_payee().into()
                    );
                } else {
                    assert!(
                        !matches!(&result, Err(err) if *err == TIP20ChannelReserveError::invalid_payee().into()),
                        "{result:?}"
                    );
                }
                eyre::Ok(())
            })?;
        }
        Ok(())
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
            let (_sender_policy, recipient_policy) = install_blacklist_policy(&mut token, admin)?;
            let (_, virtual_payee) = register_virtual_master(&mut AddressRegistry::new())?;
            let mut reserve = TIP20ChannelReserve::initialized()?;

            // Admission must check the effective recipient, not just the virtual alias.
            set_blacklisted(admin, recipient_policy, VIRTUAL_MASTER, true)?;
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
            set_blacklisted(admin, recipient_policy, VIRTUAL_MASTER, false)?;
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

            set_blacklisted(admin, recipient_policy, VIRTUAL_MASTER, true)?;
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
            let (sender_policy, recipient_policy) = install_blacklist_policy(&mut token, admin)?;
            let mut reserve = TIP20ChannelReserve::initialized()?;

            // A blocked recipient cannot be used as the payee for a new channel.
            set_blacklisted(admin, recipient_policy, payee, true)?;
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
            set_blacklisted(admin, recipient_policy, payee, false)?;
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
            set_blacklisted(admin, recipient_policy, payee, true)?;
            let res = reserve.top_up(
                payer,
                ITIP20ChannelReserve::topUpCall {
                    descriptor: descriptor.clone(),
                    additionalDeposit: U96::from(1),
                },
            );
            assert_eq!(res.unwrap_err(), TIP20Error::policy_forbids().into());

            // Once funded, vouchers cannot transmit new value if the payer is blocked.
            set_blacklisted(admin, recipient_policy, payee, false)?;
            set_blacklisted(admin, sender_policy, payer, true)?;
            let digest =
                reserve.get_voucher_digest(ITIP20ChannelReserve::getVoucherDigestCall {
                    channelId: channel_id,
                    cumulativeAmount: U96::from(10),
                })?;
            let signature = Bytes::from(payer_signer.sign_hash_sync(&digest)?.as_bytes());

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
    fn test_t12_recipient_restricted_token_supports_channel_capture_and_refund() -> eyre::Result<()>
    {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
        let payer_signer = PrivateKeySigner::random();
        let payer = payer_signer.address();
        let payee = Address::random();
        let stranger = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::path_usd(payer)
                .with_issuer(payer)
                .with_mint(payer, U256::from(1_000u128))
                .apply()?;
            install_recipient_whitelist_policy(&mut token, payer, &[payee])?;

            let mut reserve = TIP20ChannelReserve::initialized()?;

            // The reserve is not an authorized recipient, but the logical payer -> payee path is.
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

            reserve.top_up(
                payer,
                ITIP20ChannelReserve::topUpCall {
                    descriptor: descriptor.clone(),
                    additionalDeposit: U96::from(20),
                },
            )?;

            let digest =
                reserve.get_voucher_digest(ITIP20ChannelReserve::getVoucherDigestCall {
                    channelId: channel_id,
                    cumulativeAmount: U96::from(40),
                })?;
            let signature = Bytes::from(payer_signer.sign_hash_sync(&digest)?.as_bytes());
            reserve.settle(
                payee,
                ITIP20ChannelReserve::settleCall {
                    descriptor: descriptor.clone(),
                    cumulativeAmount: U96::from(40),
                    signature,
                },
            )?;

            // Exercise a positive capture delta and a refund in the same close.
            let close_digest =
                reserve.get_voucher_digest(ITIP20ChannelReserve::getVoucherDigestCall {
                    channelId: channel_id,
                    cumulativeAmount: U96::from(60),
                })?;
            let close_signature =
                Bytes::from(payer_signer.sign_hash_sync(&close_digest)?.as_bytes());
            reserve.close(
                payee,
                ITIP20ChannelReserve::closeCall {
                    descriptor,
                    cumulativeAmount: U96::from(60),
                    captureAmount: U96::from(60),
                    signature: close_signature,
                },
            )?;

            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: payer })?,
                U256::from(940u128)
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: payee })?,
                U256::from(60u128)
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: TIP20_CHANNEL_RESERVE_ADDRESS,
                })?,
                U256::ZERO
            );

            // The channel path does not weaken ordinary transfer restrictions.
            let result = token.transfer(
                payer,
                ITIP20::transferCall {
                    to: stranger,
                    amount: U256::ONE,
                },
            );
            assert_eq!(result.unwrap_err(), TIP20Error::policy_forbids().into());

            // A caller cannot use the reserve to route value to an unauthorized payee.
            seed_expiring_nonce_hash(&mut reserve)?;
            let result = reserve.open(
                payer,
                open_call(
                    stranger,
                    Address::ZERO,
                    token.address(),
                    1,
                    B256::random(),
                    Address::ZERO,
                ),
            );
            assert_eq!(result.unwrap_err(), TIP20Error::policy_forbids().into());

            Ok(())
        })
    }

    #[test]
    fn test_t12_funding_checks_payee_receive_policy() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
        let payer = Address::random();
        let payee = Address::random();

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::path_usd(payer)
                .with_issuer(payer)
                .with_mint(payer, U256::from(1_000u128))
                .apply()?;
            let mut reserve = TIP20ChannelReserve::initialized()?;

            let sender_policy = install_receive_sender_blacklist(payee, payer)?;

            let salt = B256::random();
            seed_expiring_nonce_hash(&mut reserve)?;
            let result = reserve.open(
                payer,
                open_call(
                    payee,
                    Address::ZERO,
                    token.address(),
                    100,
                    salt,
                    Address::ZERO,
                ),
            );
            assert_eq!(result.unwrap_err(), TIP20Error::policy_forbids().into());
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: payer })?,
                U256::from(1_000u128)
            );

            set_blacklisted(payee, sender_policy, payer, false)?;
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

            set_blacklisted(payee, sender_policy, payer, true)?;
            let result = reserve.top_up(
                payer,
                ITIP20ChannelReserve::topUpCall {
                    descriptor,
                    additionalDeposit: U96::from(1),
                },
            );
            assert_eq!(result.unwrap_err(), TIP20Error::policy_forbids().into());
            assert_eq!(
                reserve
                    .get_channel_state(ITIP20ChannelReserve::getChannelStateCall {
                        channelId: channel_id,
                    })?
                    .deposit,
                U96::from(100)
            );

            Ok(())
        })
    }

    #[test]
    fn test_packed_channel_state_word_direct_matches_storable() -> eyre::Result<()> {
        use crate::storage::{
            LayoutCtx, Storable as _, StorageCtx, StorageOps, hashmap::HashMapStorageProvider,
        };
        struct WordCapture(U256);
        impl StorageOps for WordCapture {
            fn load(&self, _slot: U256) -> Result<U256> {
                Ok(self.0)
            }
            fn store(&mut self, _slot: U256, value: U256) -> Result<()> {
                self.0 = value;
                Ok(())
            }
        }
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            for state in [
                PackedChannelState::default(),
                PackedChannelState {
                    settled: U96::from(0x1122_3344_5566_7788_99aa_bbcc_u128),
                    deposit: U96::from(0x0102_0304_0506_0708_090a_0b0c_u128),
                    close_requested_at: 0xdead_beef,
                    uses_logical_receive_policy_sender: true,
                    has_opening_commitment: false,
                },
                PackedChannelState {
                    settled: U96::ZERO,
                    deposit: U96::from(1u64),
                    close_requested_at: 0,
                    uses_logical_receive_policy_sender: true,
                    has_opening_commitment: true,
                },
            ] {
                let mut cap = WordCapture(U256::ZERO);
                state.store(&mut cap, U256::ZERO, LayoutCtx::FULL)?;
                assert_eq!(state.to_word_direct(), cap.0);
                assert_eq!(PackedChannelState::exists_in_word(cap.0), state.exists());
            }
            Ok(())
        })
    }

    #[test]
    fn test_channel_reserve_receive_policy_slot_matches_mapping_slot() {
        use crate::storage::StorageKey as _;
        assert_eq!(
            TIP20_CHANNEL_RESERVE_RECEIVE_POLICY_SLOT,
            TIP20_CHANNEL_RESERVE_ADDRESS
                .mapping_slot(crate::tip403_registry::slots::RECEIVE_POLICIES)
        );
    }

    #[test]
    fn test_t12_grandfathers_pre_t12_receive_policy_sender() -> eyre::Result<()> {
        assert_eq!(
            <PackedChannelState as crate::storage::StorableType>::SLOTS,
            1
        );

        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        let payer_signer = PrivateKeySigner::random();
        let payer = payer_signer.address();
        let payee = Address::random();

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::path_usd(payer)
                .with_issuer(payer)
                .with_mint(payer, U256::from(1_000u128))
                .apply()?;
            let mut reserve = TIP20ChannelReserve::initialized()?;

            // This payee accepts the reserve but not the individual payer, matching the policy
            // under which pre-T12 channel captures were funded.
            install_receive_sender_blacklist(payee, payer)?;

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

            StorageCtx.set_spec(TempoHardfork::T12);

            // Post-activation top-ups and captures retain the reserve sender for this channel.
            reserve.top_up(
                payer,
                ITIP20ChannelReserve::topUpCall {
                    descriptor: descriptor.clone(),
                    additionalDeposit: U96::from(20),
                },
            )?;

            let cumulative = U96::from(40);
            let digest =
                reserve.get_voucher_digest(ITIP20ChannelReserve::getVoucherDigestCall {
                    channelId: channel_id,
                    cumulativeAmount: cumulative,
                })?;
            let signature = Bytes::from(payer_signer.sign_hash_sync(&digest)?.as_bytes());
            reserve.settle(
                payee,
                ITIP20ChannelReserve::settleCall {
                    descriptor: descriptor.clone(),
                    cumulativeAmount: cumulative,
                    signature,
                },
            )?;

            let close_cumulative = U96::from(60);
            let close_digest =
                reserve.get_voucher_digest(ITIP20ChannelReserve::getVoucherDigestCall {
                    channelId: channel_id,
                    cumulativeAmount: close_cumulative,
                })?;
            let close_signature =
                Bytes::from(payer_signer.sign_hash_sync(&close_digest)?.as_bytes());
            reserve.close(
                payee,
                ITIP20ChannelReserve::closeCall {
                    descriptor,
                    cumulativeAmount: close_cumulative,
                    captureAmount: close_cumulative,
                    signature: close_signature,
                },
            )?;

            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: payer })?,
                U256::from(940u128)
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: payee })?,
                U256::from(60u128)
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: TIP20_CHANNEL_RESERVE_ADDRESS,
                })?,
                U256::ZERO
            );

            Ok(())
        })
    }

    #[test]
    fn test_t12_blocked_capture_reverts_and_remains_retryable() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
        let payer_signer = PrivateKeySigner::random();
        let payer = payer_signer.address();
        let payee = Address::random();

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::path_usd(payer)
                .with_issuer(payer)
                .with_mint(payer, U256::from(1_000u128))
                .apply()?;
            let mut reserve = TIP20ChannelReserve::initialized()?;

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

            // Receive policies remain mutable after funding. The payee now rejects only the
            // logical payer, while the physical reserve sender remains authorized.
            let sender_policy = install_receive_sender_blacklist(payee, payer)?;

            let cumulative = U96::from(40);
            let digest =
                reserve.get_voucher_digest(ITIP20ChannelReserve::getVoucherDigestCall {
                    channelId: channel_id,
                    cumulativeAmount: cumulative,
                })?;
            let signature = Bytes::from(payer_signer.sign_hash_sync(&digest)?.as_bytes());
            let result = reserve.settle(
                payee,
                ITIP20ChannelReserve::settleCall {
                    descriptor: descriptor.clone(),
                    cumulativeAmount: cumulative,
                    signature: signature.clone(),
                },
            );
            assert_eq!(result.unwrap_err(), TIP20Error::policy_forbids().into());

            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: payer })?,
                U256::from(900u128)
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: payee })?,
                U256::ZERO
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: TIP20_CHANNEL_RESERVE_ADDRESS,
                })?,
                U256::from(100u128)
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: crate::RECEIVE_POLICY_GUARD_ADDRESS,
                })?,
                U256::ZERO
            );
            assert_eq!(
                reserve
                    .get_channel_state(ITIP20ChannelReserve::getChannelStateCall {
                        channelId: channel_id
                    })?
                    .settled,
                U96::ZERO
            );

            let close_result = reserve.close(
                payee,
                ITIP20ChannelReserve::closeCall {
                    descriptor: descriptor.clone(),
                    cumulativeAmount: cumulative,
                    captureAmount: cumulative,
                    signature: signature.clone(),
                },
            );
            assert_eq!(
                close_result.unwrap_err(),
                TIP20Error::policy_forbids().into()
            );
            let state = reserve.get_channel_state(ITIP20ChannelReserve::getChannelStateCall {
                channelId: channel_id,
            })?;
            assert_eq!(state.deposit, U96::from(100));
            assert_eq!(state.settled, U96::ZERO);

            // Once the payee accepts the logical payer, the same voucher can settle.
            set_blacklisted(payee, sender_policy, payer, false)?;
            reserve.settle(
                payee,
                ITIP20ChannelReserve::settleCall {
                    descriptor,
                    cumulativeAmount: cumulative,
                    signature,
                },
            )?;
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: payee })?,
                U256::from(40u128)
            );
            assert_eq!(
                reserve
                    .get_channel_state(ITIP20ChannelReserve::getChannelStateCall {
                        channelId: channel_id
                    })?
                    .settled,
                cumulative
            );

            Ok(())
        })
    }

    #[test]
    fn test_t12_recipient_restricted_token_supports_unilateral_withdraw() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
        let payer = Address::random();
        let payee = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::path_usd(payer)
                .with_issuer(payer)
                .with_mint(payer, U256::from(100u128))
                .apply()?;
            install_recipient_whitelist_policy(&mut token, payer, &[payee])?;

            let mut reserve = TIP20ChannelReserve::initialized()?;
            reserve.storage.set_timestamp(U256::from(1_000u64));
            let salt = B256::random();
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
            let descriptor = descriptor(
                payer,
                payee,
                Address::ZERO,
                token.address(),
                salt,
                Address::ZERO,
                expiring_nonce_hash,
            );

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

            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: payer })?,
                U256::from(100u128)
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: TIP20_CHANNEL_RESERVE_ADDRESS,
                })?,
                U256::ZERO
            );
            Ok(())
        })
    }

    #[test]
    fn test_t12_blocked_refund_reverts_and_remains_retryable() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
        let payer = Address::random();
        let payee = Address::random();

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::path_usd(payer)
                .with_issuer(payer)
                .with_mint(payer, U256::from(1_000u128))
                .apply()?;
            let mut reserve = TIP20ChannelReserve::initialized()?;
            reserve.storage.set_timestamp(U256::from(1_000u64));

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
            reserve.request_close(
                payer,
                ITIP20ChannelReserve::requestCloseCall {
                    descriptor: descriptor.clone(),
                },
            )?;
            reserve
                .storage
                .set_timestamp(U256::from(1_000u64 + CLOSE_GRACE_PERIOD));

            // Originator recovery would make a guarded reserve-originated refund unclaimable.
            // Channel refunds reject the policy instead and leave channel state intact.
            let sender_policy =
                install_receive_sender_blacklist(payer, TIP20_CHANNEL_RESERVE_ADDRESS)?;

            let close_result = reserve.close(
                payee,
                ITIP20ChannelReserve::closeCall {
                    descriptor: descriptor.clone(),
                    cumulativeAmount: U96::ZERO,
                    captureAmount: U96::ZERO,
                    signature: Bytes::new(),
                },
            );
            assert_eq!(
                close_result.unwrap_err(),
                TIP20Error::policy_forbids().into()
            );

            let result = reserve.withdraw(
                payer,
                ITIP20ChannelReserve::withdrawCall {
                    descriptor: descriptor.clone(),
                },
            );
            assert_eq!(result.unwrap_err(), TIP20Error::policy_forbids().into());
            assert_eq!(
                reserve
                    .get_channel_state(ITIP20ChannelReserve::getChannelStateCall {
                        channelId: channel_id
                    })?
                    .deposit,
                U96::from(100)
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: payer })?,
                U256::from(900u128)
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: crate::RECEIVE_POLICY_GUARD_ADDRESS,
                })?,
                U256::ZERO
            );

            set_blacklisted(payer, sender_policy, TIP20_CHANNEL_RESERVE_ADDRESS, false)?;
            reserve.withdraw(payer, ITIP20ChannelReserve::withdrawCall { descriptor })?;
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: payer })?,
                U256::from(1_000u128)
            );
            assert!(
                reserve
                    .get_channel_state(ITIP20ChannelReserve::getChannelStateCall {
                        channelId: channel_id
                    })?
                    .deposit
                    .is_zero()
            );

            Ok(())
        })
    }

    #[test]
    fn test_pre_t12_recipient_restricted_token_cannot_fund_reserve() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        let payer = Address::random();
        let payee = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::path_usd(payer)
                .with_issuer(payer)
                .with_mint(payer, U256::from(100u128))
                .apply()?;
            install_recipient_whitelist_policy(&mut token, payer, &[payee])?;

            let mut reserve = TIP20ChannelReserve::initialized()?;
            seed_expiring_nonce_hash(&mut reserve)?;
            let result = reserve.open(
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
            assert_eq!(result.unwrap_err(), TIP20Error::policy_forbids().into());
            Ok(())
        })
    }

    #[test]
    fn test_pre_t12_settle_preserves_state_write_before_transfer_failure() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        let payer_signer = PrivateKeySigner::random();
        let payer = payer_signer.address();
        let payee = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::path_usd(payer)
                .with_issuer(payer)
                .with_role(payer, TIP20Token::pause_role())
                .with_mint(payer, U256::from(100u128))
                .apply()?;
            let mut reserve = TIP20ChannelReserve::initialized()?;

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
            let cumulative = U96::from(40);
            let digest =
                reserve.get_voucher_digest(ITIP20ChannelReserve::getVoucherDigestCall {
                    channelId: channel_id,
                    cumulativeAmount: cumulative,
                })?;
            let signature = Bytes::from(payer_signer.sign_hash_sync(&digest)?.as_bytes());

            token.pause(payer, ITIP20::pauseCall {})?;
            let result = reserve.settle(
                payee,
                ITIP20ChannelReserve::settleCall {
                    descriptor,
                    cumulativeAmount: cumulative,
                    signature,
                },
            );
            assert_eq!(result.unwrap_err(), TIP20Error::contract_paused().into());

            // Direct unit calls do not apply EVM rollback, exposing the intermediate write and
            // pinning its position before the failing transfer. On-chain the whole call reverts.
            assert_eq!(
                reserve
                    .get_channel_state(ITIP20ChannelReserve::getChannelStateCall {
                        channelId: channel_id
                    })?
                    .settled,
                cumulative
            );
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

            let mut reserve = TIP20ChannelReserve::initialized()?;
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
            let signature = Bytes::from(payer_signer.sign_hash_sync(&digest)?.as_bytes());

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
                Bytes::from(payer_signer.sign_hash_sync(&close_digest)?.as_bytes());
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
            let mut reserve = TIP20ChannelReserve::initialized()?;

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
            let mut reserve = TIP20ChannelReserve::initialized()?;

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
            let signature = Bytes::from(payer_signer.sign_hash_sync(&digest)?.as_bytes());

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
                    signature: Signature::test_signature().as_bytes().into(),
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
            let mut reserve = TIP20ChannelReserve::initialized()?;

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
            let signature = Bytes::from(payer_signer.sign_hash_sync(&digest)?.as_bytes());

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
                    signature: Signature::test_signature().as_bytes().into(),
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
            let mut reserve = TIP20ChannelReserve::initialized()?;

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
            let mut reserve = TIP20ChannelReserve::initialized()?;

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
        with_storage(TempoHardfork::T5, || {
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
            assert!(matches!(result, Err(evm2::PrecompileError::Revert(_))));
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
            let mut reserve = TIP20ChannelReserve::initialized()?;
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
            let mut reserve = TIP20ChannelReserve::initialized()?;
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
            let mut reserve = TIP20ChannelReserve::initialized()?;
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
            let mut reserve = TIP20ChannelReserve::initialized()?;
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

    /// A configuration of `owners` at `version`, each of weight one.
    fn owner_config(
        owners: &[&PrivateKeySigner],
        threshold: u8,
        version: u64,
    ) -> ConfigurableAccountConfig {
        let mut owners: Vec<_> = owners
            .iter()
            .map(|owner| ConfigurableAccountOwner {
                owner: owner.address(),
                weight: 1,
            })
            .collect();
        owners.sort_by_key(|owner| owner.owner);
        ConfigurableAccountConfig {
            salt: B256::ZERO,
            version,
            threshold,
            owners,
        }
    }

    /// Registers or rotates `account` to `config`.
    fn commit(account: Address, config: &ConfigurableAccountConfig) -> eyre::Result<B256> {
        let commitment = config.commitment().unwrap();
        StorageCtx.set_config_commitment(
            account,
            commitment,
            crate::storage::ConfigCommitmentWriteGas::Precompile,
        )?;
        Ok(commitment)
    }

    /// A configurable account voucher of `account` under `config`, approved by `approvers`.
    fn configurable_voucher(
        reserve: &TIP20ChannelReserve,
        channel_id: B256,
        amount: u64,
        account: Address,
        config: &ConfigurableAccountConfig,
        approvers: &[&PrivateKeySigner],
    ) -> eyre::Result<Bytes> {
        let digest = reserve.get_voucher_digest(ITIP20ChannelReserve::getVoucherDigestCall {
            channelId: channel_id,
            cumulativeAmount: U96::from(amount),
        })?;
        let digest = configurable_account_digest(digest, account, config.version);
        // Owner approvals must be in ascending owner order.
        let mut approvers = approvers.to_vec();
        approvers.sort_by_key(|approver| approver.address());
        let approvals = approvers
            .iter()
            .map(|approver| {
                Ok(PrimitiveSignature::Secp256k1(
                    approver.sign_hash_sync(&digest)?,
                ))
            })
            .collect::<eyre::Result<_>>()?;
        Ok(TempoSignature::ConfigurableAccount(
            ConfigurableAccountSignature::try_new(account, config.clone(), approvals).unwrap(),
        )
        .to_bytes())
    }

    /// A primitive voucher of `key`.
    fn primitive_voucher(
        reserve: &TIP20ChannelReserve,
        channel_id: B256,
        amount: u64,
        key: &PrivateKeySigner,
    ) -> eyre::Result<Bytes> {
        let digest = reserve.get_voucher_digest(ITIP20ChannelReserve::getVoucherDigestCall {
            channelId: channel_id,
            cumulativeAmount: U96::from(amount),
        })?;
        Ok(Bytes::from(key.sign_hash_sync(&digest)?.as_bytes()))
    }

    fn settle_call(
        descriptor: &ITIP20ChannelReserve::ChannelDescriptor,
        amount: u64,
        signature: Bytes,
    ) -> ITIP20ChannelReserve::settleCall {
        ITIP20ChannelReserve::settleCall {
            descriptor: descriptor.clone(),
            cumulativeAmount: U96::from(amount),
            signature,
        }
    }

    fn verify_call(
        descriptor: &ITIP20ChannelReserve::ChannelDescriptor,
        amount: u64,
        signature: Bytes,
    ) -> ITIP20ChannelReserve::verifyVoucherCall {
        ITIP20ChannelReserve::verifyVoucherCall {
            descriptor: descriptor.clone(),
            cumulativeAmount: U96::from(amount),
            signature,
        }
    }

    fn top_up_call(
        descriptor: &ITIP20ChannelReserve::ChannelDescriptor,
        amount: u64,
    ) -> ITIP20ChannelReserve::topUpCall {
        ITIP20ChannelReserve::topUpCall {
            descriptor: descriptor.clone(),
            additionalDeposit: U96::from(amount),
        }
    }

    #[test]
    fn test_t15_configurable_payer_vouchers_survive_owner_rotation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
        let (old_owner, new_owner) = (PrivateKeySigner::random(), PrivateKeySigner::random());
        let old_config = owner_config(&[&old_owner], 1, 0);
        let payer = old_config.derive_account().unwrap();
        let payee = Address::random();

        StorageCtx::enter(&mut storage, || {
            let commitment = commit(payer, &old_config)?;
            let salt = commitment;
            let token = TIP20Setup::path_usd(payee)
                .with_issuer(payee)
                .with_mint(payer, U256::from(1_000u128))
                .apply()?;
            let mut reserve = TIP20ChannelReserve::new();
            reserve.initialize()?;
            let expiring_nonce_hash = seed_expiring_nonce_hash(&mut reserve)?;

            // From T15 a committed payer can open a channel whose salt is its commitment.
            assert_eq!(
                reserve.open(
                    payer,
                    open_call(
                        payee,
                        Address::ZERO,
                        token.address(),
                        100,
                        B256::random(),
                        Address::ZERO,
                    ),
                ),
                Err(TIP20ChannelReserveError::salt_not_signer_commitment(payer, commitment).into())
            );
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
            assert_eq!(
                StorageCtx.get_events(TIP20_CHANNEL_RESERVE_ADDRESS).last(),
                Some(
                    &TIP20ChannelReserveEvent::OpeningCommitmentRecorded(
                        ITIP20ChannelReserve::OpeningCommitmentRecorded {
                            channelId: channel_id,
                            signer: payer,
                            commitment,
                        }
                    )
                    .into_log_data()
                )
            );
            let descriptor = descriptor(
                payer,
                payee,
                Address::ZERO,
                token.address(),
                salt,
                Address::ZERO,
                expiring_nonce_hash,
            );

            // The old owners sign a voucher, then the payer rotates them out.
            let held =
                configurable_voucher(&reserve, channel_id, 60, payer, &old_config, &[&old_owner])?;
            let new_config = owner_config(&[&new_owner], 1, 1);
            commit(payer, &new_config)?;

            // The voucher the payee holds stays redeemable.
            assert!(reserve.verify_voucher(verify_call(&descriptor, 60, held.clone()))?);
            reserve.settle(payee, settle_call(&descriptor, 60, held))?;
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: payee })?,
                U256::from(60)
            );

            // Neither the new configuration nor a bare owner key signs for the channel.
            let rejected = [
                configurable_voucher(&reserve, channel_id, 70, payer, &new_config, &[&new_owner])?,
                primitive_voucher(&reserve, channel_id, 70, &old_owner)?,
            ];
            for signature in rejected {
                assert!(!reserve.verify_voucher(verify_call(
                    &descriptor,
                    70,
                    signature.clone()
                ))?);
                assert_eq!(
                    reserve.settle(payee, settle_call(&descriptor, 70, signature)),
                    Err(TIP20ChannelReserveError::invalid_signature().into())
                );
            }

            // Old owners gain no authority over new funds; a zero top-up still works.
            assert_eq!(
                reserve.top_up(payer, top_up_call(&descriptor, 10)),
                Err(TIP20ChannelReserveError::signer_config_changed(payer).into())
            );
            reserve.top_up(payer, top_up_call(&descriptor, 0))?;

            // Closing deletes the channel state, including its opening-commitment flag.
            let signature =
                configurable_voucher(&reserve, channel_id, 80, payer, &old_config, &[&old_owner])?;
            reserve.close(
                payee,
                ITIP20ChannelReserve::closeCall {
                    descriptor,
                    cumulativeAmount: U96::from(80),
                    captureAmount: U96::from(80),
                    signature,
                },
            )?;
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: payee })?,
                U256::from(80)
            );
            Ok(())
        })
    }

    #[test]
    fn test_t15_unregistered_signer_vouchers() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
        let payer = Address::random();
        let payee = Address::random();
        let salt = B256::random();
        let (owner, other) = (PrivateKeySigner::random(), PrivateKeySigner::random());
        let config = owner_config(&[&owner, &other], 2, 0);
        let signer = config.derive_account().unwrap();

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::path_usd(payee)
                .with_issuer(payee)
                .with_mint(payer, U256::from(1_000u128))
                .apply()?;
            let mut reserve = TIP20ChannelReserve::new();
            reserve.initialize()?;
            let expiring_nonce_hash = seed_expiring_nonce_hash(&mut reserve)?;
            let channel_id = reserve.open(
                payer,
                open_call(payee, Address::ZERO, token.address(), 100, salt, signer),
            )?;
            // An unregistered signer has no commitment, so any salt opens.
            assert!(
                !StorageCtx
                    .get_events(TIP20_CHANNEL_RESERVE_ADDRESS)
                    .iter()
                    .any(|log| log.topics().first()
                        == Some(&ITIP20ChannelReserve::OpeningCommitmentRecorded::SIGNATURE_HASH))
            );
            let descriptor = descriptor(
                payer,
                payee,
                Address::ZERO,
                token.address(),
                salt,
                signer,
                expiring_nonce_hash,
            );

            // Below the threshold, under a configuration that doesn't derive the signer, or from
            // an owner key alone, the voucher is invalid.
            let other_config = owner_config(&[&owner], 1, 0);
            let rejected = [
                configurable_voucher(&reserve, channel_id, 30, signer, &config, &[&owner])?,
                configurable_voucher(&reserve, channel_id, 30, signer, &other_config, &[&owner])?,
                primitive_voucher(&reserve, channel_id, 30, &owner)?,
            ];
            for signature in rejected {
                assert!(!reserve.verify_voucher(verify_call(
                    &descriptor,
                    30,
                    signature.clone()
                ))?);
                assert_eq!(
                    reserve.settle(payee, settle_call(&descriptor, 30, signature)),
                    Err(TIP20ChannelReserveError::invalid_signature().into())
                );
            }

            // The version-0 configuration deriving the signer's address signs.
            let signature =
                configurable_voucher(&reserve, channel_id, 30, signer, &config, &[&owner, &other])?;
            assert!(reserve.verify_voucher(verify_call(&descriptor, 30, signature.clone()))?);
            reserve.settle(payee, settle_call(&descriptor, 30, signature))?;

            // Registering later blocks new deposits, even with the same owners, but keeps vouchers.
            commit(signer, &config)?;
            assert_eq!(
                reserve.top_up(payer, top_up_call(&descriptor, 10)),
                Err(TIP20ChannelReserveError::root_key_retired(signer).into())
            );
            let signature =
                configurable_voucher(&reserve, channel_id, 50, signer, &config, &[&owner, &other])?;
            reserve.settle(payee, settle_call(&descriptor, 50, signature))?;
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: payee })?,
                U256::from(50)
            );
            Ok(())
        })
    }

    #[test]
    fn test_verify_voucher_selector_rejected_before_t15() -> eyre::Result<()> {
        use alloy::sol_types::SolError;
        with_storage(TempoHardfork::T14, || {
            let calldata = verify_call(
                &descriptor(
                    Address::random(),
                    Address::random(),
                    Address::ZERO,
                    Address::random(),
                    B256::random(),
                    Address::ZERO,
                    B256::random(),
                ),
                1,
                Bytes::new(),
            )
            .abi_encode();
            let result = TIP20ChannelReserve::new().call(&calldata, Address::ZERO);
            assert!(
                tempo_contracts::precompiles::UnknownFunctionSelector::abi_decode(
                    crate::test_util::revert_bytes(&result)
                )
                .is_ok(),
                "verifyVoucher should be selector-gated before T15"
            );
            Ok(())
        })
    }

    #[test]
    fn test_t15_verify_voucher_missing_channel() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
        StorageCtx::enter(&mut storage, || {
            let mut reserve = TIP20ChannelReserve::new();
            reserve.initialize()?;
            let missing = descriptor(
                Address::random(),
                Address::random(),
                Address::ZERO,
                Address::random(),
                B256::random(),
                Address::ZERO,
                B256::random(),
            );
            assert_eq!(
                reserve.verify_voucher(verify_call(&missing, 1, Bytes::new())),
                Err(TIP20ChannelReserveError::channel_not_found().into())
            );
            Ok(())
        })
    }

    #[test]
    fn test_t14_open_rejects_committed_signer() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
        let owner = PrivateKeySigner::random();
        let config = owner_config(&[&owner], 1, 0);
        let payer = config.derive_account().unwrap();
        let payee = Address::random();

        StorageCtx::enter(&mut storage, || {
            commit(payer, &config)?;
            let token = TIP20Setup::path_usd(payee)
                .with_issuer(payee)
                .with_mint(payer, U256::from(1_000u128))
                .apply()?;
            let mut reserve = TIP20ChannelReserve::new();
            reserve.initialize()?;
            seed_expiring_nonce_hash(&mut reserve)?;
            assert_eq!(
                reserve.open(
                    payer,
                    open_call(
                        payee,
                        Address::ZERO,
                        token.address(),
                        100,
                        B256::random(),
                        Address::ZERO
                    ),
                ),
                Err(TIP20ChannelReserveError::root_key_retired(payer).into())
            );
            Ok(())
        })
    }

    #[test]
    fn test_t15_committed_channel_uses_one_slot_and_withdraws_after_rotation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
        let owner = PrivateKeySigner::random();
        let config = owner_config(&[&owner], 1, 0);
        let payer = config.derive_account().unwrap();
        let payee = Address::random();

        StorageCtx::enter(&mut storage, || {
            let commitment = commit(payer, &config)?;
            let token = TIP20Setup::path_usd(payee)
                .with_issuer(payee)
                .with_mint(payer, U256::from(1_000u128))
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
                    commitment,
                    Address::ZERO,
                ),
            )?;
            let descriptor = descriptor(
                payer,
                payee,
                Address::ZERO,
                token.address(),
                commitment,
                Address::ZERO,
                expiring_nonce_hash,
            );

            // After a rotation the unchanged descriptor still finds the channel, so the payer
            // can withdraw, and deleting it returns the single slot's credit.
            commit(payer, &owner_config(&[&PrivateKeySigner::random()], 1, 1))?;
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
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: payer })?,
                U256::from(1_000)
            );
            assert_eq!(reserve.storage_credits(payer)?, 1);
            Ok(())
        })
    }
}
