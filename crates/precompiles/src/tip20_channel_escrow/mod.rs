//! TIP-1034 TIP-20 channel escrow precompile.

pub mod dispatch;

use crate::{
    error::Result,
    signature_verifier::SignatureVerifier,
    storage::{Handler, Mapping},
    tip20::{TIP20Token, is_tip20_prefix},
};
use alloy::{
    primitives::{Address, B256, U256, aliases::U96, keccak256},
    sol_types::SolValue,
};
use std::sync::LazyLock;
pub use tempo_contracts::precompiles::{
    ITIP20ChannelEscrow, TIP20_CHANNEL_ESCROW_ADDRESS, TIP20ChannelEscrowError,
    TIP20ChannelEscrowEvent,
};
use tempo_precompiles_macros::{Storable, contract};

/// 15 minute grace period between `requestClose` and `withdraw`.
pub const CLOSE_GRACE_PERIOD: u64 = 15 * 60;

static VOUCHER_TYPEHASH: LazyLock<B256> =
    LazyLock::new(|| keccak256(b"Voucher(bytes32 channelId,uint96 cumulativeAmount)"));
static EIP712_DOMAIN_TYPEHASH: LazyLock<B256> = LazyLock::new(|| {
    keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
});
static NAME_HASH: LazyLock<B256> = LazyLock::new(|| keccak256(b"TIP20 Channel Escrow"));
static VERSION_HASH: LazyLock<B256> = LazyLock::new(|| keccak256(b"1"));

#[derive(Debug, Clone, Copy, Default, Storable)]
struct PackedChannelState {
    settled: U96,
    deposit: U96,
    close_requested_at: u32,
}

impl PackedChannelState {
    fn exists(self) -> bool {
        !self.deposit.is_zero()
    }

    fn close_requested_at(self) -> Option<u32> {
        (self.close_requested_at != 0).then_some(self.close_requested_at)
    }

    fn to_sol(self) -> ITIP20ChannelEscrow::ChannelState {
        ITIP20ChannelEscrow::ChannelState {
            settled: self.settled,
            deposit: self.deposit,
            closeRequestedAt: self.close_requested_at,
        }
    }
}

#[contract(addr = TIP20_CHANNEL_ESCROW_ADDRESS)]
pub struct TIP20ChannelEscrow {
    channel_states: Mapping<B256, PackedChannelState>,

    // WARNING: transient storage slots must remain after persistent storage fields until the
    // `contract` macro supports independent persistent/transient layouts.
    opened_this_tx: Mapping<B256, bool>,
    channel_open_context_hash: B256,
}

impl TIP20ChannelEscrow {
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

    pub fn open(
        &mut self,
        msg_sender: Address,
        call: ITIP20ChannelEscrow::openCall,
    ) -> Result<B256> {
        if call.payee == Address::ZERO {
            return Err(TIP20ChannelEscrowError::invalid_payee().into());
        }
        if !is_tip20_prefix(call.token) {
            return Err(TIP20ChannelEscrowError::invalid_token().into());
        }

        let deposit = call.deposit;
        if deposit.is_zero() {
            return Err(TIP20ChannelEscrowError::zero_deposit().into());
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
            return Err(TIP20ChannelEscrowError::channel_already_exists().into());
        }

        let batch = self.storage.checkpoint();
        self.channel_states[channel_id].write(PackedChannelState {
            settled: U96::ZERO,
            deposit,
            close_requested_at: 0,
        })?;
        TIP20Token::from_address(call.token)?.system_transfer_from(
            msg_sender,
            self.address,
            U256::from(call.deposit),
        )?;
        self.opened_this_tx[channel_id].t_write(true)?;
        self.emit_event(TIP20ChannelEscrowEvent::ChannelOpened(
            ITIP20ChannelEscrow::ChannelOpened {
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
        batch.commit();

        Ok(channel_id)
    }

    pub fn settle(
        &mut self,
        msg_sender: Address,
        call: ITIP20ChannelEscrow::settleCall,
    ) -> Result<()> {
        let channel_id = self.channel_id(&call.descriptor)?;
        let mut state = self.load_existing_state(channel_id)?;

        if msg_sender != call.descriptor.payee
            && (call.descriptor.operator.is_zero() || msg_sender != call.descriptor.operator)
        {
            return Err(TIP20ChannelEscrowError::not_payee_or_operator().into());
        }

        let cumulative = call.cumulativeAmount;
        if cumulative > state.deposit {
            return Err(TIP20ChannelEscrowError::amount_exceeds_deposit().into());
        }
        if cumulative <= state.settled {
            return Err(TIP20ChannelEscrowError::amount_not_increasing().into());
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

        let batch = self.storage.checkpoint();
        state.settled = cumulative;
        self.channel_states[channel_id].write(state)?;
        TIP20Token::from_address(call.descriptor.token)?.system_transfer_from(
            self.address,
            call.descriptor.payee,
            U256::from(delta),
        )?;
        self.emit_event(TIP20ChannelEscrowEvent::Settled(
            ITIP20ChannelEscrow::Settled {
                channelId: channel_id,
                payer: call.descriptor.payer,
                payee: call.descriptor.payee,
                cumulativeAmount: call.cumulativeAmount,
                deltaPaid: delta.into(),
                newSettled: cumulative.into(),
            },
        ))?;
        batch.commit();

        Ok(())
    }

    pub fn top_up(
        &mut self,
        msg_sender: Address,
        call: ITIP20ChannelEscrow::topUpCall,
    ) -> Result<()> {
        let channel_id = self.channel_id(&call.descriptor)?;
        let mut state = self.load_existing_state(channel_id)?;

        if msg_sender != call.descriptor.payer {
            return Err(TIP20ChannelEscrowError::not_payer().into());
        }

        let additional = call.additionalDeposit;
        let next_deposit = state
            .deposit
            .checked_add(additional)
            .ok_or_else(TIP20ChannelEscrowError::deposit_overflow)?;

        let had_close_request = state.close_requested_at().is_some();
        let batch = self.storage.checkpoint();

        if !additional.is_zero() {
            state.deposit = next_deposit;
            TIP20Token::from_address(call.descriptor.token)?.system_transfer_from(
                msg_sender,
                self.address,
                U256::from(call.additionalDeposit),
            )?;
        }
        if had_close_request {
            state.close_requested_at = 0;
        }

        self.channel_states[channel_id].write(state)?;
        if had_close_request {
            self.emit_event(TIP20ChannelEscrowEvent::CloseRequestCancelled(
                ITIP20ChannelEscrow::CloseRequestCancelled {
                    channelId: channel_id,
                    payer: call.descriptor.payer,
                    payee: call.descriptor.payee,
                },
            ))?;
        }
        self.emit_event(TIP20ChannelEscrowEvent::TopUp(ITIP20ChannelEscrow::TopUp {
            channelId: channel_id,
            payer: call.descriptor.payer,
            payee: call.descriptor.payee,
            additionalDeposit: call.additionalDeposit,
            newDeposit: state.deposit,
        }))?;
        batch.commit();

        Ok(())
    }

    pub fn request_close(
        &mut self,
        msg_sender: Address,
        call: ITIP20ChannelEscrow::requestCloseCall,
    ) -> Result<()> {
        let channel_id = self.channel_id(&call.descriptor)?;
        let mut state = self.load_existing_state(channel_id)?;

        if msg_sender != call.descriptor.payer {
            return Err(TIP20ChannelEscrowError::not_payer().into());
        }
        if state.close_requested_at().is_some() {
            return Ok(());
        }

        let close_requested_at = self.now_u32();
        let batch = self.storage.checkpoint();
        state.close_requested_at = close_requested_at;
        self.channel_states[channel_id].write(state)?;
        self.emit_event(TIP20ChannelEscrowEvent::CloseRequested(
            ITIP20ChannelEscrow::CloseRequested {
                channelId: channel_id,
                payer: call.descriptor.payer,
                payee: call.descriptor.payee,
                closeGraceEnd: U256::from(self.now() + CLOSE_GRACE_PERIOD),
            },
        ))?;
        batch.commit();

        Ok(())
    }

    pub fn close(
        &mut self,
        msg_sender: Address,
        call: ITIP20ChannelEscrow::closeCall,
    ) -> Result<()> {
        let channel_id = self.channel_id(&call.descriptor)?;
        let state = self.load_existing_state(channel_id)?;

        if msg_sender != call.descriptor.payee {
            return Err(TIP20ChannelEscrowError::not_payee().into());
        }

        let cumulative = call.cumulativeAmount;
        let capture = call.captureAmount;
        let previous_settled = state.settled;
        if capture < previous_settled || capture > cumulative {
            return Err(TIP20ChannelEscrowError::capture_amount_invalid().into());
        }
        if capture > state.deposit {
            return Err(TIP20ChannelEscrowError::amount_exceeds_deposit().into());
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

        let batch = self.storage.checkpoint();
        self.channel_states[channel_id].delete()?;

        let mut token = TIP20Token::from_address(call.descriptor.token)?;
        if !delta.is_zero() {
            token.system_transfer_from(self.address, call.descriptor.payee, U256::from(delta))?;
        }
        if !refund.is_zero() {
            token.system_transfer_from(self.address, call.descriptor.payer, U256::from(refund))?;
        }

        self.emit_event(TIP20ChannelEscrowEvent::ChannelClosed(
            ITIP20ChannelEscrow::ChannelClosed {
                channelId: channel_id,
                payer: call.descriptor.payer,
                payee: call.descriptor.payee,
                settledToPayee: capture.into(),
                refundedToPayer: refund.into(),
            },
        ))?;
        batch.commit();

        Ok(())
    }

    pub fn withdraw(
        &mut self,
        msg_sender: Address,
        call: ITIP20ChannelEscrow::withdrawCall,
    ) -> Result<()> {
        let channel_id = self.channel_id(&call.descriptor)?;
        let state = self.load_existing_state(channel_id)?;

        if msg_sender != call.descriptor.payer {
            return Err(TIP20ChannelEscrowError::not_payer().into());
        }

        let close_ready = state
            .close_requested_at()
            .is_some_and(|requested_at| self.now() >= requested_at as u64 + CLOSE_GRACE_PERIOD);
        if !close_ready {
            return Err(TIP20ChannelEscrowError::close_not_ready().into());
        }

        let refund = state
            .deposit
            .checked_sub(state.settled)
            .expect("settled is always <= deposit");

        let batch = self.storage.checkpoint();
        self.channel_states[channel_id].delete()?;
        if !refund.is_zero() {
            TIP20Token::from_address(call.descriptor.token)?.system_transfer_from(
                self.address,
                call.descriptor.payer,
                U256::from(refund),
            )?;
        }
        self.emit_event(TIP20ChannelEscrowEvent::ChannelClosed(
            ITIP20ChannelEscrow::ChannelClosed {
                channelId: channel_id,
                payer: call.descriptor.payer,
                payee: call.descriptor.payee,
                settledToPayee: state.settled,
                refundedToPayer: refund.into(),
            },
        ))?;
        batch.commit();

        Ok(())
    }

    pub fn get_channel(
        &self,
        call: ITIP20ChannelEscrow::getChannelCall,
    ) -> Result<ITIP20ChannelEscrow::Channel> {
        let channel_id = self.channel_id(&call.descriptor)?;
        Ok(ITIP20ChannelEscrow::Channel {
            descriptor: call.descriptor,
            state: self.channel_states[channel_id].read()?.to_sol(),
        })
    }

    pub fn get_channel_state(
        &self,
        call: ITIP20ChannelEscrow::getChannelStateCall,
    ) -> Result<ITIP20ChannelEscrow::ChannelState> {
        Ok(self.channel_states[call.channelId].read()?.to_sol())
    }

    pub fn get_channel_states_batch(
        &self,
        call: ITIP20ChannelEscrow::getChannelStatesBatchCall,
    ) -> Result<Vec<ITIP20ChannelEscrow::ChannelState>> {
        call.channelIds
            .into_iter()
            .map(|channel_id| {
                self.channel_states[channel_id]
                    .read()
                    .map(PackedChannelState::to_sol)
            })
            .collect()
    }

    pub fn compute_channel_id(
        &self,
        call: ITIP20ChannelEscrow::computeChannelIdCall,
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

    pub fn get_voucher_digest(
        &self,
        call: ITIP20ChannelEscrow::getVoucherDigestCall,
    ) -> Result<B256> {
        self.get_voucher_digest_inner(call.channelId, call.cumulativeAmount)
    }

    pub fn domain_separator(&self) -> Result<B256> {
        self.domain_separator_inner()
    }

    fn now(&self) -> u64 {
        self.storage.timestamp().saturating_to::<u64>()
    }

    fn now_u32(&self) -> u32 {
        self.storage.timestamp().saturating_to::<u32>()
    }

    fn channel_id(&self, descriptor: &ITIP20ChannelEscrow::ChannelDescriptor) -> Result<B256> {
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

    fn enclosing_channel_open_context_hash(&self) -> Result<B256> {
        let hash = self.channel_open_context_hash.t_read()?;
        if hash.is_zero() {
            return Err(TIP20ChannelEscrowError::expiring_nonce_hash_not_set().into());
        }
        Ok(hash)
    }

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

    fn load_existing_state(&self, channel_id: B256) -> Result<PackedChannelState> {
        let state = self.channel_states[channel_id].read()?;
        if !state.exists() {
            return Err(TIP20ChannelEscrowError::channel_not_found().into());
        }
        Ok(state)
    }

    fn expected_signer(&self, descriptor: &ITIP20ChannelEscrow::ChannelDescriptor) -> Address {
        if descriptor.authorizedSigner.is_zero() {
            descriptor.payer
        } else {
            descriptor.authorizedSigner
        }
    }

    fn validate_voucher(
        &self,
        descriptor: &ITIP20ChannelEscrow::ChannelDescriptor,
        channel_id: B256,
        cumulative_amount: U96,
        signature: &alloy::primitives::Bytes,
    ) -> Result<()> {
        let digest = self.get_voucher_digest_inner(channel_id, cumulative_amount)?;
        let signer = SignatureVerifier::new()
            .recover(digest, signature.clone())
            .map_err(|_| TIP20ChannelEscrowError::invalid_signature())?;
        if signer != self.expected_signer(descriptor) {
            return Err(TIP20ChannelEscrowError::invalid_signature().into());
        }
        Ok(())
    }

    fn get_voucher_digest_inner(&self, channel_id: B256, cumulative_amount: U96) -> Result<B256> {
        let struct_hash = self
            .storage
            .keccak256(&(*VOUCHER_TYPEHASH, channel_id, cumulative_amount).abi_encode())?;
        let domain_separator = self.domain_separator_inner()?;

        let mut digest_input = [0u8; 66];
        digest_input[0] = 0x19;
        digest_input[1] = 0x01;
        digest_input[2..34].copy_from_slice(domain_separator.as_slice());
        digest_input[34..66].copy_from_slice(struct_hash.as_slice());
        self.storage.keccak256(&digest_input)
    }

    fn domain_separator_inner(&self) -> Result<B256> {
        self.storage.keccak256(
            &(
                *EIP712_DOMAIN_TYPEHASH,
                *NAME_HASH,
                *VERSION_HASH,
                U256::from(self.storage.chain_id()),
                self.address,
            )
                .abi_encode(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Precompile,
        storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{TIP20Setup, assert_full_coverage, check_selector_coverage},
    };
    use alloy::{
        primitives::{Bytes, Signature},
        sol_types::SolCall,
    };
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::ITIP20ChannelEscrow::ITIP20ChannelEscrowCalls;

    fn abi_u96(value: u128) -> U96 {
        U96::from(value)
    }

    fn descriptor(
        payer: Address,
        payee: Address,
        operator: Address,
        token: Address,
        salt: B256,
        authorized_signer: Address,
        expiring_nonce_hash: B256,
    ) -> ITIP20ChannelEscrow::ChannelDescriptor {
        ITIP20ChannelEscrow::ChannelDescriptor {
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
    ) -> ITIP20ChannelEscrow::openCall {
        ITIP20ChannelEscrow::openCall {
            payee,
            operator,
            token,
            deposit: abi_u96(deposit),
            salt,
            authorizedSigner: authorized_signer,
        }
    }

    fn seed_expiring_nonce_hash(escrow: &mut TIP20ChannelEscrow) -> Result<B256> {
        let hash = B256::random();
        escrow.set_channel_open_context_hash(hash)?;
        Ok(hash)
    }

    #[test]
    fn test_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
        StorageCtx::enter(&mut storage, || {
            let mut escrow = TIP20ChannelEscrow::new();
            let unsupported = check_selector_coverage(
                &mut escrow,
                ITIP20ChannelEscrowCalls::SELECTORS,
                "ITIP20ChannelEscrow",
                ITIP20ChannelEscrowCalls::name_by_selector,
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
            let mut escrow = TIP20ChannelEscrow::new();
            escrow.initialize()?;

            let result = escrow.open(
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
                TIP20ChannelEscrowError::expiring_nonce_hash_not_set().into()
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

            let mut escrow = TIP20ChannelEscrow::new();
            escrow.initialize()?;
            let expiring_nonce_hash = seed_expiring_nonce_hash(&mut escrow)?;

            let channel_id = escrow.open(
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

            let digest = escrow.get_voucher_digest(ITIP20ChannelEscrow::getVoucherDigestCall {
                channelId: channel_id,
                cumulativeAmount: abi_u96(120),
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
            escrow.settle(
                payee,
                ITIP20ChannelEscrow::settleCall {
                    descriptor: channel_descriptor.clone(),
                    cumulativeAmount: abi_u96(120),
                    signature: signature.clone(),
                },
            )?;

            let close_digest =
                escrow.get_voucher_digest(ITIP20ChannelEscrow::getVoucherDigestCall {
                    channelId: channel_id,
                    cumulativeAmount: abi_u96(500),
                })?;
            let close_signature =
                Bytes::copy_from_slice(&payer_signer.sign_hash_sync(&close_digest)?.as_bytes());
            escrow.close(
                payee,
                ITIP20ChannelEscrow::closeCall {
                    descriptor: channel_descriptor.clone(),
                    cumulativeAmount: abi_u96(500),
                    captureAmount: abi_u96(200),
                    signature: close_signature,
                },
            )?;

            let state = escrow.get_channel_state(ITIP20ChannelEscrow::getChannelStateCall {
                channelId: channel_id,
            })?;
            assert!(state.deposit.is_zero());
            assert!(state.settled.is_zero());
            assert_eq!(state.closeRequestedAt, 0);

            let reopen_result = escrow.open(
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
                TIP20ChannelEscrowError::channel_already_exists().into()
            );

            let new_expiring_nonce_hash = seed_expiring_nonce_hash(&mut escrow)?;
            let reopened_channel_id = escrow.open(
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
                escrow.get_channel_state(ITIP20ChannelEscrow::getChannelStateCall {
                    channelId: reopened_channel_id,
                })?;
            assert_eq!(reopened_state.deposit, abi_u96(1));

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
            let escrow = TIP20ChannelEscrow::new();

            let hash_a = B256::random();
            let hash_b = B256::random();
            let without_operator =
                escrow.compute_channel_id(ITIP20ChannelEscrow::computeChannelIdCall {
                    payer,
                    payee,
                    operator: Address::ZERO,
                    token: token.address(),
                    salt,
                    authorizedSigner: Address::ZERO,
                    expiringNonceHash: hash_a,
                })?;
            let with_operator =
                escrow.compute_channel_id(ITIP20ChannelEscrow::computeChannelIdCall {
                    payer,
                    payee,
                    operator,
                    token: token.address(),
                    salt,
                    authorizedSigner: Address::ZERO,
                    expiringNonceHash: hash_a,
                })?;
            let with_other_hash =
                escrow.compute_channel_id(ITIP20ChannelEscrow::computeChannelIdCall {
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
            let mut escrow = TIP20ChannelEscrow::new();
            escrow.initialize()?;

            let hash = seed_expiring_nonce_hash(&mut escrow)?;
            let first = escrow.open(
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
            let second = escrow.open(
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

            let other_hash = seed_expiring_nonce_hash(&mut escrow)?;
            let same_descriptor_other_tx_hash = escrow.open(
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
            let mut escrow = TIP20ChannelEscrow::new();
            escrow.initialize()?;

            let salt = B256::random();
            let expiring_nonce_hash = seed_expiring_nonce_hash(&mut escrow)?;
            let channel_id = escrow.open(
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
            let digest = escrow.get_voucher_digest(ITIP20ChannelEscrow::getVoucherDigestCall {
                channelId: channel_id,
                cumulativeAmount: abi_u96(40),
            })?;
            let signature =
                Bytes::copy_from_slice(&payer_signer.sign_hash_sync(&digest)?.as_bytes());

            escrow.settle(
                operator,
                ITIP20ChannelEscrow::settleCall {
                    descriptor: channel_descriptor,
                    cumulativeAmount: abi_u96(40),
                    signature,
                },
            )?;
            let state = escrow.get_channel_state(ITIP20ChannelEscrow::getChannelStateCall {
                channelId: channel_id,
            })?;
            assert_eq!(state.settled, abi_u96(40));

            let salt = B256::random();
            let expiring_nonce_hash = seed_expiring_nonce_hash(&mut escrow)?;
            escrow.open(
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
            let result = escrow.settle(
                Address::random(),
                ITIP20ChannelEscrow::settleCall {
                    descriptor: descriptor_without_operator,
                    cumulativeAmount: abi_u96(1),
                    signature: Bytes::copy_from_slice(&Signature::test_signature().as_bytes()),
                },
            );
            assert_eq!(
                result.unwrap_err(),
                TIP20ChannelEscrowError::not_payee_or_operator().into()
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
            let mut escrow = TIP20ChannelEscrow::new();
            escrow.initialize()?;

            let expiring_nonce_hash = seed_expiring_nonce_hash(&mut escrow)?;
            let descriptor = descriptor(
                payer,
                payee,
                Address::ZERO,
                token.address(),
                salt,
                Address::ZERO,
                expiring_nonce_hash,
            );
            escrow.open(
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

            escrow.storage.set_timestamp(U256::from(1_000u64));
            escrow.request_close(
                payer,
                ITIP20ChannelEscrow::requestCloseCall {
                    descriptor: descriptor.clone(),
                },
            )?;
            let requested = escrow.get_channel(ITIP20ChannelEscrow::getChannelCall {
                descriptor: descriptor.clone(),
            })?;
            assert_eq!(requested.state.closeRequestedAt, 1_000);

            escrow.top_up(
                payer,
                ITIP20ChannelEscrow::topUpCall {
                    descriptor: descriptor.clone(),
                    additionalDeposit: abi_u96(25),
                },
            )?;

            let channel = escrow.get_channel(ITIP20ChannelEscrow::getChannelCall { descriptor })?;
            assert_eq!(channel.state.closeRequestedAt, 0);
            assert_eq!(channel.state.deposit, 125);

            Ok(())
        })
    }

    #[test]
    fn test_dispatch_rejects_static_mutation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
        StorageCtx::enter(&mut storage, || {
            let mut escrow = TIP20ChannelEscrow::new();
            let result = escrow.call(
                &ITIP20ChannelEscrow::openCall {
                    payee: Address::random(),
                    operator: Address::ZERO,
                    token: TIP20_CHANNEL_ESCROW_ADDRESS,
                    deposit: abi_u96(1),
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
            let mut escrow = TIP20ChannelEscrow::new();
            escrow.initialize()?;
            let expiring_nonce_hash = seed_expiring_nonce_hash(&mut escrow)?;
            escrow.open(
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

            let result = escrow.settle(
                payee,
                ITIP20ChannelEscrow::settleCall {
                    descriptor: descriptor(
                        payer,
                        payee,
                        Address::ZERO,
                        token.address(),
                        salt,
                        Address::ZERO,
                        expiring_nonce_hash,
                    ),
                    cumulativeAmount: abi_u96(10),
                    signature: Bytes::copy_from_slice(
                        &Signature::test_signature().as_bytes()[..64],
                    ),
                },
            );
            assert_eq!(
                result.unwrap_err(),
                TIP20ChannelEscrowError::invalid_signature().into()
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
            let mut escrow = TIP20ChannelEscrow::new();
            escrow.initialize()?;
            let expiring_nonce_hash = seed_expiring_nonce_hash(&mut escrow)?;
            escrow.open(
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

            let mut keychain_signature = Vec::with_capacity(1 + 20 + 65);
            keychain_signature.push(0x03);
            keychain_signature.extend_from_slice(Address::random().as_slice());
            keychain_signature.extend_from_slice(Signature::test_signature().as_bytes().as_slice());

            let result = escrow.settle(
                payee,
                ITIP20ChannelEscrow::settleCall {
                    descriptor: descriptor(
                        payer,
                        payee,
                        Address::ZERO,
                        token.address(),
                        salt,
                        Address::ZERO,
                        expiring_nonce_hash,
                    ),
                    cumulativeAmount: abi_u96(10),
                    signature: keychain_signature.into(),
                },
            );
            assert_eq!(
                result.unwrap_err(),
                TIP20ChannelEscrowError::invalid_signature().into()
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
            let mut escrow = TIP20ChannelEscrow::new();
            escrow.initialize()?;
            let expiring_nonce_hash = seed_expiring_nonce_hash(&mut escrow)?;
            let channel_id = escrow.open(
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

            escrow.storage.set_timestamp(U256::from(1_000u64));
            escrow.request_close(
                payer,
                ITIP20ChannelEscrow::requestCloseCall {
                    descriptor: descriptor.clone(),
                },
            )?;
            escrow
                .storage
                .set_timestamp(U256::from(1_000u64 + CLOSE_GRACE_PERIOD));
            escrow.withdraw(payer, ITIP20ChannelEscrow::withdrawCall { descriptor })?;

            let state = escrow.get_channel_state(ITIP20ChannelEscrow::getChannelStateCall {
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
            let mut escrow = TIP20ChannelEscrow::new();
            escrow.initialize()?;
            let expiring_nonce_hash = seed_expiring_nonce_hash(&mut escrow)?;
            let descriptor = descriptor(
                payer,
                payee,
                Address::ZERO,
                token.address(),
                salt,
                Address::ZERO,
                expiring_nonce_hash,
            );
            escrow.open(
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

            let result = escrow.withdraw(payer, ITIP20ChannelEscrow::withdrawCall { descriptor });
            assert_eq!(
                result.unwrap_err(),
                TIP20ChannelEscrowError::close_not_ready().into()
            );
            Ok(())
        })
    }
}
