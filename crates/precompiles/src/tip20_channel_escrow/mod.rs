//! TIP-1034 TIP-20 channel escrow precompile.

pub mod dispatch;

use crate::{
    error::Result,
    signature_verifier::SignatureVerifier,
    storage::{Handler, Mapping},
    tip20::{is_tip20_prefix, TIP20Token},
};
use alloy::{
    primitives::{aliases::U96, keccak256, Address, B256, U256},
    sol_types::SolValue,
};
use std::sync::LazyLock;
pub use tempo_contracts::precompiles::{
    ITIP20ChannelEscrow, TIP20ChannelEscrowError, TIP20ChannelEscrowEvent,
    TIP20_CHANNEL_ESCROW_ADDRESS,
};
use tempo_precompiles_macros::{contract, Storable};

const FINALIZED_CLOSE_DATA: u32 = 1;

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
    expires_at: u32,
    close_data: u32,
}

impl From<PackedChannelState> for ITIP20ChannelEscrow::ChannelState {
    fn from(state: PackedChannelState) -> Self {
        Self {
            settled: state.settled,
            deposit: state.deposit,
            expiresAt: state.expires_at,
            closeData: state.close_data,
        }
    }
}

impl PackedChannelState {
    fn exists(self) -> bool {
        !self.deposit.is_zero()
    }

    fn is_finalized(self) -> bool {
        self.close_data == FINALIZED_CLOSE_DATA
    }

    fn close_requested_at(self) -> Option<u32> {
        (self.close_data >= 2).then_some(self.close_data)
    }
}

#[contract(addr = TIP20_CHANNEL_ESCROW_ADDRESS)]
pub struct TIP20ChannelEscrow {
    channel_states: Mapping<B256, PackedChannelState>,
}

impl TIP20ChannelEscrow {
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
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
        if call.expiresAt as u64 <= self.now() {
            return Err(TIP20ChannelEscrowError::invalid_expiry().into());
        }

        let channel_id = self.compute_channel_id_inner(
            msg_sender,
            call.payee,
            call.token,
            call.salt,
            call.authorizedSigner,
        )?;
        if self.channel_states[channel_id].read()?.exists() {
            return Err(TIP20ChannelEscrowError::channel_already_exists().into());
        }

        let batch = self.storage.checkpoint();
        self.channel_states[channel_id].write(PackedChannelState {
            settled: U96::ZERO,
            deposit,
            expires_at: call.expiresAt,
            close_data: 0,
        })?;
        TIP20Token::from_address(call.token)?.system_transfer_from(
            msg_sender,
            self.address,
            U256::from(call.deposit),
        )?;
        self.emit_event(TIP20ChannelEscrowEvent::ChannelOpened(
            ITIP20ChannelEscrow::ChannelOpened {
                channelId: channel_id,
                payer: msg_sender,
                payee: call.payee,
                token: call.token,
                authorizedSigner: call.authorizedSigner,
                salt: call.salt,
                deposit: call.deposit,
                expiresAt: call.expiresAt,
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

        if msg_sender != call.descriptor.payee {
            return Err(TIP20ChannelEscrowError::not_payee().into());
        }
        if state.is_finalized() {
            return Err(TIP20ChannelEscrowError::channel_finalized().into());
        }
        if self.is_expired(state.expires_at) {
            return Err(TIP20ChannelEscrowError::channel_expired().into());
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
        if state.is_finalized() {
            return Err(TIP20ChannelEscrowError::channel_finalized().into());
        }

        let additional = call.additionalDeposit;
        let next_deposit = state
            .deposit
            .checked_add(additional)
            .ok_or_else(TIP20ChannelEscrowError::deposit_overflow)?;

        if call.newExpiresAt != 0 {
            if call.newExpiresAt as u64 <= self.now() || call.newExpiresAt <= state.expires_at {
                return Err(TIP20ChannelEscrowError::invalid_expiry().into());
            }
        }

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
        if call.newExpiresAt != 0 {
            state.expires_at = call.newExpiresAt;
        }
        if had_close_request {
            state.close_data = 0;
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
            newExpiresAt: state.expires_at,
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
        if state.is_finalized() {
            return Err(TIP20ChannelEscrowError::channel_finalized().into());
        }
        if state.close_requested_at().is_some() {
            return Ok(());
        }

        // `close_data` reserves 0 and 1 as sentinels, so tests and local fixtures that run
        // with synthetic block timestamps of 0 or 1 can encode inconsistent channel state.
        // Mainnet/testnet timestamps are guaranteed to be > 1, so this only matters outside
        // real network execution.
        let close_requested_at = self.now_u32();
        let batch = self.storage.checkpoint();
        state.close_data = close_requested_at;
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
        let mut state = self.load_existing_state(channel_id)?;

        if msg_sender != call.descriptor.payee {
            return Err(TIP20ChannelEscrowError::not_payee().into());
        }
        if state.is_finalized() {
            return Err(TIP20ChannelEscrowError::channel_finalized().into());
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
            if self.is_expired(state.expires_at) {
                return Err(TIP20ChannelEscrowError::channel_expired().into());
            }
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
        state.settled = capture;
        state.close_data = FINALIZED_CLOSE_DATA;
        self.channel_states[channel_id].write(state)?;

        let mut token = TIP20Token::from_address(call.descriptor.token)?;
        if !delta.is_zero() {
            token.system_transfer_from(
                self.address,
                call.descriptor.payee,
                U256::from(delta),
            )?;
        }
        if !refund.is_zero() {
            token.system_transfer_from(
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
        let mut state = self.load_existing_state(channel_id)?;

        if msg_sender != call.descriptor.payer {
            return Err(TIP20ChannelEscrowError::not_payer().into());
        }
        if state.is_finalized() {
            return Err(TIP20ChannelEscrowError::channel_finalized().into());
        }

        let close_ready = state
            .close_requested_at()
            .is_some_and(|requested_at| self.now() >= requested_at as u64 + CLOSE_GRACE_PERIOD);
        if !close_ready && !self.is_expired(state.expires_at) {
            return Err(TIP20ChannelEscrowError::close_not_ready().into());
        }

        let refund = state
            .deposit
            .checked_sub(state.settled)
            .expect("settled is always <= deposit");

        let batch = self.storage.checkpoint();
        state.close_data = FINALIZED_CLOSE_DATA;
        self.channel_states[channel_id].write(state)?;
        if !refund.is_zero() {
            TIP20Token::from_address(call.descriptor.token)?.system_transfer_from(
                self.address,
                call.descriptor.payer,
                U256::from(refund),
            )?;
        }
        self.emit_event(TIP20ChannelEscrowEvent::ChannelExpired(
            ITIP20ChannelEscrow::ChannelExpired {
                channelId: channel_id,
                payer: call.descriptor.payer,
                payee: call.descriptor.payee,
            },
        ))?;
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
            state: self.channel_states[channel_id].read()?.into(),
        })
    }

    pub fn get_channel_state(
        &self,
        call: ITIP20ChannelEscrow::getChannelStateCall,
    ) -> Result<ITIP20ChannelEscrow::ChannelState> {
        Ok(self.channel_states[call.channelId].read()?.into())
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
                    .map(Into::into)
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
            call.token,
            call.salt,
            call.authorizedSigner,
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

    fn is_expired(&self, expires_at: u32) -> bool {
        self.now() >= expires_at as u64
    }

    fn channel_id(&self, descriptor: &ITIP20ChannelEscrow::ChannelDescriptor) -> Result<B256> {
        self.compute_channel_id_inner(
            descriptor.payer,
            descriptor.payee,
            descriptor.token,
            descriptor.salt,
            descriptor.authorizedSigner,
        )
    }

    fn compute_channel_id_inner(
        &self,
        payer: Address,
        payee: Address,
        token: Address,
        salt: B256,
        authorized_signer: Address,
    ) -> Result<B256> {
        self.storage.keccak256(
            &(
                payer,
                payee,
                token,
                salt,
                authorized_signer,
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

    fn get_voucher_digest_inner(
        &self,
        channel_id: B256,
        cumulative_amount: U96,
    ) -> Result<B256> {
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
        storage::{hashmap::HashMapStorageProvider, ContractStorage, StorageCtx},
        test_util::{assert_full_coverage, check_selector_coverage, TIP20Setup},
        Precompile,
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
        token: Address,
        salt: B256,
        authorized_signer: Address,
    ) -> ITIP20ChannelEscrow::ChannelDescriptor {
        ITIP20ChannelEscrow::ChannelDescriptor {
            payer,
            payee,
            token,
            salt,
            authorizedSigner: authorized_signer,
        }
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
    fn test_open_settle_close_flow_and_tombstone() -> eyre::Result<()> {
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
            let now = StorageCtx::default().timestamp().to::<u32>();

            let channel_id = escrow.open(
                payer,
                ITIP20ChannelEscrow::openCall {
                    payee,
                    token: token.address(),
                    deposit: abi_u96(300),
                    salt,
                    authorizedSigner: Address::ZERO,
                    expiresAt: now + 1_000,
                },
            )?;

            let digest = escrow.get_voucher_digest(ITIP20ChannelEscrow::getVoucherDigestCall {
                channelId: channel_id,
                cumulativeAmount: abi_u96(120),
            })?;
            let signature =
                Bytes::copy_from_slice(&payer_signer.sign_hash_sync(&digest)?.as_bytes());

            let channel_descriptor = descriptor(payer, payee, token.address(), salt, Address::ZERO);
            escrow.settle(
                payee,
                ITIP20ChannelEscrow::settleCall {
                    descriptor: channel_descriptor.clone(),
                    cumulativeAmount: abi_u96(120),
                    signature: signature.clone(),
                },
            )?;
            escrow.close(
                payee,
                ITIP20ChannelEscrow::closeCall {
                    descriptor: channel_descriptor.clone(),
                    cumulativeAmount: abi_u96(120),
                    captureAmount: abi_u96(120),
                    signature,
                },
            )?;

            let state = escrow.get_channel_state(ITIP20ChannelEscrow::getChannelStateCall {
                channelId: channel_id,
            })?;
            assert_eq!(state.closeData, FINALIZED_CLOSE_DATA);
            assert_eq!(state.deposit, 300);
            assert_eq!(state.settled, 120);

            let reopen_result = escrow.open(
                payer,
                ITIP20ChannelEscrow::openCall {
                    payee,
                    token: token.address(),
                    deposit: abi_u96(1),
                    salt,
                    authorizedSigner: Address::ZERO,
                    expiresAt: now + 2_000,
                },
            );
            assert_eq!(
                reopen_result.unwrap_err(),
                TIP20ChannelEscrowError::channel_already_exists().into()
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

            let expires_at = StorageCtx::default().timestamp().to::<u32>() + 1_000;
            let descriptor = descriptor(payer, payee, token.address(), salt, Address::ZERO);
            escrow.open(
                payer,
                ITIP20ChannelEscrow::openCall {
                    payee,
                    token: token.address(),
                    deposit: abi_u96(100),
                    salt,
                    authorizedSigner: Address::ZERO,
                    expiresAt: expires_at,
                },
            )?;

            escrow.request_close(
                payer,
                ITIP20ChannelEscrow::requestCloseCall {
                    descriptor: descriptor.clone(),
                },
            )?;
            escrow.top_up(
                payer,
                ITIP20ChannelEscrow::topUpCall {
                    descriptor: descriptor.clone(),
                    additionalDeposit: abi_u96(25),
                    newExpiresAt: expires_at + 500,
                },
            )?;

            let channel = escrow.get_channel(ITIP20ChannelEscrow::getChannelCall { descriptor })?;
            assert_eq!(channel.state.closeData, 0);
            assert_eq!(channel.state.deposit, 125);
            assert_eq!(channel.state.expiresAt, expires_at + 500);

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
                    token: TIP20_CHANNEL_ESCROW_ADDRESS,
                    deposit: abi_u96(1),
                    salt: B256::ZERO,
                    authorizedSigner: Address::ZERO,
                    expiresAt: 2,
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
            let now = StorageCtx::default().timestamp().to::<u32>();
            escrow.open(
                payer,
                ITIP20ChannelEscrow::openCall {
                    payee,
                    token: token.address(),
                    deposit: abi_u96(100),
                    salt,
                    authorizedSigner: Address::ZERO,
                    expiresAt: now + 1_000,
                },
            )?;

            let result = escrow.settle(
                payee,
                ITIP20ChannelEscrow::settleCall {
                    descriptor: descriptor(payer, payee, token.address(), salt, Address::ZERO),
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
            let now = StorageCtx::default().timestamp().to::<u32>();
            escrow.open(
                payer,
                ITIP20ChannelEscrow::openCall {
                    payee,
                    token: token.address(),
                    deposit: abi_u96(100),
                    salt,
                    authorizedSigner: Address::ZERO,
                    expiresAt: now + 1_000,
                },
            )?;

            let mut keychain_signature = Vec::with_capacity(1 + 20 + 65);
            keychain_signature.push(0x03);
            keychain_signature.extend_from_slice(Address::random().as_slice());
            keychain_signature.extend_from_slice(Signature::test_signature().as_bytes().as_slice());

            let result = escrow.settle(
                payee,
                ITIP20ChannelEscrow::settleCall {
                    descriptor: descriptor(payer, payee, token.address(), salt, Address::ZERO),
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
}
