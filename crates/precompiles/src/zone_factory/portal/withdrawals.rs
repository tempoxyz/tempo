//! Withdrawal processing, callback delivery, bounce-backs and refunds.

use super::{
    CALLBACK_DEPOSIT_AVAILABLE, MAX_UNPROCESSED_DEPOSITS, WITHDRAWAL_NOT_ENTERED,
    WITHDRAWAL_PROCESSING, ZonePortalStorage,
};
use crate::{
    error::{Result, TempoPrecompileError},
    storage::Handler,
};
use alloy::{
    primitives::{Address, B256, Bytes, U256},
    sol,
    sol_types::{
        SolCall, SolError, SolType,
        abi::{self, token::WordToken},
    },
};
use tempo_contracts::{
    precompiles::{
        ADDRESS_REGISTRY_ADDRESS, IAddressRegistry, ITIP20, ITIP403Registry,
        TIP403_REGISTRY_ADDRESS, ZonePortalError, ZonePortalEvent, ZonePortalRole,
    },
    zones::{MAX_WITHDRAWAL_GAS_LIMIT, Withdrawal, ZoneMessenger, ZonePortal},
};

sol! {
    /// `WithdrawalQueueLib.InvalidWithdrawalProof`.
    error InvalidWithdrawalProof();
}

impl ZonePortalStorage {
    /// Solidity `claimRefund`.
    pub fn claim_refund(
        &mut self,
        sender: Address,
        call: ZonePortal::claimRefundCall,
    ) -> Result<u128> {
        self.require_allowed(sender)?;
        let amount = self.refunds[call.token][sender].read()?;
        self.refunds[call.token][sender].write(0)?;

        if !self.try_transfer(call.token, sender, amount)? {
            return Err(ZonePortalError::callback_rejected().into());
        }

        self.emit(ZonePortalEvent::refund_claimed(sender, call.token, amount))?;
        Ok(amount)
    }

    /// Solidity `deliverWithdrawal`.
    pub fn deliver_withdrawal(
        &mut self,
        sender: Address,
        call: ZonePortal::deliverWithdrawalCall,
    ) -> Result<()> {
        if sender != self.address {
            return Err(ZonePortalError::not_self().into());
        }
        // The binding names the Solidity `(token, target, senderTag)` parameters
        // `(to, token, memo)`; positions and the selector match.
        let ZonePortal::deliverWithdrawalCall {
            to: token,
            token: target,
            amount,
            memo: sender_tag,
            gasLimit: gas_limit,
            callbackData: data,
        } = call;

        if self.is_gateway_enforced.read()?
            && !self.has_role_of(target, ZonePortalRole::CallbackGateway)?
        {
            return Err(ZonePortalError::invalid_callback_target().into());
        }
        let messenger = self.messenger.read()?;
        let transfer = ITIP20::transferCall {
            to: messenger,
            amount: U256::from(amount),
        };
        if !self.external_call(token, &transfer)? {
            return Err(ZonePortalError::transfer_failed().into());
        }

        let deposit_queue_hash_before = self.current_deposit_queue_hash.read()?;

        self.withdrawal_reentrancy_status
            .write(CALLBACK_DEPOSIT_AVAILABLE)?;

        let relay = ZoneMessenger::relayMessageCall {
            zoneId: self.zone_id.read()?,
            token,
            senderTag: sender_tag,
            target,
            amount,
            gasLimit: gas_limit,
            data,
        };
        self.external_call(messenger, &relay)?;

        self.withdrawal_reentrancy_status
            .write(WITHDRAWAL_PROCESSING)?;

        if self.is_access_enforced.read()?
            && self.current_deposit_queue_hash.read()? == deposit_queue_hash_before
        {
            return Err(ZonePortalError::callback_did_not_return_to_zone().into());
        }
        Ok(())
    }

    /// Solidity `processWithdrawals`.
    pub fn process_withdrawals(
        &mut self,
        sender: Address,
        call: ZonePortal::processWithdrawalsCall,
    ) -> Result<()> {
        self.only_sequencer(sender)?;
        self.when_not_paused()?;
        // `nonReentrantWithdrawal`. A revert rolls back the status write with the frame.
        if self.withdrawal_reentrancy_status.read()? != WITHDRAWAL_NOT_ENTERED {
            return Err(ZonePortalError::reentrant_withdrawal().into());
        }
        self.withdrawal_reentrancy_status
            .write(WITHDRAWAL_PROCESSING)?;

        let ZonePortal::processWithdrawalsCall {
            withdrawals,
            remainingQueue: remaining_queue,
        } = call;

        let unprocessed = self
            .deposit_count
            .read()?
            .checked_sub(self.last_processed_deposit_number.read()?)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        if unprocessed > MAX_UNPROCESSED_DEPOSITS
            || withdrawals.len() as u64 > MAX_UNPROCESSED_DEPOSITS - unprocessed
        {
            return Err(
                ZonePortalError::deposit_block_capacity_exceeded(MAX_UNPROCESSED_DEPOSITS).into(),
            );
        }

        // Each entry is the withdrawal's queue link hash and the queue suffix after it.
        let mut links = vec![(B256::ZERO, B256::ZERO); withdrawals.len()];
        let mut next_queue = remaining_queue;
        for (withdrawal, link) in withdrawals.iter().zip(&mut links).rev() {
            let encoded = abi::encode_params(&(
                <Withdrawal as SolType>::tokenize(withdrawal),
                WordToken(next_queue),
            ));
            *link = (self.storage.keccak256(&encoded)?, next_queue);
            next_queue = link.0;
        }

        for (withdrawal, (hash, remaining)) in withdrawals.iter().zip(links) {
            self.process_withdrawal(withdrawal, hash, remaining)?;
        }

        self.withdrawal_reentrancy_status
            .write(WITHDRAWAL_NOT_ENTERED)
    }

    /// Solidity `withdrawalQueueHead`.
    pub fn withdrawal_queue_head(
        &self,
        _call: ZonePortal::withdrawalQueueHeadCall,
    ) -> Result<U256> {
        self.withdrawal_queue.head.read()
    }

    /// Solidity `withdrawalQueueSlot`.
    pub fn withdrawal_queue_slot(&self, call: ZonePortal::withdrawalQueueSlotCall) -> Result<B256> {
        self.withdrawal_queue.slots[call.queueIndex].read()
    }

    /// Solidity `withdrawalQueueTail`.
    pub fn withdrawal_queue_tail(
        &self,
        _call: ZonePortal::withdrawalQueueTailCall,
    ) -> Result<U256> {
        self.withdrawal_queue.tail.read()
    }

    /// Solidity `_processWithdrawal`; `hash` is `keccak256(abi.encode(withdrawal, remainingQueue))`.
    fn process_withdrawal(
        &mut self,
        withdrawal: &Withdrawal,
        hash: B256,
        remaining_queue: B256,
    ) -> Result<()> {
        self.dequeue_withdrawal(hash, remaining_queue)?;

        let token = withdrawal.token;

        if withdrawal.fallbackNonce == 0 {
            return self.process_deposit_bounce_back(withdrawal);
        }

        if withdrawal.gasLimit > MAX_WITHDRAWAL_GAS_LIMIT {
            self.enqueue_bounce_back(token, withdrawal.amount, withdrawal.fallbackNonce)?;
            return self.emit(ZonePortalEvent::withdrawal_processed(
                withdrawal.to,
                withdrawal.senderTag,
                token,
                withdrawal.amount,
                false,
            ));
        }

        let success = if withdrawal.gasLimit == 0 {
            // Re-check current roles without reverting so an in-flight withdrawal to a revoked
            // account or newly registered gateway bounces without blocking the FIFO.
            (!self.is_gateway_enforced.read()?
                || !self.has_role_of(withdrawal.to, ZonePortalRole::CallbackGateway)?)
                && self.is_allowed(withdrawal.to)?
                && self.try_transfer(token, withdrawal.to, withdrawal.amount)?
        } else {
            // Isolate callback effects so failure can be caught without reverting the dequeue.
            let deliver = ZonePortal::deliverWithdrawalCall {
                to: token,
                token: withdrawal.to,
                amount: withdrawal.amount,
                memo: withdrawal.senderTag,
                gasLimit: withdrawal.gasLimit,
                callbackData: withdrawal.callbackData.clone(),
            };
            self.try_external_call(self.address, &deliver, false)?
                .is_some()
        };

        if !success {
            self.enqueue_bounce_back(token, withdrawal.amount, withdrawal.fallbackNonce)?;
        }
        self.emit(ZonePortalEvent::withdrawal_processed(
            withdrawal.to,
            withdrawal.senderTag,
            token,
            withdrawal.amount,
            success,
        ))
    }

    /// `WithdrawalQueueLib.dequeue`: pops the head withdrawal whose link hash is `hash`.
    fn dequeue_withdrawal(&mut self, hash: B256, remaining_queue: B256) -> Result<()> {
        let head = self.withdrawal_queue.head.read()?;

        if hash != self.withdrawal_queue.slots[head].read()? {
            return Err(TempoPrecompileError::RawRevert(
                InvalidWithdrawalProof {}.abi_encode().into(),
            ));
        }

        self.withdrawal_queue.slots[head].write(remaining_queue)?;
        if remaining_queue.is_zero() {
            self.withdrawal_queue.head.write(
                head.checked_add(U256::ONE)
                    .ok_or_else(TempoPrecompileError::under_overflow)?,
            )?;
        }
        Ok(())
    }

    /// Solidity `_processDepositBounceBack`.
    fn process_deposit_bounce_back(&mut self, withdrawal: &Withdrawal) -> Result<()> {
        let token = withdrawal.token;
        let bounceback_fee = self
            .calculate_bounceback_fee(ZonePortal::calculateBouncebackFeeCall {})?
            .min(withdrawal.amount);
        // Only deduct the fee if the admin transfer succeeds; otherwise the full amount remains
        // refundable to the deposit recipient.
        let mut collected_fee = 0;
        if bounceback_fee > 0 {
            let admin = self.admin.read()?;
            if self.try_transfer(token, admin, bounceback_fee)? {
                collected_fee = bounceback_fee;
            }
        }
        let refund_amount = withdrawal.amount - collected_fee;

        let success = self.is_allowed(withdrawal.to)?
            && self.try_transfer(token, withdrawal.to, refund_amount)?;

        if success {
            self.emit(ZonePortalEvent::deposit_bounce_back(
                withdrawal.to,
                token,
                refund_amount,
                collected_fee,
            ))
        } else {
            let refund = &mut self.refunds[token][withdrawal.to];
            let pending = refund
                .read()?
                .checked_add(refund_amount)
                .ok_or_else(TempoPrecompileError::under_overflow)?;
            refund.write(pending)?;
            self.emit(ZonePortalEvent::deposit_bounce_back_pending(
                withdrawal.to,
                token,
                refund_amount,
                collected_fee,
            ))
        }
    }

    /// Solidity `_tryTransfer`: whether a TIP-20 transfer to `to` went through, without
    /// bubbling registry, policy or token reverts.
    fn try_transfer(&mut self, token: Address, to: Address, amount: u128) -> Result<bool> {
        let resolve = IAddressRegistry::resolveRecipientCall { to };
        let Some(effective_recipient) = self.try_call(ADDRESS_REGISTRY_ADDRESS, &resolve, true)?
        else {
            return Ok(false);
        };

        let validate = ITIP403Registry::validateReceivePolicyCall {
            token,
            sender: self.address,
            receiver: effective_recipient,
        };
        match self.try_call(TIP403_REGISTRY_ADDRESS, &validate, true)? {
            Some(policy) if policy.authorized => {}
            _ => return Ok(false),
        }

        let transfer = ITIP20::transferCall {
            to,
            amount: U256::from(amount),
        };
        Ok(self.try_call(token, &transfer, false)?.unwrap_or_default())
    }

    /// A Solidity `try` call with return values: `None` when the callee reverts. Unlike
    /// [`Self::try_external_call`], return data that does not decode reverts with empty data, as
    /// Solidity's `catch` does not catch decoding failures.
    fn try_call<C: SolCall>(
        &mut self,
        target: Address,
        call: &C,
        is_static: bool,
    ) -> Result<Option<C::Return>> {
        let result = self.raw_call(target, call.abi_encode().into(), is_static)?;
        if !result.success {
            return Ok(None);
        }
        C::abi_decode_returns_validate(&result.output)
            .map(Some)
            .map_err(|_| TempoPrecompileError::RawRevert(Bytes::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PATH_USD_ADDRESS,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::TIP20Setup,
        zone_factory::ZoneFactory,
    };
    use alloy::primitives::{IntoLogData, LogData, b256};
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::IZoneFactory;

    const OWNER: Address = Address::with_last_byte(0x11);
    const ADMIN: Address = Address::with_last_byte(0x22);
    const SEQUENCER: Address = Address::with_last_byte(0x33);
    const RECIPIENT_1: Address = Address::with_last_byte(0x77);
    const RECIPIENT_2: Address = Address::with_last_byte(0x88);

    /// `keccak256(abi.encode(withdrawal_2(), bytes32(0)))`, from cast.
    const HASH_2: B256 =
        b256!("0x78cff9df50113aeee9333e32baddb186548b08b7f544398e0886a813995f005e");
    /// `keccak256(abi.encode(withdrawal_1(), HASH_2))`, from cast.
    const HASH_1: B256 =
        b256!("0x89cba4ee609f0f4baaf1860c298c98fd656950efcb2033c845ef13b366b0a801");

    /// Creates zone 1 in closed access and gateway mode, with one queued withdrawal batch whose
    /// hash chain is `[withdrawal_1(), withdrawal_2()]`.
    fn create_portal() -> eyre::Result<ZonePortalStorage> {
        TIP20Setup::path_usd(ADMIN).apply()?;
        let mut factory = ZoneFactory::new();
        factory.next_zone_id.write(1)?;
        factory.owner.write(OWNER)?;
        let created = factory.create_zone(
            OWNER,
            IZoneFactory::createZoneCall {
                params: IZoneFactory::CreateZoneParams {
                    initialToken: PATH_USD_ADDRESS,
                    accessMode: true,
                    gatewayMode: true,
                    allowedAccounts: vec![],
                    zoneGateways: vec![],
                    admin: ADMIN,
                    sequencers: vec![SEQUENCER],
                    threshold: 1,
                    rpcUrl: "https://zone.example".to_string(),
                },
            },
        )?;
        let mut portal = ZonePortalStorage::new(created.portal);
        portal.withdrawal_queue.slots[U256::ZERO].write(HASH_1)?;
        portal.withdrawal_queue.tail.write(U256::ONE)?;
        Ok(portal)
    }

    /// A deposit bounce-back (`fallbackNonce == 0`) to a recipient closed access rejects.
    fn withdrawal_1() -> Withdrawal {
        Withdrawal {
            token: PATH_USD_ADDRESS,
            senderTag: B256::repeat_byte(0x11),
            to: RECIPIENT_1,
            amount: 1000,
            memo: B256::repeat_byte(0x22),
            gasLimit: 0,
            fallbackNonce: 0,
            callbackData: Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]),
            encryptedSender: Bytes::from_static(&[0xca, 0xfe]),
        }
    }

    fn withdrawal_2() -> Withdrawal {
        Withdrawal {
            token: PATH_USD_ADDRESS,
            senderTag: B256::repeat_byte(0x44),
            to: RECIPIENT_2,
            amount: 250,
            memo: B256::ZERO,
            gasLimit: 0,
            fallbackNonce: 0,
            callbackData: Bytes::new(),
            encryptedSender: Bytes::new(),
        }
    }

    fn process(
        withdrawals: Vec<Withdrawal>,
        remaining_queue: B256,
    ) -> ZonePortal::processWithdrawalsCall {
        ZonePortal::processWithdrawalsCall {
            withdrawals,
            remainingQueue: remaining_queue,
        }
    }

    fn pending(to: Address, amount: u128) -> LogData {
        ZonePortalEvent::deposit_bounce_back_pending(to, PATH_USD_ADDRESS, amount, 0)
            .into_log_data()
    }

    #[test]
    fn process_withdrawals_matches_solidity_hash_chain() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
        let portal_address = StorageCtx::enter(&mut storage, || -> eyre::Result<Address> {
            let mut portal = create_portal()?;
            portal.process_withdrawals(
                SEQUENCER,
                process(vec![withdrawal_1(), withdrawal_2()], B256::ZERO),
            )?;

            assert_eq!(
                portal.withdrawal_queue_head(ZonePortal::withdrawalQueueHeadCall {})?,
                U256::ONE
            );
            assert_eq!(
                portal.withdrawal_queue_tail(ZonePortal::withdrawalQueueTailCall {})?,
                U256::ONE
            );
            assert_eq!(
                portal.withdrawal_queue_slot(ZonePortal::withdrawalQueueSlotCall {
                    queueIndex: U256::ZERO
                })?,
                B256::ZERO
            );
            assert_eq!(portal.refunds[PATH_USD_ADDRESS][RECIPIENT_1].read()?, 1000);
            assert_eq!(portal.refunds[PATH_USD_ADDRESS][RECIPIENT_2].read()?, 250);
            assert_eq!(
                portal.withdrawal_reentrancy_status.read()?,
                WITHDRAWAL_NOT_ENTERED
            );
            Ok(portal.address)
        })?;
        let events = storage.get_events(portal_address);
        assert_eq!(
            events[events.len() - 2..],
            [pending(RECIPIENT_1, 1000), pending(RECIPIENT_2, 250)]
        );
        Ok(())
    }

    #[test]
    fn process_withdrawals_keeps_head_on_partial_batch() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
        StorageCtx::enter(&mut storage, || {
            let mut portal = create_portal()?;
            portal.process_withdrawals(SEQUENCER, process(vec![withdrawal_1()], HASH_2))?;

            assert_eq!(portal.withdrawal_queue.head.read()?, U256::ZERO);
            assert_eq!(portal.withdrawal_queue.slots[U256::ZERO].read()?, HASH_2);
            assert_eq!(portal.refunds[PATH_USD_ADDRESS][RECIPIENT_1].read()?, 1000);
            Ok(())
        })
    }

    #[test]
    fn process_withdrawals_rejects() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
        StorageCtx::enter(&mut storage, || {
            let mut portal = create_portal()?;

            assert_eq!(
                portal.process_withdrawals(ADMIN, process(vec![], B256::ZERO)),
                Err(ZonePortalError::not_sequencer().into())
            );

            // Out of order: the head link is withdrawal_1.
            assert_eq!(
                portal.process_withdrawals(SEQUENCER, process(vec![withdrawal_2()], B256::ZERO)),
                Err(TempoPrecompileError::RawRevert(
                    InvalidWithdrawalProof {}.abi_encode().into()
                ))
            );

            // Without an EVM frame to roll back, the failed call leaves the guard entered.
            assert_eq!(
                portal.withdrawal_reentrancy_status.read()?,
                WITHDRAWAL_PROCESSING
            );
            portal
                .withdrawal_reentrancy_status
                .write(WITHDRAWAL_NOT_ENTERED)?;

            portal.deposit_count.write(MAX_UNPROCESSED_DEPOSITS)?;
            assert_eq!(
                portal.process_withdrawals(SEQUENCER, process(vec![withdrawal_1()], HASH_2)),
                Err(
                    ZonePortalError::deposit_block_capacity_exceeded(MAX_UNPROCESSED_DEPOSITS)
                        .into()
                )
            );
            portal.deposit_count.write(0)?;
            portal
                .withdrawal_reentrancy_status
                .write(WITHDRAWAL_NOT_ENTERED)?;

            portal
                .withdrawal_reentrancy_status
                .write(WITHDRAWAL_PROCESSING)?;
            assert_eq!(
                portal.process_withdrawals(SEQUENCER, process(vec![], B256::ZERO)),
                Err(ZonePortalError::reentrant_withdrawal().into())
            );

            portal.pause_expiry.write(u64::MAX)?;
            assert_eq!(
                portal.process_withdrawals(SEQUENCER, process(vec![], B256::ZERO)),
                Err(ZonePortalError::portal_is_paused().into())
            );
            Ok(())
        })
    }

    #[test]
    fn deliver_withdrawal_rejects() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
        StorageCtx::enter(&mut storage, || {
            let mut portal = create_portal()?;
            let call = ZonePortal::deliverWithdrawalCall {
                to: PATH_USD_ADDRESS,
                token: RECIPIENT_1,
                amount: 1,
                memo: B256::ZERO,
                gasLimit: 1,
                callbackData: Bytes::new(),
            };

            assert_eq!(
                portal.deliver_withdrawal(SEQUENCER, call.clone()),
                Err(ZonePortalError::not_self().into())
            );
            assert_eq!(
                portal.deliver_withdrawal(portal.address, call),
                Err(ZonePortalError::invalid_callback_target().into())
            );
            Ok(())
        })
    }

    #[test]
    fn claim_refund_requires_allowed_account() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
        StorageCtx::enter(&mut storage, || {
            let mut portal = create_portal()?;
            assert_eq!(
                portal.claim_refund(
                    RECIPIENT_1,
                    ZonePortal::claimRefundCall {
                        token: PATH_USD_ADDRESS
                    }
                ),
                Err(ZonePortalError::account_not_allowed(RECIPIENT_1).into())
            );
            Ok(())
        })
    }
}
