//! [TIP-1028] ReceivePolicyGuard precompile for blocked inbound TIP-20 transfers and mints.

pub mod dispatch;

pub use tempo_contracts::precompiles::IReceivePolicyGuard::{self, InboundKind};
use tempo_contracts::precompiles::{
    IReceivePolicyGuard::ClaimReceiptV1, ITIP403Registry::BlockedReason, ReceivePolicyGuardError,
};

use crate::{
    RECEIVE_POLICY_GUARD_ADDRESS,
    address_registry::AddressRegistry,
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping},
    tip20::{Recipient, TIP20Token},
};
use alloy::{
    primitives::{Address, B256, Bytes, U256},
    sol_types::SolValue,
};
use tempo_precompiles_macros::{Storable, contract};
use tempo_primitives::TempoAddressExt;

/// Version tag for the v1 [`IReceivePolicyGuard::ClaimReceiptV1`] layout.
pub const BLOCKED_RECEIPT_VERSION: u8 = 1;

/// Recovery-authority sentinel: originator/sender is authorized to claim (`address(0)`).
pub const RECOVERY_ORIGINATOR: Address = Address::ZERO;

/// TIP-1028 precompile holding blocked inbound transfers and mints until claimed.
#[contract(addr = RECEIVE_POLICY_GUARD_ADDRESS)]
pub struct ReceivePolicyGuard {
    nonce: u64,
    balances: Mapping<B256, U256>,
}

impl ReceivePolicyGuard {
    /// One-time storage initialization.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Returns the unclaimed amount for a receipt, or zero if unknown or already claimed.
    pub fn balance_of(&self, receipt: Bytes) -> Result<U256> {
        let receipt = ClaimReceiptV1::try_from(receipt)?;
        self.balances[self.receipt_key(&receipt)?].read()
    }

    /// Records a blocked inbound transfer or mint and emits `TransferBlocked` event.
    /// Caller must send the funds into this address, which are claimable with a valid receipt.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn store_blocked(
        &mut self,
        token: Address,
        originator: Address,
        to: &Recipient,
        recovery_address: Address,
        amount: U256,
        blocked_reason: BlockedReason,
        kind: InboundKind,
        memo: B256,
    ) -> Result<(u64, u64)> {
        debug_assert!(
            token.is_tip20(),
            "ReceivePolicyGuard only accepts TIP20 tokens"
        );

        let is_invalid_reason = match blocked_reason {
            BlockedReason::RECEIVE_POLICY | BlockedReason::TOKEN_FILTER => false,
            BlockedReason::NONE | BlockedReason::__Invalid => true,
        };
        if is_invalid_reason || matches!(kind, InboundKind::__Invalid) {
            return Err(ReceivePolicyGuardError::invalid_receipt().into());
        }

        let receiver = to.target;
        let recipient = to.virtual_addr.unwrap_or(to.target);

        let blocked_nonce = self.next_receipt_nonce()?;
        let blocked_at = self.storage.timestamp().saturating_to::<u64>();
        let receipt = IReceivePolicyGuard::ClaimReceiptV1::new(
            token,
            recovery_address,
            originator,
            recipient,
            blocked_at,
            blocked_nonce,
            blocked_reason as u8,
            kind,
            memo,
        );
        let key = self.receipt_key(&receipt)?;
        self.balances[key].write(amount)?;

        self.emit_event(receipt.blocked_event(receiver, amount))?;
        Ok((blocked_nonce, blocked_at))
    }

    /// Given a valid receipt, releases blocked funds to the authorized receiver.
    pub fn claim(&mut self, msg_sender: Address, to: Address, receipt: Bytes) -> Result<()> {
        if to == RECEIVE_POLICY_GUARD_ADDRESS {
            return Err(ReceivePolicyGuardError::invalid_claim_address().into());
        }

        let (receipt, receiver, recovery_mode) = resolve_receipt(receipt)?;
        if receipt.recoveryAuthority != msg_sender {
            return Err(ReceivePolicyGuardError::unauthorized_claimer().into());
        };

        let key = self.receipt_key(&receipt)?;
        let amount = self.balances[key].read()?;
        if amount.is_zero() {
            return Err(ReceivePolicyGuardError::invalid_receipt().into());
        }

        self.balances[key].write(U256::ZERO)?;

        TIP20Token::from_address(receipt.token)?.release_blocked_funds(
            receipt.originator,
            receiver,
            to,
            amount,
            recovery_mode,
            receipt.recoveryAuthority,
        )?;

        self.emit_event(receipt.claimed_event(receiver, msg_sender, to, amount))
    }

    pub fn burn_blocked_receipt(&mut self, msg_sender: Address, receipt: Bytes) -> Result<()> {
        let (receipt, receiver, recovery_mode) = resolve_receipt(receipt)?;

        let key = self.receipt_key(&receipt)?;
        let amount = self.balances[key].read()?;
        if amount.is_zero() {
            return Err(ReceivePolicyGuardError::invalid_receipt().into());
        }

        // Burn from the account with ownership of the funds.
        let owner = recovery_mode.policy_subject(receipt.originator, receiver);
        TIP20Token::from_address(receipt.token)?.burn_blocked(msg_sender, owner, amount, true)?;
        self.balances[key].write(U256::ZERO)?;

        self.emit_event(receipt.burned_event(receiver, msg_sender, amount))
    }

    /// Allocates the next nonzero receipt nonce.
    fn next_receipt_nonce(&mut self) -> Result<u64> {
        let nonce = self.nonce.read()?.max(1);
        self.nonce.write(
            nonce
                .checked_add(1)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;
        Ok(nonce)
    }

    /// Content hash over every receipt field. Any mutation yields a different empty slot.
    fn receipt_key(&self, receipt: &IReceivePolicyGuard::ClaimReceiptV1) -> Result<B256> {
        self.storage.keccak256(receipt.abi_encode().as_ref())
    }
}

/// Recovery authority for blocked inbound funds.
#[derive(Debug, Clone, Copy, Default, Storable, PartialEq)]
#[repr(u8)]
pub(crate) enum RecoveryMode {
    #[default]
    Originator,
    Receiver,
    ThirdParty,
}

impl RecoveryMode {
    /// Encodes a configured recovery authority into a mode and stored authority value.
    pub(crate) fn encode(authority: Address, msg_sender: Address) -> (Self, Address) {
        if authority == RECOVERY_ORIGINATOR {
            (Self::Originator, Address::ZERO)
        } else if authority == msg_sender {
            (Self::Receiver, Address::ZERO)
        } else {
            (Self::ThirdParty, authority)
        }
    }

    /// Resolves the recovery mode for a receipt and resolved receiver.
    pub(crate) fn from(receipt: &ClaimReceiptV1, receiver: Address) -> Self {
        if receipt.recoveryAuthority == receipt.originator {
            Self::Originator
        } else if receipt.recoveryAuthority == receiver {
            Self::Receiver
        } else {
            Self::ThirdParty
        }
    }

    /// Returns the address of the account who has effective ownership of the blocked funds.
    pub(crate) fn policy_subject(self, originator: Address, receiver: Address) -> Address {
        match self {
            Self::Originator => originator,
            Self::Receiver | Self::ThirdParty => receiver,
        }
    }

    /// Returns whether a claim is a reroute under TIP-1028.
    /// Originator-authorized claims are always reroutes; non-originator recovery claims resume
    /// only when claiming to the receiver.
    pub(crate) fn is_reroute(self, to: Address, receiver: Address) -> bool {
        match self {
            Self::Originator => true,
            Self::Receiver | Self::ThirdParty => to != receiver,
        }
    }

    /// Returns the account charged for access-key spending limits, if any.
    pub(crate) fn spending_account(self, recovery_authority: Address) -> Option<Address> {
        match self {
            Self::Originator | Self::Receiver => Some(recovery_authority),
            Self::ThirdParty => None,
        }
    }
}

fn resolve_receipt(bytes: Bytes) -> Result<(ClaimReceiptV1, Address, RecoveryMode)> {
    let receipt = ClaimReceiptV1::try_from(bytes)?;
    let receiver = AddressRegistry::new()
        .resolve_receiver(receipt.recipient)
        .map_err(|_| ReceivePolicyGuardError::invalid_claim_address())?;
    let recovery_mode = RecoveryMode::from(&receipt, receiver);

    Ok((receipt, receiver, recovery_mode))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        address_registry::AddressRegistry,
        error::TempoPrecompileError,
        storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{TIP20Setup, VIRTUAL_MASTER, register_virtual_master},
        tip20::{BURN_BLOCKED_ROLE, ITIP20},
        tip403_registry::{ALLOW_ALL_POLICY_ID, REJECT_ALL_POLICY_ID, TIP403Registry},
    };
    use alloy::sol_types::SolValue;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{
        ITIP403Registry, ReceivePolicyGuardEvent, TIP20Error, TIP20Event,
    };

    fn block_all_senders(receiver: Address, recovery_authority: Address) -> Result<()> {
        TIP403Registry::new().set_receive_policy(
            receiver,
            ITIP403Registry::setReceivePolicyCall {
                senderPolicyId: REJECT_ALL_POLICY_ID,
                tokenFilterId: ALLOW_ALL_POLICY_ID,
                recoveryAuthority: recovery_authority,
            },
        )
    }

    fn assert_invalid_receipt(result: Result<()>) {
        assert_eq!(
            result.unwrap_err(),
            ReceivePolicyGuardError::invalid_receipt().into()
        );
    }

    fn assert_unauthorized(result: Result<()>) {
        assert_eq!(
            result.unwrap_err(),
            ReceivePolicyGuardError::unauthorized_claimer().into()
        );
    }

    #[test]
    fn test_claim_blocked_inbound() -> eyre::Result<()> {
        let admin = Address::random();
        let transfer_originator = Address::random();
        let receiver = Address::random();
        let amount = U256::from(100u64);
        let blocked_at = 1_728_000u64;

        for kind in [InboundKind::TRANSFER, InboundKind::MINT] {
            let originator = match kind {
                InboundKind::TRANSFER => transfer_originator,
                InboundKind::MINT => admin,
                InboundKind::__Invalid => unreachable!(),
            };

            let third_party = Address::random();
            for (configured_authority, claimer, destination, is_third_party) in [
                (RECOVERY_ORIGINATOR, originator, originator, false),
                (receiver, receiver, receiver, false),
                (third_party, third_party, Address::random(), true),
            ] {
                let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
                storage.set_timestamp(U256::from(blocked_at));

                StorageCtx::enter(&mut storage, || {
                    let mut setup = TIP20Setup::create("T", "T", admin).with_issuer(admin);
                    if matches!(kind, InboundKind::TRANSFER) {
                        setup = setup.with_mint(originator, amount);
                    }
                    let mut token = setup.apply()?;
                    block_all_senders(receiver, configured_authority)?;

                    let unknown = ClaimReceiptV1::new(
                        token.address(),
                        claimer,
                        originator,
                        receiver,
                        blocked_at,
                        99,
                        BlockedReason::RECEIVE_POLICY as u8,
                        kind,
                        B256::ZERO,
                    );
                    let mut guard = ReceivePolicyGuard::new();
                    assert_eq!(guard.balance_of(unknown.abi_encode().into())?, U256::ZERO);

                    guard.clear_emitted_events();
                    token.clear_emitted_events();
                    match kind {
                        InboundKind::TRANSFER => {
                            token.transfer(
                                originator,
                                ITIP20::transferCall {
                                    to: receiver,
                                    amount,
                                },
                            )?;
                            token.assert_emitted_events(vec![TIP20Event::transfer(
                                originator,
                                RECEIVE_POLICY_GUARD_ADDRESS,
                                amount,
                            )]);
                        }
                        InboundKind::MINT => {
                            token.mint(
                                admin,
                                ITIP20::mintCall {
                                    to: receiver,
                                    amount,
                                },
                            )?;
                            token.assert_emitted_events(vec![
                                TIP20Event::transfer(
                                    Address::ZERO,
                                    RECEIVE_POLICY_GUARD_ADDRESS,
                                    amount,
                                ),
                                TIP20Event::mint(RECEIVE_POLICY_GUARD_ADDRESS, amount),
                            ]);
                        }
                        InboundKind::__Invalid => unreachable!(),
                    }
                    guard.assert_emitted_events(vec![ReceivePolicyGuardEvent::TransferBlocked(
                        IReceivePolicyGuard::TransferBlocked {
                            token: token.address(),
                            from: originator,
                            receiver,
                            receiptVersion: BLOCKED_RECEIPT_VERSION,
                            blockedNonce: 1,
                            blockedAt: blocked_at,
                            recipient: receiver,
                            amount,
                            blockedReason: BlockedReason::RECEIVE_POLICY as u8,
                            recoveryAuthority: claimer,
                            memo: B256::ZERO,
                        },
                    )]);

                    let receipt = ClaimReceiptV1::new(
                        token.address(),
                        claimer,
                        originator,
                        receiver,
                        blocked_at,
                        1,
                        BlockedReason::RECEIVE_POLICY as u8,
                        kind,
                        B256::ZERO,
                    );
                    assert_eq!(guard.balance_of(receipt.abi_encode().into())?, amount);

                    if is_third_party {
                        assert_unauthorized(guard.claim(
                            receiver,
                            receiver,
                            receipt.abi_encode().into(),
                        ));
                        assert_unauthorized(guard.claim(
                            Address::random(),
                            receiver,
                            receipt.abi_encode().into(),
                        ));
                        assert_eq!(guard.balance_of(receipt.abi_encode().into())?, amount);
                    }

                    guard.clear_emitted_events();
                    guard.claim(claimer, destination, receipt.abi_encode().into())?;
                    guard.assert_emitted_events(vec![ReceivePolicyGuardEvent::ReceiptClaimed(
                        IReceivePolicyGuard::ReceiptClaimed {
                            token: token.address(),
                            receiver,
                            receiptVersion: BLOCKED_RECEIPT_VERSION,
                            blockedNonce: 1,
                            blockedAt: blocked_at,
                            originator,
                            recipient: receiver,
                            recoveryAuthority: claimer,
                            caller: claimer,
                            to: destination,
                            amount,
                        },
                    )]);

                    assert_eq!(guard.balance_of(receipt.abi_encode().into())?, U256::ZERO);
                    assert_eq!(
                        token.balance_of(ITIP20::balanceOfCall {
                            account: RECEIVE_POLICY_GUARD_ADDRESS
                        })?,
                        U256::ZERO
                    );
                    assert_eq!(
                        token.balance_of(ITIP20::balanceOfCall {
                            account: destination
                        })?,
                        amount
                    );

                    Ok::<(), TempoPrecompileError>(())
                })?;
            }
        }

        Ok(())
    }

    #[test]
    fn test_burn_blocked_receipt_emits_receipt_burned() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        let blocked_at = 1_728_010u64;
        storage.set_timestamp(U256::from(blocked_at));

        let admin = Address::random();
        let burner = Address::random();
        let originator = Address::random();
        let receiver = Address::random();
        let amount = U256::from(100u64);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("T", "T", admin)
                .with_issuer(admin)
                .with_role(burner, *BURN_BLOCKED_ROLE)
                .with_mint(originator, amount)
                .apply()?;
            block_all_senders(receiver, receiver)?;

            token.transfer(
                originator,
                ITIP20::transferCall {
                    to: receiver,
                    amount,
                },
            )?;

            let receipt = ClaimReceiptV1::new(
                token.address(),
                receiver,
                originator,
                receiver,
                blocked_at,
                1,
                BlockedReason::RECEIVE_POLICY as u8,
                InboundKind::TRANSFER,
                B256::ZERO,
            );

            let mut registry = TIP403Registry::new();
            let policy_id = registry.create_policy(
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::BLACKLIST,
                },
            )?;
            registry.modify_policy_blacklist(
                admin,
                ITIP403Registry::modifyPolicyBlacklistCall {
                    policyId: policy_id,
                    account: receiver,
                    restricted: true,
                },
            )?;
            token.change_transfer_policy_id(
                admin,
                ITIP20::changeTransferPolicyIdCall {
                    newPolicyId: policy_id,
                },
            )?;

            let mut guard = ReceivePolicyGuard::new();
            guard.clear_emitted_events();

            guard.burn_blocked_receipt(burner, receipt.abi_encode().into())?;

            guard.assert_emitted_events(vec![ReceivePolicyGuardEvent::ReceiptBurned(
                IReceivePolicyGuard::ReceiptBurned {
                    token: token.address(),
                    receiver,
                    receiptVersion: BLOCKED_RECEIPT_VERSION,
                    blockedNonce: 1,
                    blockedAt: blocked_at,
                    originator,
                    recipient: receiver,
                    recoveryAuthority: receiver,
                    caller: burner,
                    amount,
                },
            )]);
            assert_eq!(guard.balance_of(receipt.abi_encode().into())?, U256::ZERO);

            Ok(())
        })
    }

    #[test]
    fn test_claim_rejects_when_token_paused() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        let blocked_at = 1_728_000u64;
        storage.set_timestamp(U256::from(blocked_at));

        let admin = Address::random();
        let originator = Address::random();
        let receiver = Address::random();
        let amount = U256::from(100u64);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("T", "T", admin)
                .with_issuer(admin)
                .with_role(admin, TIP20Token::pause_role())
                .with_mint(originator, amount)
                .apply()?;
            block_all_senders(receiver, receiver)?;

            token.transfer(
                originator,
                ITIP20::transferCall {
                    to: receiver,
                    amount,
                },
            )?;
            token.pause(admin, ITIP20::pauseCall {})?;

            let receipt = ClaimReceiptV1::new(
                token.address(),
                receiver,
                originator,
                receiver,
                blocked_at,
                1,
                BlockedReason::RECEIVE_POLICY as u8,
                InboundKind::TRANSFER,
                B256::ZERO,
            );
            let mut guard = ReceivePolicyGuard::new();
            let result = guard.claim(receiver, receiver, receipt.abi_encode().into());
            assert_eq!(result.unwrap_err(), TIP20Error::contract_paused().into());

            Ok(())
        })
    }

    #[test]
    fn test_receive_policy_guard_balance_matches_open_receipts() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        storage.set_timestamp(U256::from(1_728_001u64));

        let admin = Address::random();
        let originator = Address::random();
        let receiver_a = Address::random();
        let receiver_b = Address::random();
        let receiver_c = Address::random();
        let recovery = Address::random();
        let amount_a = U256::from(30u64);
        let amount_b = U256::from(45u64);
        let amount_c = U256::from(70u64);

        StorageCtx::enter(&mut storage, || {
            let mut token_a = TIP20Setup::create("A", "A", admin)
                .with_issuer(admin)
                .with_mint(originator, amount_a + amount_b)
                .apply()?;
            let mut token_b = TIP20Setup::create("B", "B", admin)
                .with_issuer(admin)
                .with_mint(originator, amount_c)
                .apply()?;

            block_all_senders(receiver_a, receiver_a)?;
            block_all_senders(receiver_b, recovery)?;
            block_all_senders(receiver_c, receiver_c)?;

            token_a.transfer(
                originator,
                ITIP20::transferCall {
                    to: receiver_a,
                    amount: amount_a,
                },
            )?;
            token_a.transfer(
                originator,
                ITIP20::transferCall {
                    to: receiver_b,
                    amount: amount_b,
                },
            )?;
            token_b.transfer(
                originator,
                ITIP20::transferCall {
                    to: receiver_c,
                    amount: amount_c,
                },
            )?;

            let receipt_a = ClaimReceiptV1::new(
                token_a.address(),
                receiver_a,
                originator,
                receiver_a,
                1_728_001,
                1,
                BlockedReason::RECEIVE_POLICY as u8,
                InboundKind::TRANSFER,
                B256::ZERO,
            );
            let receipt_b = ClaimReceiptV1::new(
                token_a.address(),
                recovery,
                originator,
                receiver_b,
                1_728_001,
                2,
                BlockedReason::RECEIVE_POLICY as u8,
                InboundKind::TRANSFER,
                B256::ZERO,
            );
            let receipt_c = ClaimReceiptV1::new(
                token_b.address(),
                receiver_c,
                originator,
                receiver_c,
                1_728_001,
                3,
                BlockedReason::RECEIVE_POLICY as u8,
                InboundKind::TRANSFER,
                B256::ZERO,
            );

            let mut guard = ReceivePolicyGuard::new();
            assert_eq!(
                token_a.balance_of(ITIP20::balanceOfCall {
                    account: RECEIVE_POLICY_GUARD_ADDRESS
                })?,
                guard.balance_of(receipt_a.abi_encode().into())?
                    + guard.balance_of(receipt_b.abi_encode().into())?
            );
            assert_eq!(
                token_b.balance_of(ITIP20::balanceOfCall {
                    account: RECEIVE_POLICY_GUARD_ADDRESS
                })?,
                guard.balance_of(receipt_c.abi_encode().into())?
            );

            guard.claim(receiver_a, receiver_a, receipt_a.abi_encode().into())?;
            assert_eq!(
                token_a.balance_of(ITIP20::balanceOfCall {
                    account: RECEIVE_POLICY_GUARD_ADDRESS
                })?,
                guard.balance_of(receipt_b.abi_encode().into())?
            );
            assert_eq!(
                token_b.balance_of(ITIP20::balanceOfCall {
                    account: RECEIVE_POLICY_GUARD_ADDRESS
                })?,
                guard.balance_of(receipt_c.abi_encode().into())?
            );

            guard.claim(recovery, recovery, receipt_b.abi_encode().into())?;
            assert_eq!(
                token_a.balance_of(ITIP20::balanceOfCall {
                    account: RECEIVE_POLICY_GUARD_ADDRESS
                })?,
                U256::ZERO
            );
            assert_eq!(
                token_b.balance_of(ITIP20::balanceOfCall {
                    account: RECEIVE_POLICY_GUARD_ADDRESS
                })?,
                guard.balance_of(receipt_c.abi_encode().into())?
            );

            Ok(())
        })
    }

    #[test]
    fn test_receipt_rejects_bad_encoding() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);

        StorageCtx::enter(&mut storage, || {
            let guard = ReceivePolicyGuard::new();
            let result = guard.balance_of(vec![0xde, 0xad, 0xbe, 0xef].into());
            assert!(matches!(
                result,
                Err(e) if e == ReceivePolicyGuardError::invalid_receipt().into()
            ));

            Ok(())
        })
    }

    #[test]
    fn test_store_rejects_invalid_metadata() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("T", "T", admin).apply()?;
            let mut guard = ReceivePolicyGuard::new();

            for (blocked_reason, kind) in [
                (BlockedReason::NONE, InboundKind::TRANSFER),
                (BlockedReason::__Invalid, InboundKind::TRANSFER),
                (BlockedReason::RECEIVE_POLICY, InboundKind::__Invalid),
            ] {
                let result = guard.store_blocked(
                    token.address(),
                    Address::random(),
                    &Recipient::direct(Address::random()),
                    Address::ZERO,
                    U256::from(1u64),
                    blocked_reason,
                    kind,
                    B256::ZERO,
                );
                assert!(matches!(
                    result,
                    Err(e) if e == ReceivePolicyGuardError::invalid_receipt().into()
                ));
            }

            Ok(())
        })
    }

    #[test]
    fn test_receipt_key_binds_receipt_fields() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        storage.set_timestamp(U256::from(1_728_002u64));

        let admin = Address::random();
        let originator_a = Address::random();
        let originator_b = Address::random();
        let recipient = Address::random();
        let recovery = Address::random();
        let memo = B256::repeat_byte(0x11);
        let amount_a = U256::from(10u64);
        let amount_b = U256::from(20u64);

        StorageCtx::enter(&mut storage, || {
            let token_a = TIP20Setup::create("A", "A", admin).apply()?;
            let token_b = TIP20Setup::create("B", "B", admin).apply()?;
            let mut guard = ReceivePolicyGuard::new();

            let (nonce_a, blocked_at_a) = guard.store_blocked(
                token_a.address(),
                originator_a,
                &Recipient::direct(recipient),
                recovery,
                amount_a,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                memo,
            )?;
            let (nonce_b, blocked_at_b) = guard.store_blocked(
                token_b.address(),
                originator_b,
                &Recipient::direct(recipient),
                recovery,
                amount_b,
                BlockedReason::TOKEN_FILTER,
                InboundKind::MINT,
                B256::repeat_byte(0x22),
            )?;

            let receipt_a = ClaimReceiptV1::new(
                token_a.address(),
                recovery,
                originator_a,
                recipient,
                blocked_at_a,
                nonce_a,
                BlockedReason::RECEIVE_POLICY as u8,
                InboundKind::TRANSFER,
                memo,
            );
            let receipt_b = ClaimReceiptV1::new(
                token_b.address(),
                recovery,
                originator_b,
                recipient,
                blocked_at_b,
                nonce_b,
                BlockedReason::TOKEN_FILTER as u8,
                InboundKind::MINT,
                B256::repeat_byte(0x22),
            );

            assert_eq!(guard.balance_of(receipt_a.abi_encode().into())?, amount_a);
            assert_eq!(guard.balance_of(receipt_b.abi_encode().into())?, amount_b);

            let mutated_receipts = [
                ClaimReceiptV1::new(
                    token_a.address(),
                    recovery,
                    Address::random(),
                    recipient,
                    blocked_at_a,
                    nonce_a,
                    BlockedReason::RECEIVE_POLICY as u8,
                    InboundKind::TRANSFER,
                    memo,
                ),
                ClaimReceiptV1::new(
                    token_a.address(),
                    recovery,
                    originator_a,
                    Address::random(),
                    blocked_at_a,
                    nonce_a,
                    BlockedReason::RECEIVE_POLICY as u8,
                    InboundKind::TRANSFER,
                    memo,
                ),
                ClaimReceiptV1::new(
                    token_a.address(),
                    recovery,
                    originator_a,
                    recipient,
                    blocked_at_a + 1,
                    nonce_a,
                    BlockedReason::RECEIVE_POLICY as u8,
                    InboundKind::TRANSFER,
                    memo,
                ),
                ClaimReceiptV1::new(
                    token_a.address(),
                    recovery,
                    originator_a,
                    recipient,
                    blocked_at_a,
                    nonce_a + 1,
                    BlockedReason::RECEIVE_POLICY as u8,
                    InboundKind::TRANSFER,
                    memo,
                ),
                ClaimReceiptV1::new(
                    token_a.address(),
                    recovery,
                    originator_a,
                    recipient,
                    blocked_at_a,
                    nonce_a,
                    BlockedReason::TOKEN_FILTER as u8,
                    InboundKind::TRANSFER,
                    memo,
                ),
                ClaimReceiptV1::new(
                    token_a.address(),
                    recovery,
                    originator_a,
                    recipient,
                    blocked_at_a,
                    nonce_a,
                    BlockedReason::RECEIVE_POLICY as u8,
                    InboundKind::MINT,
                    memo,
                ),
                ClaimReceiptV1::new(
                    token_a.address(),
                    recovery,
                    originator_a,
                    recipient,
                    blocked_at_a,
                    nonce_a,
                    BlockedReason::RECEIVE_POLICY as u8,
                    InboundKind::TRANSFER,
                    B256::repeat_byte(0x33),
                ),
            ];

            for mutated in mutated_receipts {
                assert_eq!(guard.balance_of(mutated.abi_encode().into())?, U256::ZERO);
            }
            assert_eq!(guard.balance_of(receipt_a.abi_encode().into())?, amount_a);
            assert_eq!(guard.balance_of(receipt_b.abi_encode().into())?, amount_b);

            Ok(())
        })
    }

    #[test]
    fn test_claim_rejects_missing_receipt() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        storage.set_timestamp(U256::from(1_728_003u64));

        let admin = Address::random();
        let originator = Address::random();
        let receiver = Address::random();
        let amount = U256::from(100u64);
        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("T", "T", admin)
                .with_issuer(admin)
                .with_mint(originator, amount)
                .apply()?;

            let receipt = ClaimReceiptV1::new(
                token.address(),
                receiver,
                originator,
                receiver,
                1_728_003,
                1,
                BlockedReason::RECEIVE_POLICY as u8,
                InboundKind::TRANSFER,
                B256::ZERO,
            );

            let mut guard = ReceivePolicyGuard::new();
            assert_invalid_receipt(guard.claim(receiver, receiver, receipt.abi_encode().into()));

            block_all_senders(receiver, receiver)?;
            token.transfer(
                originator,
                ITIP20::transferCall {
                    to: receiver,
                    amount,
                },
            )?;
            guard.claim(receiver, receiver, receipt.abi_encode().into())?;
            assert_invalid_receipt(guard.claim(receiver, receiver, receipt.abi_encode().into()));

            Ok(())
        })
    }

    #[test]
    fn test_claim_requires_authorized_caller() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        storage.set_timestamp(U256::from(1_728_004u64));

        let admin = Address::random();
        let originator = Address::random();
        let receiver = Address::random();
        let recovery_receiver = Address::random();
        let recovery = Address::random();
        let stranger = Address::random();
        let amount = U256::from(50u64);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("T", "T", admin)
                .with_issuer(admin)
                .with_mint(originator, amount * U256::from(2u64))
                .apply()?;
            block_all_senders(receiver, receiver)?;
            block_all_senders(recovery_receiver, recovery)?;

            token.transfer(
                originator,
                ITIP20::transferCall {
                    to: receiver,
                    amount,
                },
            )?;
            token.transfer(
                originator,
                ITIP20::transferCall {
                    to: recovery_receiver,
                    amount,
                },
            )?;

            let self_receipt = ClaimReceiptV1::new(
                token.address(),
                receiver,
                originator,
                receiver,
                1_728_004,
                1,
                BlockedReason::RECEIVE_POLICY as u8,
                InboundKind::TRANSFER,
                B256::ZERO,
            );
            let recovery_receipt = ClaimReceiptV1::new(
                token.address(),
                recovery,
                originator,
                recovery_receiver,
                1_728_004,
                2,
                BlockedReason::RECEIVE_POLICY as u8,
                InboundKind::TRANSFER,
                B256::ZERO,
            );

            let mut guard = ReceivePolicyGuard::new();
            assert_unauthorized(guard.claim(stranger, receiver, self_receipt.abi_encode().into()));
            for caller in [recovery_receiver, stranger] {
                assert_unauthorized(guard.claim(
                    caller,
                    recovery_receiver,
                    recovery_receipt.abi_encode().into(),
                ));
            }
            assert_eq!(guard.balance_of(self_receipt.abi_encode().into())?, amount);
            assert_eq!(
                guard.balance_of(recovery_receipt.abi_encode().into())?,
                amount
            );

            Ok(())
        })
    }

    #[test]
    fn test_claim_virtual_recipient() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        storage.set_timestamp(U256::from(1_728_009u64));

        let admin = Address::random();
        let originator = Address::random();
        let amount = U256::from(123u64);

        StorageCtx::enter(&mut storage, || {
            let (_, virtual_addr) = register_virtual_master(&mut AddressRegistry::new())?;
            let mut token = TIP20Setup::create("T", "T", admin)
                .with_issuer(admin)
                .with_mint(originator, amount)
                .apply()?;
            block_all_senders(VIRTUAL_MASTER, VIRTUAL_MASTER)?;
            let mut guard = ReceivePolicyGuard::new();
            guard.clear_emitted_events();
            token.transfer(
                originator,
                ITIP20::transferCall {
                    to: virtual_addr,
                    amount,
                },
            )?;

            let receipt = ClaimReceiptV1::new(
                token.address(),
                VIRTUAL_MASTER,
                originator,
                virtual_addr,
                1_728_009,
                1,
                BlockedReason::RECEIVE_POLICY as u8,
                InboundKind::TRANSFER,
                B256::ZERO,
            );
            guard.assert_emitted_events(vec![ReceivePolicyGuardEvent::TransferBlocked(
                IReceivePolicyGuard::TransferBlocked {
                    token: token.address(),
                    from: originator,
                    receiver: VIRTUAL_MASTER,
                    receiptVersion: BLOCKED_RECEIPT_VERSION,
                    blockedNonce: 1,
                    blockedAt: 1_728_009,
                    recipient: virtual_addr,
                    amount,
                    blockedReason: BlockedReason::RECEIVE_POLICY as u8,
                    recoveryAuthority: VIRTUAL_MASTER,
                    memo: B256::ZERO,
                },
            )]);
            guard.clear_emitted_events();
            guard.claim(VIRTUAL_MASTER, VIRTUAL_MASTER, receipt.abi_encode().into())?;

            guard.assert_emitted_events(vec![ReceivePolicyGuardEvent::ReceiptClaimed(
                IReceivePolicyGuard::ReceiptClaimed {
                    token: token.address(),
                    receiver: VIRTUAL_MASTER,
                    receiptVersion: BLOCKED_RECEIPT_VERSION,
                    blockedNonce: 1,
                    blockedAt: 1_728_009,
                    originator,
                    recipient: virtual_addr,
                    recoveryAuthority: VIRTUAL_MASTER,
                    caller: VIRTUAL_MASTER,
                    to: VIRTUAL_MASTER,
                    amount,
                },
            )]);
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: VIRTUAL_MASTER
                })?,
                amount
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: virtual_addr
                })?,
                U256::ZERO
            );

            Ok(())
        })
    }
}
