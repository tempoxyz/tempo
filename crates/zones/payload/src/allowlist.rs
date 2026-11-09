//! Reads of the on-chain `ZoneAllowlist` outside the EVM, and the transfer screen built on them.
//!
//! The allowlist is enforced only where blocks are built, so followers and the prover accept any
//! block. Pool admission rejects a transaction whose calls move TIP-20 funds to or from an unlisted
//! account, and the leader's builder checks each pool transaction again against the list as of the
//! parent block, which catches list changes after admission.
//!
//! Checking calldata is enough on zones: contract creation and authorization lists are disabled,
//! and T15, which enables transfers, removes the Multicall3 and Permit2 predeploys. Funds can only
//! move through the TIP-20 calls screened here, the outbox, and fees. `ReceivePolicyGuard` claims
//! need no screen: from T15 zone precompiles revert blocked inbounds instead of diverting them to
//! the guard, and earlier the inbox reverts a mint the receive policy blocks, so the guard never
//! holds funds on a zone.

use alloy_primitives::{Address, TxKind};
use alloy_sol_types::SolCall as _;
use evm2::registry::HandlerError;
use reth_errors::ProviderError;
use reth_storage_api::StateProvider;
use reth_transaction_pool::{PoolTransaction as _, error::InvalidPoolTransactionError};
use tempo_contracts::precompiles::ITIP20;
use tempo_primitives::TempoAddressExt as _;
use tempo_transaction_pool::transaction::{TempoPoolTransactionError, TempoPooledTransaction};
use zone_precompiles::{ZONE_ALLOWLIST_ADDRESS, allowlist};

use crate::abi::{IZoneOutbox, ZONE_OUTBOX_ADDRESS};

/// The zone allowlist as of one state, read by raw slot.
pub struct Allowlist<'a> {
    state: &'a dyn StateProvider,
    enabled: bool,
}

impl<'a> Allowlist<'a> {
    /// Reads whether enforcement is enabled in `state`. Before T15, and until the admin enables
    /// it, the slot is empty and every account is allowed.
    pub fn read(state: &'a dyn StateProvider) -> Result<Self, ProviderError> {
        let enabled = state
            .storage(ZONE_ALLOWLIST_ADDRESS, allowlist::slots::ENABLED.into())?
            .unwrap_or_default();
        Ok(Self {
            state,
            enabled: !enabled.is_zero(),
        })
    }

    /// Whether `account` may deposit, receive deposits and transfer: true while enforcement is
    /// disabled, or when it is listed.
    pub fn allows(&self, account: Address) -> Result<bool, ProviderError> {
        if !self.enabled {
            return Ok(true);
        }
        let index = self.state.storage(
            ZONE_ALLOWLIST_ADDRESS,
            allowlist::member_index_slot(account).into(),
        )?;
        Ok(index.is_some_and(|index| !index.is_zero()))
    }

    /// Whether every account in `accounts` is allowed.
    pub fn allows_all(&self, accounts: &[Address]) -> Result<bool, ProviderError> {
        for account in accounts {
            if !self.allows(*account)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Why a transaction failed the transfer screen.
#[derive(Debug, thiserror::Error)]
pub enum TransferScreenError {
    /// The allowlist could not be read from state.
    #[error(transparent)]
    State(#[from] ProviderError),
    /// The transaction moves funds to or from an unlisted account, or a screened call does not
    /// decode.
    #[error(transparent)]
    Rejected(InvalidPoolTransactionError),
}

/// Reject a transaction whose calls move TIP-20 funds or name a withdrawal fallback recipient
/// outside `allowlist`, or call `transferFrom` from an unlisted account. Every party of the
/// transaction is checked against one state.
///
/// Pool admission calls this on submission against the latest state, and the leader's builder
/// calls it again against the parent state before executing each pool transaction.
pub fn validate_transfer_calls(
    allowlist: &Allowlist<'_>,
    tx: &TempoPooledTransaction,
) -> Result<(), TransferScreenError> {
    let sender = *tx.sender_ref();
    let mut parties = Vec::new();
    for (kind, input) in tx.inner().calls() {
        if let TxKind::Call(target) = kind {
            push_parties(sender, target, input, &mut parties)
                .map_err(TransferScreenError::Rejected)?;
        }
    }
    if parties.is_empty() || allowlist.allows_all(&parties)? {
        Ok(())
    } else {
        Err(TransferScreenError::Rejected(transfer_error(
            "transfer sender or recipient is not allowlisted",
        )))
    }
}

/// Push the accounts that a call from `sender` to `target` moves Zone funds between onto
/// `parties`.
///
/// Fails when `input` has a screened selector but does not decode. The precompile would revert
/// such a call, and admitting it unscreened would rely on both decoders agreeing.
fn push_parties(
    sender: Address,
    target: Address,
    input: &[u8],
    parties: &mut Vec<Address>,
) -> Result<(), InvalidPoolTransactionError> {
    let Some(&selector) = input.first_chunk::<4>() else {
        return Ok(());
    };
    let malformed = |_| transfer_error("malformed transfer calldata");
    if target.is_tip20() {
        // A listed spender is required, so `transferFrom(a, b, 0)` cannot probe the list.
        let (spender, from, to) = match selector {
            ITIP20::transferCall::SELECTOR => {
                ITIP20::transferCall::abi_decode(input).map(|call| (None, sender, call.to))
            }
            ITIP20::transferWithMemoCall::SELECTOR => {
                ITIP20::transferWithMemoCall::abi_decode(input).map(|call| (None, sender, call.to))
            }
            ITIP20::transferFromCall::SELECTOR => ITIP20::transferFromCall::abi_decode(input)
                .map(|call| (Some(sender), call.from, call.to)),
            ITIP20::transferFromWithMemoCall::SELECTOR => {
                ITIP20::transferFromWithMemoCall::abi_decode(input)
                    .map(|call| (Some(sender), call.from, call.to))
            }
            _ => return Ok(()),
        }
        .map_err(malformed)?;
        parties.extend(spender);
        // Moving funds into the outbox withdraws, which an unlisted account may still do.
        if from != ZONE_OUTBOX_ADDRESS && to != ZONE_OUTBOX_ADDRESS {
            parties.extend([from, to]);
        }
    } else if target == ZONE_OUTBOX_ADDRESS
        && selector == IZoneOutbox::requestWithdrawalCall::SELECTOR
    {
        let call = IZoneOutbox::requestWithdrawalCall::abi_decode(input).map_err(malformed)?;
        // The fallback is credited if the withdrawal bounces back from L1. Naming oneself is
        // always allowed, so an unlisted account can still withdraw.
        if call.zoneFallbackRecipient != sender {
            parties.extend([sender, call.zoneFallbackRecipient]);
        }
    }
    Ok(())
}

/// Pool error for a transaction that fails the transfer screen. It does not say which account
/// failed the check.
fn transfer_error(reason: &'static str) -> InvalidPoolTransactionError {
    InvalidPoolTransactionError::other(TempoPoolTransactionError::Evm(HandlerError::External(
        reason.into(),
    )))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloy_consensus::{Signed, TxEip1559};
    use alloy_primitives::{B256, Bytes, Signature, U256, address};
    use reth_primitives_traits::Recovered;
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use reth_storage_api::StateProviderFactory as _;
    use tempo_primitives::{
        TempoPrimitives, TempoTxEnvelope,
        transaction::{Call, TempoTransaction},
    };

    const ALICE: Address = address!("0x00000000000000000000000000000000000a11ce");
    const BOB: Address = address!("0x0000000000000000000000000000000000000b0b");
    const CAROL: Address = address!("0x00000000000000000000000000000000000ca201");

    /// Zone state whose allowlist has enforcement `enabled` and lists `members`.
    pub(crate) fn state(enabled: bool, members: &[Address]) -> MockEthProvider<TempoPrimitives> {
        let provider = MockEthProvider::<TempoPrimitives>::new();
        provider.add_account(
            ZONE_ALLOWLIST_ADDRESS,
            ExtendedAccount::new(0, U256::ZERO).extend_storage(
                allowlist::storage_entries(enabled, members)
                    .into_iter()
                    .map(|(slot, value)| (B256::from(slot), value)),
            ),
        );
        provider
    }

    fn call(to: Address, input: impl Into<Bytes>) -> Call {
        Call {
            to: TxKind::Call(to),
            value: U256::ZERO,
            input: input.into(),
        }
    }

    fn token_transfer(to: Address) -> Call {
        call(
            Address::new_tip20(0),
            ITIP20::transferCall {
                to,
                amount: U256::ONE,
            }
            .abi_encode(),
        )
    }

    fn token_transfer_from(from: Address, to: Address) -> Call {
        call(
            Address::new_tip20(0),
            ITIP20::transferFromWithMemoCall {
                from,
                to,
                amount: U256::ONE,
                memo: Default::default(),
            }
            .abi_encode(),
        )
    }

    fn request_withdrawal(fallback_recipient: Address) -> Call {
        call(
            ZONE_OUTBOX_ADDRESS,
            IZoneOutbox::requestWithdrawalCall {
                token: Address::new_tip20(0),
                to: fallback_recipient,
                amount: 1,
                memo: Default::default(),
                gasLimit: 0,
                zoneFallbackRecipient: fallback_recipient,
                data: Bytes::new(),
                revealTo: Bytes::new(),
            }
            .abi_encode(),
        )
    }

    fn pooled_transaction(envelope: TempoTxEnvelope, sender: Address) -> TempoPooledTransaction {
        TempoPooledTransaction::new(Recovered::new_unchecked(envelope, sender))
    }

    fn aa_transaction(sender: Address, calls: Vec<Call>) -> TempoPooledTransaction {
        let transaction = TempoTransaction {
            calls,
            ..Default::default()
        };
        pooled_transaction(
            transaction
                .into_signed(Signature::test_signature().into())
                .into(),
            sender,
        )
    }

    /// Screens `tx` against an enabled list holding `members`.
    fn screen(members: &[Address], tx: &TempoPooledTransaction) -> Result<(), String> {
        let provider = state(true, members);
        let state = provider.latest().unwrap();
        let allowlist = Allowlist::read(state.as_ref()).unwrap();
        validate_transfer_calls(&allowlist, tx).map_err(|err| match err {
            TransferScreenError::Rejected(err) => err.to_string(),
            TransferScreenError::State(err) => panic!("state read failed: {err}"),
        })
    }

    /// Checks an AA transaction from `sender` against a list holding ALICE and BOB.
    fn admits_calls(sender: Address, calls: Vec<Call>) -> bool {
        match screen(&[ALICE, BOB], &aa_transaction(sender, calls)) {
            Ok(()) => true,
            Err(err) => {
                assert_eq!(
                    err,
                    transfer_error("transfer sender or recipient is not allowlisted").to_string()
                );
                false
            }
        }
    }

    #[test]
    fn disabled_or_empty_state_allows_everyone() {
        for provider in [state(false, &[ALICE]), MockEthProvider::new()] {
            let state = provider.latest().unwrap();
            let allowlist = Allowlist::read(state.as_ref()).unwrap();
            assert!(allowlist.allows_all(&[ALICE, BOB, CAROL]).unwrap());
        }
        let provider = state(true, &[ALICE]);
        let state = provider.latest().unwrap();
        let allowlist = Allowlist::read(state.as_ref()).unwrap();
        assert!(allowlist.allows(ALICE).unwrap());
        assert!(!allowlist.allows(BOB).unwrap());
        assert!(allowlist.allows_all(&[]).unwrap());
        assert!(!allowlist.allows_all(&[ALICE, BOB]).unwrap());
    }

    #[test]
    fn transfers_need_both_parties_listed() {
        assert!(admits_calls(ALICE, vec![token_transfer(BOB)]));
        assert!(!admits_calls(ALICE, vec![token_transfer(CAROL)]));
        assert!(!admits_calls(CAROL, vec![token_transfer(ALICE)]));
        // Any unlisted call rejects the whole batch.
        assert!(!admits_calls(
            ALICE,
            vec![token_transfer(BOB), token_transfer(CAROL)]
        ));
        // The spender, owner, and recipient must all be listed.
        assert!(admits_calls(BOB, vec![token_transfer_from(ALICE, BOB)]));
        assert!(!admits_calls(ALICE, vec![token_transfer_from(CAROL, BOB)]));
        assert!(!admits_calls(
            ALICE,
            vec![token_transfer_from(ALICE, CAROL)]
        ));
        // An unlisted spender is rejected whatever parties it names, so it cannot use the result
        // to learn whether they are listed.
        assert!(!admits_calls(CAROL, vec![token_transfer_from(ALICE, BOB)]));
        assert!(!admits_calls(
            CAROL,
            vec![token_transfer_from(ALICE, ALICE)]
        ));
        assert!(!admits_calls(
            CAROL,
            vec![token_transfer_from(CAROL, CAROL)]
        ));
        // Transfer calldata sent to a non-token contract moves no TIP-20 funds.
        assert!(admits_calls(
            ALICE,
            vec![call(
                CAROL,
                ITIP20::transferCall {
                    to: CAROL,
                    amount: U256::ONE
                }
                .abi_encode()
            )]
        ));
    }

    #[test]
    fn unlisted_accounts_can_still_withdraw() {
        assert!(admits_calls(
            CAROL,
            vec![token_transfer(ZONE_OUTBOX_ADDRESS)]
        ));
        assert!(admits_calls(CAROL, vec![request_withdrawal(CAROL)]));
    }

    #[test]
    fn withdrawal_fallback_recipients_need_both_parties_listed_unless_self() {
        assert!(admits_calls(ALICE, vec![request_withdrawal(BOB)]));
        assert!(!admits_calls(CAROL, vec![request_withdrawal(ALICE)]));
        assert!(!admits_calls(ALICE, vec![request_withdrawal(CAROL)]));
    }

    #[test]
    fn malformed_screened_calls_are_rejected() {
        let truncated = |call: Call| {
            let mut input = call.input.to_vec();
            input.truncate(input.len() - 1);
            Call {
                input: input.into(),
                ..call
            }
        };
        let screened = [
            token_transfer(BOB),
            token_transfer_from(ALICE, BOB),
            request_withdrawal(BOB),
        ];
        for call in screened {
            let err =
                screen(&[ALICE, BOB], &aa_transaction(ALICE, vec![truncated(call)])).unwrap_err();
            assert_eq!(
                err,
                transfer_error("malformed transfer calldata").to_string()
            );
        }
        // Calls the screen does not inspect are left to the precompile.
        assert!(admits_calls(
            CAROL,
            vec![truncated(call(
                Address::new_tip20(0),
                ITIP20::approveCall {
                    spender: CAROL,
                    amount: U256::ONE
                }
                .abi_encode()
            ))]
        ));
    }

    #[test]
    fn non_aa_transfers_are_checked() {
        let envelope = TempoTxEnvelope::Eip1559(Signed::new_unhashed(
            TxEip1559 {
                to: TxKind::Call(Address::new_tip20(0)),
                input: ITIP20::transferCall {
                    to: BOB,
                    amount: U256::ONE,
                }
                .abi_encode()
                .into(),
                ..Default::default()
            },
            Signature::test_signature(),
        ));
        let transaction = pooled_transaction(envelope, ALICE);
        assert!(screen(&[ALICE], &transaction).is_err());
        assert!(screen(&[ALICE, BOB], &transaction).is_ok());
    }
}
