//! Inferred account and storage prerequisites for transfer-shaped TIP-20 calls.
//!
//! This helper records a deterministic prewarming superset for transactions composed only of
//! supported TIP-20 transfer variants. For every supported call, it records the token account and
//! the token-level storage slots for `PAUSED`, `TRANSFER_POLICY_ID`, `GLOBAL_REWARD_PER_TOKEN`, and
//! `OPTED_IN_SUPPLY`.
//!
//! For direct transfer parties, it records the TIP-20 holder slots for the party:
//! `balances[holder]` and `userRewardInfo[holder] + 0`, `+ 1`, and `+ 2`.
//!
//! For T3+ virtual recipients, it records the address registry account and the
//! `AddressRegistry::data[master_id]` slot instead of recipient balance or reward slots. The
//! unresolved master account's token slots are intentionally left for a later state-derived
//! expansion step.
//!
//! The account and storage iterators preserve inferred transaction order and may contain
//! duplicates.

use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_sol_types::SolInterface;
use smallvec::SmallVec;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::ADDRESS_REGISTRY_ADDRESS;
use tempo_precompiles::{
    address_registry,
    storage::StorageKey,
    tip20::{self, ITIP20, TIP20Token},
};
use tempo_primitives::{MasterId, TempoAddressExt};

/// Inferred account and storage prerequisites for a transaction composed only of
/// transfer-shaped TIP-20 calls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InferredTip20Prerequisites {
    /// Decoded supported TIP-20 transfer calls, in transaction call order.
    ///
    /// These are derived from `TempoTxEnvelope::calls()` by requiring each target to be
    /// `TxKind::Call(token)` where `token.is_tip20()`, then decoding calldata as
    /// [`ITIP20::ITIP20Calls`]. `transfer` and `transferWithMemo` use the transaction sender as
    /// `from`; `transferFrom` and `transferFromWithMemo` use the transaction sender as `spender`
    /// and the decoded calldata `from` as owner. Recipient classification is derived from the
    /// decoded `to` address and the provided hardfork. The inline capacity is optimized for the
    /// common single-call transaction; multi-call AA transactions spill as needed.
    ///
    /// This is call metadata, not a union of preload addresses. For example, `from` and direct
    /// `to` are retained here as transfer parties, but their TIP-20 state is loaded through
    /// `storage_slots` on the token account rather than as separate account entries.
    calls: SmallVec<[InferredTip20TransferCall; 1]>,
    /// Account addresses in inferred transaction order.
    ///
    /// These are derived from the decoded call target and recipient classification. Every
    /// supported call records the TIP-20 `token` account from `TxKind::Call(token)`. T3+ virtual
    /// recipients also record [`ADDRESS_REGISTRY_ADDRESS`] because resolving the virtual
    /// recipient requires reading address-registry state. The inline capacity covers the largest
    /// single-call case: token plus address registry.
    ///
    /// This is not the union of all addresses contained in `calls`: direct `from` and `to`
    /// addresses are transfer parties, not account records that own the inferred TIP-20 storage
    /// slots. This list may contain duplicates.
    accounts: SmallVec<[Address; 2]>,
    /// Storage slots in inferred transaction order.
    ///
    /// These are derived from generated TIP-20 storage helpers and slot constants. For each
    /// supported call, this records fixed token slots from [`tip20::slots`], holder slots from
    /// [`TIP20Token`] for direct/effective-known transfer parties, `allowances[from][spender]` for
    /// `transferFrom` variants, and `AddressRegistry::data[master_id]` for T3+ virtual
    /// recipients. The inline capacity covers the largest single-call direct-recipient case:
    /// 4 common token slots, 4 owner holder slots, 4 recipient holder slots, and 1 allowance slot.
    /// This list may contain duplicates.
    storage_slots: SmallVec<[InferredStorageSlot; 13]>,
}

impl InferredTip20Prerequisites {
    /// Infers prerequisite account and storage touches for transfer-shaped TIP-20 calls.
    ///
    /// Returns `None` if any call in the transaction is not one of:
    /// `transfer`, `transferWithMemo`, `transferFrom`, or `transferFromWithMemo`
    /// to a TIP-20 token address.
    ///
    /// For `transfer` and `transferWithMemo`, `from` is inferred as the transaction sender.
    /// For `transferFrom` and `transferFromWithMemo`, `spender` is inferred as the transaction
    /// sender and `from` is decoded from calldata.
    pub(crate) fn new<'a>(
        calls: impl Iterator<Item = (TxKind, &'a Bytes)>,
        sender: Address,
        hardfork: TempoHardfork,
    ) -> Option<Self> {
        let mut prerequisites = Self {
            calls: SmallVec::new(),
            accounts: SmallVec::new(),
            storage_slots: SmallVec::new(),
        };

        for (kind, input) in calls {
            let call = infer_tip20_transfer_call(kind, input, sender, hardfork)?;
            prerequisites.push_call(call);
        }

        if prerequisites.calls.is_empty() {
            return None;
        }

        Some(prerequisites)
    }

    /// Returns the decoded transfer-shaped TIP-20 calls.
    pub fn calls(&self) -> &[InferredTip20TransferCall] {
        &self.calls
    }

    /// Returns precomputed account loads in inferred transaction order.
    ///
    /// This may contain duplicates.
    pub fn accounts(&self) -> impl Iterator<Item = Address> + '_ {
        self.accounts.iter().copied()
    }

    /// Returns precomputed storage slot loads in inferred transaction order.
    ///
    /// This may contain duplicates.
    pub fn storage_slots(&self) -> impl Iterator<Item = InferredStorageSlot> + '_ {
        self.storage_slots.iter().copied()
    }

    fn push_call(&mut self, call: InferredTip20TransferCall) {
        self.add_call_prerequisites(&call);
        self.calls.push(call);
    }

    fn add_call_prerequisites(&mut self, call: &InferredTip20TransferCall) {
        let token = call.token();
        self.accounts.push(token);

        if call.to().is_virtual() {
            self.accounts.push(ADDRESS_REGISTRY_ADDRESS);
        }

        self.add_common_tip20_slots(token);

        match call {
            InferredTip20TransferCall::Transfer { from, to, .. } => {
                self.add_tip20_holder_slots(token, *from);
                self.add_recipient_slots(token, *to);
            }
            InferredTip20TransferCall::TransferFrom {
                spender, from, to, ..
            } => {
                self.add_tip20_holder_slots(token, *from);
                self.add_recipient_slots(token, *to);
                self.add_tip20_slot(
                    token,
                    TIP20Token::from_address_unchecked(token).allowances[*from][*spender].slot(),
                );
            }
        }
    }

    fn add_common_tip20_slots(&mut self, token: Address) {
        self.add_tip20_slot(token, tip20::slots::PAUSED.into());
        self.add_tip20_slot(token, tip20::slots::TRANSFER_POLICY_ID.into());
        self.add_tip20_slot(token, tip20::slots::GLOBAL_REWARD_PER_TOKEN.into());
        self.add_tip20_slot(token, tip20::slots::OPTED_IN_SUPPLY.into());
    }

    fn add_recipient_slots(&mut self, token: Address, recipient: InferredTip20Recipient) {
        match recipient {
            InferredTip20Recipient::Direct(address) => self.add_tip20_holder_slots(token, address),
            InferredTip20Recipient::Virtual { master_id, .. } => {
                self.add_registry_slot(master_id.mapping_slot(address_registry::slots::DATA));
            }
        }
    }

    fn add_tip20_holder_slots(&mut self, token: Address, holder: Address) {
        let token_layout = TIP20Token::from_address_unchecked(token);
        self.add_tip20_slot(token, token_layout.balances[holder].slot());

        let reward_info_base = holder.mapping_slot(token_layout.user_reward_info.slot());
        self.add_tip20_slot(token, reward_info_base);
        self.add_tip20_slot(token, reward_info_base + U256::from(1));
        self.add_tip20_slot(token, reward_info_base + U256::from(2));
    }

    fn add_tip20_slot(&mut self, token: Address, slot: U256) {
        self.storage_slots.push(InferredStorageSlot {
            address: token,
            slot,
        });
    }

    fn add_registry_slot(&mut self, slot: U256) {
        self.storage_slots.push(InferredStorageSlot {
            address: ADDRESS_REGISTRY_ADDRESS,
            slot,
        });
    }
}

/// Supported transfer-shaped TIP-20 call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InferredTip20TransferCall {
    /// `transfer` or `transferWithMemo`.
    ///
    /// Recorded prerequisites:
    ///
    /// - accounts: the `token` account; for T3+ virtual recipients, the address registry account
    /// - token slots: common TIP-20 slots
    /// - sender slots: `balances[from]` and `userRewardInfo[from] + 0`, `+ 1`, `+ 2`
    /// - direct recipient slots: `balances[to]` and `userRewardInfo[to] + 0`, `+ 1`, `+ 2`
    /// - T3+ virtual recipient slots: `AddressRegistry::data[master_id]`, with no unresolved
    ///   recipient balance or reward slots
    Transfer {
        token: Address,
        from: Address,
        to: InferredTip20Recipient,
    },
    /// `transferFrom` or `transferFromWithMemo`.
    ///
    /// Recorded prerequisites:
    ///
    /// - accounts: the `token` account; for T3+ virtual recipients, the address registry account
    /// - token slots: common TIP-20 slots
    /// - owner slots: `balances[from]` and `userRewardInfo[from] + 0`, `+ 1`, `+ 2`
    /// - direct recipient slots: `balances[to]` and `userRewardInfo[to] + 0`, `+ 1`, `+ 2`
    /// - allowance slot: `allowances[from][spender]`
    /// - T3+ virtual recipient slots: `AddressRegistry::data[master_id]`, with no unresolved
    ///   recipient balance or reward slots
    TransferFrom {
        token: Address,
        spender: Address,
        from: Address,
        to: InferredTip20Recipient,
    },
}

impl InferredTip20TransferCall {
    /// Returns the TIP-20 token target of this call.
    pub const fn token(&self) -> Address {
        match self {
            Self::Transfer { token, .. } | Self::TransferFrom { token, .. } => *token,
        }
    }

    /// Returns the inferred recipient of this call.
    pub const fn to(&self) -> InferredTip20Recipient {
        match self {
            Self::Transfer { to, .. } | Self::TransferFrom { to, .. } => *to,
        }
    }
}

/// Recipient inferred from calldata and hardfork rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InferredTip20Recipient {
    /// Direct recipient, or a virtual-looking recipient before T3.
    Direct(Address),
    /// T3+ virtual recipient whose master must be read from the address registry.
    Virtual {
        virtual_address: Address,
        master_id: MasterId,
    },
}

impl InferredTip20Recipient {
    /// Returns the direct address if no state lookup is required to resolve the recipient.
    pub const fn direct_address(&self) -> Option<Address> {
        match self {
            Self::Direct(address) => Some(*address),
            Self::Virtual { .. } => None,
        }
    }

    /// Returns true if this is a T3+ virtual recipient.
    pub const fn is_virtual(&self) -> bool {
        matches!(self, Self::Virtual { .. })
    }
}

/// Inferred storage slot for an account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InferredStorageSlot {
    pub address: Address,
    pub slot: U256,
}

fn infer_tip20_transfer_call(
    kind: TxKind,
    input: &Bytes,
    sender: Address,
    hardfork: TempoHardfork,
) -> Option<InferredTip20TransferCall> {
    let token = kind.to().copied().filter(TempoAddressExt::is_tip20)?;
    let call = ITIP20::ITIP20Calls::abi_decode(input).ok()?;

    match call {
        ITIP20::ITIP20Calls::transfer(call) => Some(InferredTip20TransferCall::Transfer {
            token,
            from: sender,
            to: recipient(call.to, hardfork),
        }),
        ITIP20::ITIP20Calls::transferWithMemo(call) => Some(InferredTip20TransferCall::Transfer {
            token,
            from: sender,
            to: recipient(call.to, hardfork),
        }),
        ITIP20::ITIP20Calls::transferFrom(call) => Some(InferredTip20TransferCall::TransferFrom {
            token,
            spender: sender,
            from: call.from,
            to: recipient(call.to, hardfork),
        }),
        ITIP20::ITIP20Calls::transferFromWithMemo(call) => {
            Some(InferredTip20TransferCall::TransferFrom {
                token,
                spender: sender,
                from: call.from,
                to: recipient(call.to, hardfork),
            })
        }
        _ => None,
    }
}

fn recipient(address: Address, hardfork: TempoHardfork) -> InferredTip20Recipient {
    if hardfork.is_t3()
        && let Some((master_id, _)) = address.decode_virtual()
    {
        return InferredTip20Recipient::Virtual {
            virtual_address: address,
            master_id,
        };
    }

    InferredTip20Recipient::Direct(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_utils::TxBuilder, transaction::TempoPooledTransaction};
    use alloy_consensus::{Signed, TxEip1559, TxLegacy};
    use alloy_primitives::{B256, Bytes, Signature, TxKind, U256, address};
    use alloy_sol_types::SolCall;
    use reth_primitives_traits::Recovered;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_primitives::{TempoTxEnvelope, UserTag, transaction::tempo_transaction::Call};

    fn transfer_call(to: Address) -> Bytes {
        ITIP20::transferCall {
            to,
            amount: U256::from(1),
        }
        .abi_encode()
        .into()
    }

    fn transfer_with_memo_call(to: Address) -> Bytes {
        ITIP20::transferWithMemoCall {
            to,
            amount: U256::from(1),
            memo: B256::repeat_byte(0x01),
        }
        .abi_encode()
        .into()
    }

    fn transfer_from_call(from: Address, to: Address) -> Bytes {
        ITIP20::transferFromCall {
            from,
            to,
            amount: U256::from(1),
        }
        .abi_encode()
        .into()
    }

    fn transfer_from_with_memo_call(from: Address, to: Address) -> Bytes {
        ITIP20::transferFromWithMemoCall {
            from,
            to,
            amount: U256::from(1),
            memo: B256::repeat_byte(0x02),
        }
        .abi_encode()
        .into()
    }

    fn legacy_tx(sender: Address, token: Address, input: Bytes) -> TempoPooledTransaction {
        let tx = TxLegacy {
            to: TxKind::Call(token),
            input,
            ..Default::default()
        };
        let envelope = TempoTxEnvelope::Legacy(Signed::new_unchecked(
            tx,
            Signature::test_signature(),
            B256::ZERO,
        ));
        TempoPooledTransaction::new(Recovered::new_unchecked(envelope, sender))
    }

    fn eip1559_tx(sender: Address, token: Address, input: Bytes) -> TempoPooledTransaction {
        let tx = TxEip1559 {
            to: TxKind::Call(token),
            input,
            ..Default::default()
        };
        let envelope = TempoTxEnvelope::Eip1559(Signed::new_unchecked(
            tx,
            Signature::test_signature(),
            B256::ZERO,
        ));
        TempoPooledTransaction::new(Recovered::new_unchecked(envelope, sender))
    }

    fn slots(prerequisites: &InferredTip20Prerequisites) -> Vec<InferredStorageSlot> {
        prerequisites.storage_slots().collect()
    }

    fn slot(address: Address, slot: U256) -> InferredStorageSlot {
        InferredStorageSlot { address, slot }
    }

    fn holder_slots(token: Address, holder: Address) -> Vec<InferredStorageSlot> {
        let token_layout = TIP20Token::from_address_unchecked(token);
        let reward_base = holder.mapping_slot(token_layout.user_reward_info.slot());
        vec![
            slot(token, token_layout.balances[holder].slot()),
            slot(token, reward_base),
            slot(token, reward_base + U256::from(1)),
            slot(token, reward_base + U256::from(2)),
        ]
    }

    fn common_slots(token: Address) -> Vec<InferredStorageSlot> {
        vec![
            slot(token, tip20::slots::PAUSED.into()),
            slot(token, tip20::slots::TRANSFER_POLICY_ID.into()),
            slot(token, tip20::slots::GLOBAL_REWARD_PER_TOKEN.into()),
            slot(token, tip20::slots::OPTED_IN_SUPPLY.into()),
        ]
    }

    #[test]
    fn legacy_transfer_infers_common_balance_and_reward_slots() {
        let sender = address!("0000000000000000000000000000000000000001");
        let token = address!("20c0000000000000000000000000000000000001");
        let to = address!("0000000000000000000000000000000000000002");
        let tx = legacy_tx(sender, token, transfer_call(to));

        let prerequisites = tx
            .inferred_tip20_prerequisites(TempoHardfork::T3)
            .expect("transfer prerequisites");

        assert_eq!(prerequisites.accounts().collect::<Vec<_>>(), vec![token]);
        assert_eq!(
            prerequisites.calls(),
            &[InferredTip20TransferCall::Transfer {
                token,
                from: sender,
                to: InferredTip20Recipient::Direct(to),
            }]
        );

        let inferred = slots(&prerequisites);
        for expected in common_slots(token)
            .into_iter()
            .chain(holder_slots(token, sender))
            .chain(holder_slots(token, to))
        {
            assert!(inferred.contains(&expected), "missing {expected:?}");
        }
    }

    #[test]
    fn transfer_with_memo_matches_transfer_touches() {
        let sender = address!("0000000000000000000000000000000000000001");
        let token = address!("20c0000000000000000000000000000000000001");
        let to = address!("0000000000000000000000000000000000000002");
        let transfer = legacy_tx(sender, token, transfer_call(to))
            .inferred_tip20_prerequisites(TempoHardfork::T3)
            .expect("transfer prerequisites");
        let memo = legacy_tx(sender, token, transfer_with_memo_call(to))
            .inferred_tip20_prerequisites(TempoHardfork::T3)
            .expect("memo prerequisites");

        assert_eq!(
            transfer.accounts().collect::<Vec<_>>(),
            memo.accounts().collect::<Vec<_>>()
        );
        assert_eq!(slots(&transfer), slots(&memo));
    }

    #[test]
    fn transfer_from_variants_include_allowance_slot() {
        let sender = address!("0000000000000000000000000000000000000001");
        let from = address!("0000000000000000000000000000000000000002");
        let to = address!("0000000000000000000000000000000000000003");
        let token = address!("20c0000000000000000000000000000000000001");

        for input in [
            transfer_from_call(from, to),
            transfer_from_with_memo_call(from, to),
        ] {
            let prerequisites = legacy_tx(sender, token, input)
                .inferred_tip20_prerequisites(TempoHardfork::T3)
                .expect("transferFrom prerequisites");
            let allowance =
                TIP20Token::from_address_unchecked(token).allowances[from][sender].slot();

            assert!(slots(&prerequisites).contains(&slot(token, allowance)));
            assert_eq!(
                prerequisites.calls(),
                &[InferredTip20TransferCall::TransferFrom {
                    token,
                    spender: sender,
                    from,
                    to: InferredTip20Recipient::Direct(to),
                }]
            );
        }
    }

    #[test]
    fn aa_transfer_calls_aggregate_in_stable_order() {
        let sender = address!("0000000000000000000000000000000000000001");
        let token_a = address!("20c0000000000000000000000000000000000001");
        let token_b = address!("20c0000000000000000000000000000000000002");
        let to = address!("0000000000000000000000000000000000000002");
        let tx = TxBuilder::aa(sender)
            .calls(vec![
                Call {
                    to: TxKind::Call(token_a),
                    value: U256::ZERO,
                    input: transfer_call(to),
                },
                Call {
                    to: TxKind::Call(token_b),
                    value: U256::ZERO,
                    input: transfer_call(to),
                },
            ])
            .build();

        let prerequisites = tx
            .inferred_tip20_prerequisites(TempoHardfork::T3)
            .expect("AA prerequisites");
        let accounts = prerequisites.accounts().collect::<Vec<_>>();
        let slots = slots(&prerequisites);

        assert_eq!(accounts, vec![token_a, token_b]);
        assert_eq!(slots[0], slot(token_a, tip20::slots::PAUSED.into()));
        assert_eq!(slots[12], slot(token_b, tip20::slots::PAUSED.into()));
    }

    #[test]
    fn unsupported_calls_return_none() {
        let sender = address!("0000000000000000000000000000000000000001");
        let token = address!("20c0000000000000000000000000000000000001");
        let non_tip20 = address!("1111111111111111111111111111111111111111");
        let to = address!("0000000000000000000000000000000000000002");

        let approve = ITIP20::approveCall {
            spender: to,
            amount: U256::from(1),
        }
        .abi_encode()
        .into();
        let mint = ITIP20::mintCall {
            to,
            amount: U256::from(1),
        }
        .abi_encode()
        .into();
        let burn = ITIP20::burnCall {
            amount: U256::from(1),
        }
        .abi_encode()
        .into();
        let malformed = Bytes::from_static(&ITIP20::transferCall::SELECTOR);

        for input in [approve, mint, burn, malformed] {
            assert!(
                legacy_tx(sender, token, input)
                    .inferred_tip20_prerequisites(TempoHardfork::T3)
                    .is_none()
            );
        }

        assert!(
            legacy_tx(sender, non_tip20, transfer_call(to))
                .inferred_tip20_prerequisites(TempoHardfork::T3)
                .is_none()
        );

        let create_tx = TxBuilder::aa(sender)
            .calls(vec![Call {
                to: TxKind::Create,
                value: U256::ZERO,
                input: transfer_call(to),
            }])
            .build();
        assert!(
            create_tx
                .inferred_tip20_prerequisites(TempoHardfork::T3)
                .is_none()
        );

        let mixed = TxBuilder::aa(sender)
            .calls(vec![
                Call {
                    to: TxKind::Call(token),
                    value: U256::ZERO,
                    input: transfer_call(to),
                },
                Call {
                    to: TxKind::Call(token),
                    value: U256::ZERO,
                    input: Bytes::new(),
                },
            ])
            .build();
        assert!(
            mixed
                .inferred_tip20_prerequisites(TempoHardfork::T3)
                .is_none()
        );
    }

    #[test]
    fn t3_virtual_recipient_emits_registry_slot_without_recipient_balance_slots() {
        let sender = address!("0000000000000000000000000000000000000001");
        let token = address!("20c0000000000000000000000000000000000001");
        let master_id = MasterId::from([1, 2, 3, 4]);
        let virtual_address = Address::new_virtual(master_id, UserTag::from([5, 6, 7, 8, 9, 10]));
        let tx = legacy_tx(sender, token, transfer_call(virtual_address));

        let prerequisites = tx
            .inferred_tip20_prerequisites(TempoHardfork::T3)
            .expect("virtual prerequisites");
        let slots = slots(&prerequisites);

        assert_eq!(
            prerequisites.accounts().collect::<Vec<_>>(),
            vec![token, ADDRESS_REGISTRY_ADDRESS]
        );
        assert_eq!(
            prerequisites.calls(),
            &[InferredTip20TransferCall::Transfer {
                token,
                from: sender,
                to: InferredTip20Recipient::Virtual {
                    virtual_address,
                    master_id,
                },
            }]
        );
        assert!(slots.contains(&slot(
            ADDRESS_REGISTRY_ADDRESS,
            master_id.mapping_slot(address_registry::slots::DATA)
        )));
        assert!(!slots.contains(&slot(
            token,
            TIP20Token::from_address_unchecked(token).balances[virtual_address].slot()
        )));
    }

    #[test]
    fn pre_t3_virtual_looking_recipient_is_direct() {
        let sender = address!("0000000000000000000000000000000000000001");
        let token = address!("20c0000000000000000000000000000000000001");
        let master_id = MasterId::from([1, 2, 3, 4]);
        let virtual_address = Address::new_virtual(master_id, UserTag::from([5, 6, 7, 8, 9, 10]));
        let tx = legacy_tx(sender, token, transfer_call(virtual_address));

        let prerequisites = tx
            .inferred_tip20_prerequisites(TempoHardfork::T2)
            .expect("pre-T3 prerequisites");
        let slots = slots(&prerequisites);

        assert_eq!(prerequisites.accounts().collect::<Vec<_>>(), vec![token]);
        assert_eq!(
            prerequisites.calls(),
            &[InferredTip20TransferCall::Transfer {
                token,
                from: sender,
                to: InferredTip20Recipient::Direct(virtual_address),
            }]
        );
        assert!(slots.contains(&slot(
            token,
            TIP20Token::from_address_unchecked(token).balances[virtual_address].slot()
        )));
    }

    #[test]
    fn eip1559_transfer_is_supported() {
        let sender = address!("0000000000000000000000000000000000000001");
        let token = address!("20c0000000000000000000000000000000000001");
        let to = address!("0000000000000000000000000000000000000002");
        let tx = eip1559_tx(sender, token, transfer_call(to));

        let prerequisites = tx
            .inferred_tip20_prerequisites(TempoHardfork::T3)
            .expect("EIP-1559 prerequisites");

        assert_eq!(prerequisites.accounts().collect::<Vec<_>>(), vec![token]);
    }
}
