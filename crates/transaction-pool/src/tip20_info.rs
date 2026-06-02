use crate::transaction::TempoPooledTransaction;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_sol_types::SolInterface;
use reth_transaction_pool::PoolTransaction;
use tempo_contracts::precompiles::ITIP20;
use tempo_precompiles::{TIP_FEE_MANAGER_ADDRESS, storage::StorageKey, tip20::tip20_slots};
use tempo_primitives::TempoAddressExt;

/// Precomputed storage slot owned by a TIP-20 token account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tip20StorageSlot {
    /// Token account whose storage is touched.
    pub address: Address,
    /// Storage slot to prewarm.
    pub slot: U256,
}

/// Static TIP-20 storage metadata derived from a transfer-only payment transaction.
///
/// The vectors are separated by storage kind so the payload builder can warm the
/// high-cardinality per-transaction storage directly. Token-global metadata is
/// intentionally omitted and left to normal execution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tip20StaticInfo {
    balance_slots: Vec<Tip20StorageSlot>,
    reward_slots: Vec<Tip20StorageSlot>,
    allowance_slots: Vec<Tip20StorageSlot>,
}

impl Tip20StaticInfo {
    /// Derives static TIP-20 prewarm metadata for transfer-only payment transactions.
    pub(crate) fn for_transaction(tx: &TempoPooledTransaction) -> Option<Self> {
        if !tx.is_payment() || !is_tip20_transfer_calls(tx.inner().calls()) {
            return None;
        }

        let sender = tx.sender();
        let fee_payer = tx.inner().fee_payer(sender).unwrap_or(sender);
        let fee_token = tx.effective_fee_token();

        let mut info = Self::default();
        info.add_fee_touches(fee_token, fee_payer);

        for (kind, input) in tx.inner().calls() {
            let token = *kind.to()?;
            let call = ITIP20::ITIP20Calls::abi_decode(input).ok()?;
            info.add_transfer_call(sender, token, call);
        }

        (!info.is_empty()).then_some(info)
    }

    /// TIP-20 balance storage slots touched by the transaction.
    pub fn balance_slots(&self) -> &[Tip20StorageSlot] {
        &self.balance_slots
    }

    /// TIP-20 reward storage slots touched by the transaction.
    pub fn reward_slots(&self) -> &[Tip20StorageSlot] {
        &self.reward_slots
    }

    /// TIP-20 allowance storage slots touched by the transaction.
    pub fn allowance_slots(&self) -> &[Tip20StorageSlot] {
        &self.allowance_slots
    }

    /// Total number of static entries in this plan.
    pub fn len(&self) -> usize {
        self.balance_slots.len() + self.reward_slots.len() + self.allowance_slots.len()
    }

    /// Returns true if the plan has no static entries.
    pub fn is_empty(&self) -> bool {
        self.balance_slots.is_empty()
            && self.reward_slots.is_empty()
            && self.allowance_slots.is_empty()
    }

    fn add_balance_slot(&mut self, token: Address, account: Address) {
        add_unique(
            &mut self.balance_slots,
            Tip20StorageSlot {
                address: token,
                slot: account.mapping_slot(tip20_slots::BALANCES),
            },
        );
    }

    fn add_reward_slots(&mut self, token: Address, account: Address) {
        let base_slot = account.mapping_slot(tip20_slots::USER_REWARD_INFO);
        add_unique(
            &mut self.reward_slots,
            Tip20StorageSlot {
                address: token,
                slot: base_slot,
            },
        );
        add_unique(
            &mut self.reward_slots,
            Tip20StorageSlot {
                address: token,
                slot: base_slot + U256::from(1),
            },
        );
        add_unique(
            &mut self.reward_slots,
            Tip20StorageSlot {
                address: token,
                slot: base_slot + U256::from(2),
            },
        );
    }

    fn add_allowance_slot(&mut self, token: Address, owner: Address, spender: Address) {
        add_unique(
            &mut self.allowance_slots,
            Tip20StorageSlot {
                address: token,
                slot: spender.mapping_slot(owner.mapping_slot(tip20_slots::ALLOWANCES)),
            },
        );
    }

    fn add_fee_touches(&mut self, fee_token: Address, fee_payer: Address) {
        if !fee_token.is_tip20() {
            return;
        }

        self.add_balance_slot(fee_token, fee_payer);
        self.add_balance_slot(fee_token, TIP_FEE_MANAGER_ADDRESS);
        self.add_reward_slots(fee_token, fee_payer);
    }

    fn add_transfer_call(&mut self, sender: Address, token: Address, call: ITIP20::ITIP20Calls) {
        match call {
            ITIP20::ITIP20Calls::transfer(call) => {
                self.add_balance_slot(token, sender);
                self.add_balance_slot(token, call.to);
                self.add_reward_slots(token, sender);
                self.add_reward_slots(token, call.to);
            }
            ITIP20::ITIP20Calls::transferWithMemo(call) => {
                self.add_balance_slot(token, sender);
                self.add_balance_slot(token, call.to);
                self.add_reward_slots(token, sender);
                self.add_reward_slots(token, call.to);
            }
            ITIP20::ITIP20Calls::transferFrom(call) => {
                self.add_balance_slot(token, call.from);
                self.add_balance_slot(token, call.to);
                self.add_allowance_slot(token, call.from, sender);
                self.add_reward_slots(token, call.from);
                self.add_reward_slots(token, call.to);
            }
            ITIP20::ITIP20Calls::transferFromWithMemo(call) => {
                self.add_balance_slot(token, call.from);
                self.add_balance_slot(token, call.to);
                self.add_allowance_slot(token, call.from, sender);
                self.add_reward_slots(token, call.from);
                self.add_reward_slots(token, call.to);
            }
            _ => {}
        }
    }
}

fn is_tip20_transfer_calls<'a>(calls: impl IntoIterator<Item = (TxKind, &'a Bytes)>) -> bool {
    let mut has_call = false;
    for (kind, input) in calls {
        has_call = true;
        if !is_tip20_transfer_call(kind, input) {
            return false;
        }
    }
    has_call
}

fn is_tip20_transfer_call(kind: TxKind, input: &[u8]) -> bool {
    let Some(token) = kind.to().copied() else {
        return false;
    };
    if !token.is_tip20() {
        return false;
    }

    matches!(
        ITIP20::ITIP20Calls::abi_decode(input),
        Ok(ITIP20::ITIP20Calls::transfer(_)
            | ITIP20::ITIP20Calls::transferWithMemo(_)
            | ITIP20::ITIP20Calls::transferFrom(_)
            | ITIP20::ITIP20Calls::transferFromWithMemo(_))
    )
}

fn add_unique<T: PartialEq>(items: &mut Vec<T>, item: T) {
    if !items.contains(&item) {
        items.push(item);
    }
}
