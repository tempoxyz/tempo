//! Gas-weighted selection of payment and general transactions during payload building.

use crate::{StateAwarePoolTransaction, best::BestTransaction};
use alloy_primitives::{
    Address, U256,
    map::{HashMap, HashSet, hash_map::Entry},
};
use reth_transaction_pool::{
    BestTransactions, PoolTransaction, error::InvalidPoolTransactionError,
};
use std::collections::{BTreeMap, VecDeque};

/// Bound both retained transactions and work spent searching for a preferred lane.
const MAX_BUFFERED_TRANSACTIONS: usize = 1024;
const MAX_LOOKAHEAD: usize = 64;

type Sequence = (Address, U256);

/// Selects the lane with the lowest gas-weighted virtual finish time.
///
/// The source's order is retained within each lane, except that nonce ancestors always
/// precede their descendants, even across lanes. An empty or blocked preferred lane
/// lends its capacity to the other lane. Candidate cost prevents a large transaction from
/// running as soon as its lane falls slightly behind, while actual execution gas corrects
/// subsequent choices. Bounded lookahead makes the ratio a soft target. Call
/// [`Self::set_gas_used`] with actual execution gas before requesting the next item.
pub struct LaneBalancedTransactions<I: Iterator> {
    inner: I,
    general: BTreeMap<u64, I::Item>,
    payments: BTreeMap<u64, I::Item>,
    sequences: HashMap<Sequence, BufferedSequence<I::Item>>,
    invalid: HashSet<Sequence>,
    next_rank: u64,
    buffered: usize,
    general_limit: u64,
    total_limit: u64,
    general_used: u64,
    total_used: u64,
    is_t5: bool,
}

impl<I> LaneBalancedTransactions<I>
where
    I: BestTransactions,
    I::Item: StateAwarePoolTransaction,
{
    /// Wraps a source using the same gas limits and payment classification as the builder.
    pub fn new(inner: I, general_limit: u64, total_limit: u64, is_t5: bool) -> Self {
        Self {
            inner,
            general: BTreeMap::new(),
            payments: BTreeMap::new(),
            sequences: HashMap::default(),
            invalid: HashSet::default(),
            next_rank: 0,
            buffered: 0,
            general_limit: general_limit.min(total_limit),
            total_limit,
            general_used: 0,
            total_used: 0,
            is_t5,
        }
    }

    /// Updates lane accounting from executed gas, never a transaction's declared limit.
    pub fn set_gas_used(&mut self, general_used: u64, total_used: u64) {
        self.general_used = general_used;
        self.total_used = total_used;
    }

    fn select_general(&self) -> Option<bool> {
        let general = self.general.first_key_value();
        let payment = self.payments.first_key_value();

        match (general, payment) {
            (None, None) => None,
            (Some(_), None) => Some(true),
            (None, Some(_)) => Some(false),
            (Some((general_rank, general)), Some((payment_rank, payment))) => {
                if self.general_limit == 0 {
                    return Some(false);
                }
                let payment_limit = self.total_limit.saturating_sub(self.general_limit);
                if payment_limit == 0 {
                    return Some(true);
                }

                let general_finish = u128::from(self.general_used)
                    .saturating_add(u128::from(general.estimated_gas_used()));
                let payment_used = self.total_used.saturating_sub(self.general_used);
                let payment_finish = u128::from(payment_used)
                    .saturating_add(u128::from(payment.estimated_gas_used()));
                let general_weighted = general_finish.saturating_mul(u128::from(payment_limit));
                let payment_weighted =
                    payment_finish.saturating_mul(u128::from(self.general_limit));

                Some(match general_weighted.cmp(&payment_weighted) {
                    std::cmp::Ordering::Less => true,
                    std::cmp::Ordering::Greater => false,
                    std::cmp::Ordering::Equal => general_rank < payment_rank,
                })
            }
        }
    }

    fn ready(&mut self, general: bool) -> &mut BTreeMap<u64, I::Item> {
        if general {
            &mut self.general
        } else {
            &mut self.payments
        }
    }

    fn push(&mut self, item: I::Item) {
        let tx = item.best_transaction();
        let sequence = sequence(tx);
        if sequence.is_some_and(|sequence| self.invalid.contains(&sequence)) {
            return;
        }
        let general = if self.is_t5 {
            !tx.transaction.is_payment()
        } else {
            !tx.transaction.inner().is_payment_v1()
        };
        let rank = self.next_rank;
        self.next_rank += 1;
        self.buffered += 1;

        if let Some(sequence) = sequence {
            match self.sequences.entry(sequence) {
                Entry::Occupied(mut entry) => {
                    entry.get_mut().following.push_back((rank, general, item));
                    return;
                }
                Entry::Vacant(entry) => {
                    entry.insert(BufferedSequence {
                        head: (rank, general),
                        following: VecDeque::new(),
                    });
                }
            }
        }
        self.ready(general).insert(rank, item);
    }

    fn pop(&mut self, general: bool) -> Option<I::Item> {
        let (_, item) = self.ready(general).pop_first()?;
        self.buffered -= 1;
        if let Some(sequence) = sequence(item.best_transaction()) {
            let queued = self
                .sequences
                .get_mut(&sequence)
                .expect("ready sequence exists");
            if let Some((rank, general, next)) = queued.following.pop_front() {
                queued.head = (rank, general);
                self.ready(general).insert(rank, next);
            } else {
                self.sequences.remove(&sequence);
            }
        }
        Some(item)
    }
}

impl<I> Iterator for LaneBalancedTransactions<I>
where
    I: BestTransactions,
    I::Item: StateAwarePoolTransaction,
{
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        for _ in 0..MAX_LOOKAHEAD {
            if (!self.general.is_empty() && !self.payments.is_empty())
                || self.buffered >= MAX_BUFFERED_TRANSACTIONS
            {
                break;
            }
            let Some(item) = self.inner.next() else { break };
            self.push(item);
        }
        self.select_general().and_then(|general| self.pop(general))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        // Invalidated source items may be skipped, so no nonzero lower bound is guaranteed.
        (
            0,
            self.inner
                .size_hint()
                .1
                .and_then(|n| n.checked_add(self.buffered)),
        )
    }
}

impl<I> BestTransactions for LaneBalancedTransactions<I>
where
    I: BestTransactions + Send,
    I::Item: StateAwarePoolTransaction + Send,
{
    fn mark_invalid(&mut self, transaction: &Self::Item, kind: InvalidPoolTransactionError) {
        if let Some(sequence) = sequence(transaction.best_transaction()) {
            self.invalid.insert(sequence);
            if let Some(queued) = self.sequences.remove(&sequence) {
                self.ready(queued.head.1).remove(&queued.head.0);
                self.buffered -= 1 + queued.following.len();
            }
        }
        self.inner.mark_invalid(transaction, kind);
    }

    fn no_updates(&mut self) {
        self.inner.no_updates();
    }

    fn set_skip_blobs(&mut self, skip_blobs: bool) {
        self.inner.set_skip_blobs(skip_blobs);
    }
}

struct BufferedSequence<T> {
    head: (u64, bool),
    following: VecDeque<(u64, bool, T)>,
}

fn sequence(tx: &BestTransaction) -> Option<Sequence> {
    (!tx.transaction.is_expiring_nonce()).then(|| {
        (
            tx.transaction.sender(),
            tx.transaction.nonce_key().unwrap_or_default(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TxBuilder, wrap_valid_tx};
    use alloy_primitives::{B256, TxKind};
    use alloy_sol_types::SolCall;
    use reth_transaction_pool::TransactionOrigin;
    use std::sync::Arc;
    use tempo_contracts::precompiles::ITIP20;
    use tempo_precompiles::DEFAULT_FEE_TOKEN;
    use tempo_primitives::transaction::tempo_transaction::Call;

    #[derive(Default)]
    struct Source {
        txs: VecDeque<BestTransaction>,
        pulls: usize,
        no_updates: bool,
    }

    impl Iterator for Source {
        type Item = BestTransaction;

        fn next(&mut self) -> Option<Self::Item> {
            self.pulls += 1;
            self.txs.pop_front()
        }
    }

    impl BestTransactions for Source {
        fn mark_invalid(&mut self, _: &Self::Item, _: InvalidPoolTransactionError) {}

        fn no_updates(&mut self) {
            self.no_updates = true;
        }

        fn set_skip_blobs(&mut self, _: bool) {}
    }

    fn tx_with_gas_limit(
        payment: bool,
        sender: Address,
        key: U256,
        nonce: u64,
        gas_limit: u64,
    ) -> BestTransaction {
        let builder = TxBuilder::aa(sender)
            .nonce_key(key)
            .nonce(nonce)
            .gas_limit(gas_limit);
        let builder = if payment {
            builder.calls(vec![Call {
                to: TxKind::Call(DEFAULT_FEE_TOKEN),
                value: U256::ZERO,
                input: ITIP20::transferCall {
                    to: Address::random(),
                    amount: U256::from(1),
                }
                .abi_encode()
                .into(),
            }])
        } else {
            builder
        };
        let tx = Arc::new(wrap_valid_tx(builder.build(), TransactionOrigin::External));
        assert_eq!(tx.transaction.is_payment(), payment);
        tx
    }

    fn tx(payment: bool, sender: Address, key: U256, nonce: u64) -> BestTransaction {
        tx_with_gas_limit(payment, sender, key, nonce, 1_000_000)
    }

    fn independent(payment: bool) -> BestTransaction {
        tx(payment, Address::random(), U256::ZERO, 0)
    }

    fn independent_with_gas_limit(payment: bool, gas_limit: u64) -> BestTransaction {
        tx_with_gas_limit(payment, Address::random(), U256::ZERO, 0, gas_limit)
    }

    fn scheduler(
        txs: Vec<BestTransaction>,
        general: u64,
        total: u64,
    ) -> LaneBalancedTransactions<Source> {
        LaneBalancedTransactions::new(
            Source {
                txs: txs.into(),
                ..Default::default()
            },
            general,
            total,
            true,
        )
    }

    fn next_hash(txs: &mut LaneBalancedTransactions<Source>) -> Option<B256> {
        txs.next().map(|tx| *tx.hash())
    }

    #[test]
    fn balances_actual_gas_and_preserves_order_within_each_lane() {
        let general = (0..10)
            .map(|_| independent_with_gas_limit(false, 1))
            .collect::<Vec<_>>();
        let payments = (0..100)
            .map(|_| independent_with_gas_limit(true, 1))
            .collect::<Vec<_>>();
        let mut txs = scheduler(general.iter().chain(&payments).cloned().collect(), 10, 100);
        let (mut g, mut p) = (0, 0);
        for _ in 0..100 {
            txs.set_gas_used(g, g + p);
            let item = txs.next().unwrap();
            if item.transaction.is_payment() {
                assert_eq!(item.hash(), payments[p as usize].hash());
                p += 1;
            } else {
                assert_eq!(item.hash(), general[g as usize].hash());
                g += 1;
            }
            // One indivisible transaction of slack.
            assert!((10 * g as i64 - (g + p) as i64).abs() <= 10);
        }
        assert_eq!((g, p), (10, 90));
    }

    #[test]
    fn lends_capacity_and_accepts_live_arrivals() {
        let general = independent(false);
        let mut txs = scheduler(vec![general.clone()], 1, 100);
        assert_eq!(next_hash(&mut txs), Some(*general.hash()));
        assert!(txs.next().is_none());
        let payment = independent(true);
        txs.inner.txs.push_back(payment.clone());
        txs.set_gas_used(500, 500);
        assert_eq!(next_hash(&mut txs), Some(*payment.hash()));
        txs.no_updates();
        assert!(txs.inner.no_updates);
    }

    #[test]
    fn keeps_cross_lane_nonce_ancestors_before_descendants() {
        for key in [U256::ZERO, U256::from(7)] {
            let sender = Address::random();
            let parent = tx(false, sender, key, 0);
            let child = tx(true, sender, key, 1);
            let other = independent(true);
            let mut txs = scheduler(vec![parent.clone(), child.clone(), other.clone()], 1, 100);
            assert_eq!(next_hash(&mut txs), Some(*other.hash()));
            assert_eq!(next_hash(&mut txs), Some(*parent.hash()));
            assert_eq!(next_hash(&mut txs), Some(*child.hash()));
        }
    }

    #[test]
    fn invalidation_removes_buffered_and_future_descendants_only() {
        for key in [U256::ZERO, U256::from(7)] {
            let sender = Address::random();
            let parent = tx(false, sender, key, 0);
            let child = tx(true, sender, key, 1);
            let unrelated = tx(true, sender, key + U256::from(1), 0);
            let mut txs = scheduler(vec![parent.clone(), child, unrelated.clone()], 1, 100);
            assert_eq!(next_hash(&mut txs), Some(*unrelated.hash()));
            assert_eq!(next_hash(&mut txs), Some(*parent.hash()));
            txs.mark_invalid(
                &parent,
                InvalidPoolTransactionError::ExceedsGasLimit(100, 0),
            );
            txs.inner.txs.push_back(tx(true, sender, key, 2));
            assert!(txs.next().is_none());
            assert_eq!(txs.buffered, 0);
        }
    }

    #[test]
    fn expiring_nonces_do_not_block_each_other() {
        let sender = Address::random();
        let parent = tx(false, sender, U256::MAX, 0);
        let payment = tx(true, sender, U256::MAX, 0);
        assert!(parent.transaction.is_expiring_nonce());
        let mut txs = scheduler(vec![parent.clone(), payment.clone()], 1, 100);
        assert_eq!(next_hash(&mut txs), Some(*payment.hash()));
        txs.mark_invalid(
            &payment,
            InvalidPoolTransactionError::ExceedsGasLimit(100, 0),
        );
        assert_eq!(next_hash(&mut txs), Some(*parent.hash()));
    }

    #[test]
    fn bounds_lookahead_and_memory_when_preferred_lane_is_absent() {
        let mut txs = scheduler((0..2048).map(|_| independent(false)).collect(), 1, 100);
        for _ in 0..2048 {
            let pulls = txs.inner.pulls;
            assert!(txs.next().is_some());
            assert!(txs.inner.pulls - pulls <= MAX_LOOKAHEAD);
            assert!(txs.buffered < MAX_BUFFERED_TRANSACTIONS);
        }
        assert!(txs.next().is_none());
    }

    #[test]
    fn handles_zero_full_and_large_weights() {
        let general = independent(false);
        let payment = independent(true);
        for (weight, expected) in [(0, payment.hash()), (u64::MAX, general.hash())] {
            let mut txs = scheduler(vec![general.clone(), payment.clone()], weight, u64::MAX);
            txs.set_gas_used(u64::MAX / 2, u64::MAX - 1);
            assert_eq!(next_hash(&mut txs), Some(*expected));
        }
        let expected = *general.hash();
        let mut txs = scheduler(vec![general, payment], u64::MAX / 2, u64::MAX);
        txs.set_gas_used(u64::MAX / 4, u64::MAX - 1);
        assert_eq!(next_hash(&mut txs), Some(expected));
    }

    #[test]
    fn unequal_execution_costs_change_the_transaction_ratio() {
        let general = (0..10).map(|_| independent_with_gas_limit(false, 25));
        let payments = (0..1000).map(|_| independent_with_gas_limit(true, 2));
        let mut txs = scheduler(general.chain(payments).collect(), 10, 100);
        let (mut general_gas, mut payment_gas, mut general_count) = (0, 0, 0);
        for _ in 0..300 {
            txs.set_gas_used(general_gas, general_gas + payment_gas);
            if txs.next().unwrap().transaction.is_payment() {
                payment_gas += 2;
            } else {
                general_gas += 25;
                general_count += 1;
            }
            let target = (general_gas + payment_gas) as f64 / 10.0;
            assert!((general_gas as f64 - target).abs() <= 25.0);
        }
        assert_eq!(general_count, 2);
    }

    #[test]
    fn candidate_cost_prevents_an_early_general_burst() {
        let general = independent_with_gas_limit(false, 25);
        let payments = (0..113)
            .map(|_| independent_with_gas_limit(true, 2))
            .collect::<Vec<_>>();
        let mut txs = scheduler(
            std::iter::once(general.clone())
                .chain(payments.iter().cloned())
                .collect(),
            10,
            100,
        );

        let mut payment_gas = 0;
        for expected in &payments[..112] {
            txs.set_gas_used(0, payment_gas);
            assert_eq!(next_hash(&mut txs), Some(*expected.hash()));
            payment_gas += 2;
        }
        txs.set_gas_used(0, payment_gas);
        assert_eq!(next_hash(&mut txs), Some(*general.hash()));
    }
}
