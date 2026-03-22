#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use reth_transaction_pool::{
    BestTransactions, CoinbaseTipOrdering, Priority, error::InvalidPoolTransactionError,
};
use tempo_transaction_pool::{
    best::{BestPriorityTransactions, MergeBestTransactions},
    transaction::TempoPooledTransaction,
};

/// Mock iterator that yields items in order with associated priorities.
struct MockBestTransactions {
    items: Vec<(u16, Priority<u128>)>,
    index: usize,
}

impl MockBestTransactions {
    fn new(priorities: Vec<u16>) -> Self {
        let items = priorities
            .into_iter()
            .map(|p| (p, Priority::Value(p as u128)))
            .collect();
        Self { items, index: 0 }
    }
}

impl Iterator for MockBestTransactions {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_tx_and_priority().map(|(item, _)| item)
    }
}

impl BestPriorityTransactions<CoinbaseTipOrdering<TempoPooledTransaction>>
    for MockBestTransactions
{
    fn next_tx_and_priority(&mut self) -> Option<(Self::Item, Priority<u128>)> {
        if self.index < self.items.len() {
            let (item, priority) = self.items[self.index].clone();
            self.index += 1;
            Some((item, priority))
        } else {
            None
        }
    }
}

impl BestTransactions for MockBestTransactions {
    fn mark_invalid(&mut self, _transaction: &Self::Item, _kind: &InvalidPoolTransactionError) {}
    fn no_updates(&mut self) {}
    fn set_skip_blobs(&mut self, _skip_blobs: bool) {}
}

#[derive(Debug, Arbitrary)]
struct MergeInput {
    left_priorities: Vec<u16>,
    right_priorities: Vec<u16>,
}

fuzz_target!(|input: MergeInput| {
    if input.left_priorities.len() + input.right_priorities.len() > 500 {
        return;
    }

    // Sort in descending order (BestTransactions returns highest first)
    let mut left = input.left_priorities;
    let mut right = input.right_priorities;
    left.sort_unstable_by(|a, b| b.cmp(a));
    right.sort_unstable_by(|a, b| b.cmp(a));

    let expected_len = left.len() + right.len();

    // Build expected multiset for exact verification
    let mut expected: Vec<u16> = left.iter().chain(right.iter()).copied().collect();
    expected.sort_unstable_by(|a, b| b.cmp(a));

    let left_iter = MockBestTransactions::new(left);
    let right_iter = MockBestTransactions::new(right);

    let mut merged = MergeBestTransactions::new(left_iter, right_iter);

    let mut results = Vec::new();
    while let Some(item) = merged.next() {
        results.push(item);
    }

    // Invariant 1: All items present
    assert_eq!(
        results.len(),
        expected_len,
        "Expected {} items, got {}",
        expected_len,
        results.len()
    );

    // Invariant 2: Non-increasing order
    for window in results.windows(2) {
        assert!(
            window[0] >= window[1],
            "Order violation: {} < {}",
            window[0],
            window[1]
        );
    }

    // Invariant 3: Exact multiset match (catches dropped/duplicated items)
    assert_eq!(
        results, expected,
        "Merged output does not match expected sorted multiset"
    );
});
