use crate::types::Height;
use commonware_cryptography::PublicKey;
use commonware_utils::{
    ordered::{Quorum, Set},
    N3f1,
};
use std::collections::{btree_map, BTreeMap, HashMap};

/// A data structure that keeps track of the reported tip for each validator.
/// It can efficiently query the `f`th highest tip, where `f` is the maximum number of faults
/// that can be tolerated for the given set of validators.
pub struct SafeTip<P: PublicKey> {
    /// For each validator, the maximum tip that it has reported.
    tips: HashMap<P, Height>,

    /// The `f` highest tips, stored as a map from height to number of validators.
    ///
    /// We assume that all of these values could have been reported by faulty validators.
    hi: BTreeMap<Height, usize>,

    /// The `n-f` lowest tips, stored as a map from height to number of validators.
    ///
    /// Treat the highest value as the safe tip, which is the tip that at least one honest validator
    /// has reached.
    lo: BTreeMap<Height, usize>,
}

impl<P: PublicKey> Default for SafeTip<P> {
    fn default() -> Self {
        Self {
            tips: HashMap::new(),
            hi: BTreeMap::new(),
            lo: BTreeMap::new(),
        }
    }
}

impl<P: PublicKey> SafeTip<P> {
    /// Initializes an instance with the given validators.
    ///
    /// # Panics
    ///
    /// Panics if the validator set is empty.
    pub fn init(&mut self, validators: &Set<P>) {
        // Ensure the validator set is not empty
        assert!(!validators.is_empty());

        // Get the number of validators and the maximum number of faults
        let n = validators.len();
        let f = validators.max_faults::<N3f1>() as usize;

        // Initialize the tips map
        let mut tips = HashMap::with_capacity(n);
        for validator in validators {
            tips.insert(validator.clone(), Height::default());
        }

        // Initialize the heaps
        let mut lo = BTreeMap::new();
        lo.insert(Height::default(), n - f);
        let mut hi = BTreeMap::new();
        if f > 0 {
            hi.insert(Height::default(), f);
        }

        self.tips = tips;
        self.hi = hi;
        self.lo = lo;
    }

    /// Updates the validator set. New validators are added with a default tip of 0.
    ///
    /// # Panics
    ///
    /// Panics if the new validator set is not the same size as the existing set.
    pub fn reconcile(&mut self, validators: &Set<P>) {
        // Verify the new validator set size
        assert!(
            validators.len() == self.tips.len(),
            "Validator set size mismatch"
        );

        // Get the set of exiting validators.
        let mut exiting_vals = Vec::new();
        for val in self.tips.keys() {
            if validators.position(val).is_none() {
                exiting_vals.push(val.clone());
            }
        }

        // Remove validators that are no longer in the set.
        // Their old tip value gets set to the default value.
        for val in exiting_vals {
            // Remove the validator from the set of validators.
            let old = self.tips.remove(&val).unwrap();
            let new = Height::default();

            // Update the heaps. Since the value is decreasing (or stays at 0), there are four
            // cases, which we check in order-of-preference:
            // 1. No-op. The value was already `0`.
            // 2. The value can remain in the `lo` heap.
            // 3. The value can remain in the `hi` heap.
            // 4. The value must be moved from the `hi` heap to the `lo` heap.

            // Case 1: No-op
            if old == new {
                continue;
            }

            // Case 2: The value can remain in the `lo` heap.
            if self.lo.contains_key(&old) {
                dec(self.lo.entry(old));
                inc(self.lo.entry(new));
                continue;
            }

            // At this point, we know that the old value is in the `hi` heap. If every single value
            // in the `lo` heap is less-than-or-equal-to the new value, then the value can remain in
            // the `hi` heap.
            let stay_in_hi: bool = self
                .lo
                .last_entry()
                .map(|e| *e.key())
                .is_none_or(|max_lo| max_lo <= new);

            // Case 3: The value can remain in the `hi` heap.
            if stay_in_hi {
                dec(self.hi.entry(old));
                inc(self.hi.entry(new));
                continue;
            }

            // Case 4: The value must be moved from the `hi` heap to the `lo` heap.
            dec(self.hi.entry(old));
            inc(self.lo.entry(new));

            // Move the maximum value from the `lo` heap to the `hi` heap.
            let max_lo = *self.lo.last_entry().expect("Empty lo heap").key();
            assert!(max_lo > new); // Sanity-check
            dec(self.lo.entry(max_lo));
            inc(self.hi.entry(max_lo));
        }

        // Add new validators with default height
        for new_val in validators {
            self.tips.entry(new_val.clone()).or_default();
        }
    }

    /// Updates the tip for the given validator.
    ///
    /// Returns `None` if the validator is not in the set of validators.
    ///
    /// Returns `None` if the new tip is not higher than the old tip.
    ///
    /// Otherwise, returns the old tip.
    pub fn update(&mut self, public_key: P, new: Height) -> Option<Height> {
        // Update the tip for the given validator. Return early if the validator is not in the set.
        let &old = self.tips.get(&public_key)?;

        // If the new tip is not higher than the old tip, this is a no-op.
        if old >= new {
            return None;
        }

        // Update the tip for the given validator
        self.tips.insert(public_key, new);

        // Update the heaps. Since the value is strictly increasing, there are three cases, which we
        // check in order-of-preference:
        // 1. The value can remain in the `hi` heap.
        // 2. The value can remain in the `lo` heap.
        // 3. The value must be moved from the `lo` heap to the `hi` heap.

        // Case 1: The value can remain in the `hi` heap.
        if self.hi.contains_key(&old) {
            dec(self.hi.entry(old));
            inc(self.hi.entry(new));
            return Some(old);
        }

        // At this point, we know that the old value is in the `lo` heap. If every single value in
        // the `hi` heap is greater-than-or-equal-to the new value, then the value can remain in the
        // `lo` heap.
        let stay_in_lo: bool = self
            .hi
            .first_entry()
            .map(|e| *e.key())
            .is_none_or(|min_hi| min_hi >= new);

        // Case 2: The value can remain in the `lo` heap.
        if stay_in_lo {
            dec(self.lo.entry(old));
            inc(self.lo.entry(new));
            return Some(old);
        }

        // Case 3: The value must be moved from the `lo` heap to the `hi` heap.
        dec(self.lo.entry(old));
        inc(self.hi.entry(new));

        // Move the minimum value from the `hi` heap to the `lo` heap.
        let min_hi = *self.hi.first_entry().expect("Empty hi heap").key();
        assert!(min_hi < new); // Sanity-check
        dec(self.hi.entry(min_hi));
        inc(self.lo.entry(min_hi));

        Some(old)
    }

    /// Returns the `f`th highest tip.
    ///
    /// # Panics
    ///
    /// Panics if the set of validators is empty.
    pub fn get(&self) -> Height {
        self.lo
            .last_key_value()
            .map(|(k, _)| *k)
            .expect("Empty validator set")
    }
}

/// Increments the value of the entry in the map.
///
/// If the entry does not exist, it is created with a value of 1.
fn inc(entry: btree_map::Entry<'_, Height, usize>) {
    *entry.or_default() += 1;
}

/// Decrements the value of the entry in the map.
///
/// If the value reaches zero, the entry is removed from the map.
///
/// # Panics
///
/// Panics if the entry is [btree_map::Entry::Vacant].
fn dec(entry: btree_map::Entry<'_, Height, usize>) {
    let btree_map::Entry::Occupied(mut value) = entry else {
        panic!("Cannot decrement a non-existent entry");
    };
    *value.get_mut() -= 1;
    if *value.get() == 0 {
        value.remove();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        Signer,
    };
    use commonware_utils::TryCollect;
    use rstest::rstest;

    fn key(i: u64) -> PublicKey {
        PrivateKey::from_seed(i).public_key()
    }

    fn setup_safe_tip(validator_count: usize) -> (SafeTip<PublicKey>, Set<PublicKey>) {
        let mut safe_tip = SafeTip::<PublicKey>::default();
        let validators = (1..=validator_count)
            .map(|i| key(i as u64))
            .try_collect::<Set<_>>()
            .unwrap();
        safe_tip.init(&validators);
        (safe_tip, validators)
    }

    fn setup_with_tips(
        validator_count: usize,
        tips: &[u64],
    ) -> (SafeTip<PublicKey>, Set<PublicKey>) {
        let (mut safe_tip, validators) = setup_safe_tip(validator_count);
        for (i, &tip) in tips.iter().enumerate() {
            if i < validators.len() && tip > 0 {
                safe_tip.update(validators[i].clone(), Height::new(tip));
            }
        }
        (safe_tip, validators)
    }

    #[test]
    fn test_init() {
        let (safe_tip, _) = setup_safe_tip(4);
        assert_eq!(safe_tip.tips.len(), 4);
        assert_eq!(safe_tip.get(), Height::zero());
    }

    #[test]
    fn test_validation_failures() {
        // Test init with empty validator set
        let mut safe_tip = SafeTip::<PublicKey>::default();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            safe_tip.init(&[].try_into().unwrap());
        }));
        assert!(result.is_err());

        // Test reconcile with size mismatch
        let mut safe_tip = SafeTip::<PublicKey>::default();
        safe_tip.init(&[key(1), key(2), key(3), key(4)].try_into().unwrap());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            safe_tip.reconcile(&[key(1), key(2), key(3)].try_into().unwrap());
        }));
        assert!(result.is_err());

        // Test dec function with non-existent entry
        let mut map = BTreeMap::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            dec(map.entry(Height::new(42)));
        }));
        assert!(result.is_err());
    }

    #[test]
    fn test_update_and_get() {
        let (mut safe_tip, validators) = setup_safe_tip(4);

        // Valid update
        assert_eq!(
            safe_tip.update(validators[0].clone(), Height::new(10)),
            Some(Height::zero())
        );
        assert_eq!(safe_tip.get(), Height::zero());

        // Update with lower tip - no-op
        assert_eq!(safe_tip.update(validators[0].clone(), Height::new(5)), None);
        assert_eq!(safe_tip.get(), Height::zero());

        // Update with same tip - no-op
        assert_eq!(
            safe_tip.update(validators[0].clone(), Height::new(10)),
            None
        );
        assert_eq!(safe_tip.get(), Height::zero());

        // Update remaining validators
        assert_eq!(
            safe_tip.update(validators[1].clone(), Height::new(20)),
            Some(Height::zero())
        );
        assert_eq!(safe_tip.get(), Height::new(10));
        assert_eq!(
            safe_tip.update(validators[2].clone(), Height::new(30)),
            Some(Height::zero())
        );
        assert_eq!(safe_tip.get(), Height::new(20));
        assert_eq!(
            safe_tip.update(validators[3].clone(), Height::new(40)),
            Some(Height::zero())
        );
        assert_eq!(safe_tip.get(), Height::new(30));
    }

    #[test]
    fn test_reconcile() {
        let mut safe_tip = SafeTip::<PublicKey>::default();
        let old_validators = &[key(1), key(2), key(3), key(4)];
        safe_tip.init(&old_validators.try_into().unwrap());

        safe_tip.update(key(1), Height::new(10));
        safe_tip.update(key(2), Height::new(20));
        safe_tip.update(key(3), Height::new(30));
        safe_tip.update(key(4), Height::new(40));

        assert_eq!(safe_tip.get(), Height::new(30));

        // Reconcile with a new set of validators
        let new_validators = &[key(3), key(4), key(5), key(6)];
        safe_tip.reconcile(&new_validators.try_into().unwrap());

        assert_eq!(safe_tip.tips.len(), 4);
        assert!(safe_tip.tips.contains_key(&key(3)));
        assert!(safe_tip.tips.contains_key(&key(4)));
        assert!(safe_tip.tips.contains_key(&key(5)));
        assert!(safe_tip.tips.contains_key(&key(6)));
        assert_eq!(*safe_tip.tips.get(&key(3)).unwrap(), Height::new(30));
        assert_eq!(*safe_tip.tips.get(&key(4)).unwrap(), Height::new(40));
        assert_eq!(*safe_tip.tips.get(&key(5)).unwrap(), Height::zero());
        assert_eq!(*safe_tip.tips.get(&key(6)).unwrap(), Height::zero());
        assert_eq!(safe_tip.get(), Height::new(30));
    }

    #[test]
    fn test_reconcile_identical() {
        let mut safe_tip = SafeTip::<PublicKey>::default();
        let validators = &[key(1), key(2), key(3), key(4)];
        safe_tip.init(&validators.try_into().unwrap());

        // Set some initial tips
        safe_tip.update(key(1), Height::new(10));
        safe_tip.update(key(2), Height::new(20));
        safe_tip.update(key(3), Height::new(30));

        let initial_safe_tip = safe_tip.get();
        let initial_tips = safe_tip.tips.clone();
        let initial_hi = safe_tip.hi.clone();
        let initial_lo = safe_tip.lo.clone();

        // Reconcile with identical validator set - should be a no-op
        safe_tip.reconcile(&validators.try_into().unwrap());

        // Verify nothing changed
        assert_eq!(safe_tip.get(), initial_safe_tip);
        assert_eq!(safe_tip.tips, initial_tips);
        assert_eq!(safe_tip.hi, initial_hi);
        assert_eq!(safe_tip.lo, initial_lo);
    }

    #[test]
    fn test_update_nonexistent_validator() {
        let (mut safe_tip, _) = setup_with_tips(4, &[10, 20, 0, 0]);

        let initial_safe_tip = safe_tip.get();
        let initial_tips = safe_tip.tips.clone();

        // Test multiple non-existent validators
        for nonexistent_key in [key(100), key(200), key(300)] {
            assert_eq!(safe_tip.update(nonexistent_key, Height::new(50)), None);
        }

        // State should remain unchanged
        assert_eq!(safe_tip.get(), initial_safe_tip);
        assert_eq!(safe_tip.tips, initial_tips);
    }

    #[rstest]
    #[case::single_validator_no_faults_possible(1, 0)]
    #[case::two_validators_no_faults_possible(2, 0)]
    #[case::three_validators_no_faults_possible(3, 0)]
    #[case::four_validators_one_fault_possible(4, 1)]
    #[case::seven_validators_two_faults_possible(7, 2)]
    fn test_edge_cases_for_f(#[case] n: usize, #[case] f: usize) {
        let (mut safe_tip, validators) = setup_safe_tip(n);

        // Initial state checks
        assert_eq!(safe_tip.get(), Height::zero());

        if f == 0 {
            assert_eq!(safe_tip.hi.len(), 0,);
            assert_eq!(safe_tip.lo.len(), 1,);

            // When f=0, updates should immediately change safe tip
            safe_tip.update(validators[0].clone(), Height::new(10));
            assert_eq!(safe_tip.get(), Height::new(10),);
        } else {
            assert_eq!(safe_tip.hi.len(), 1,);
            assert_eq!(safe_tip.lo.len(), 1,);

            if n == 7 && f == 2 {
                assert_eq!(safe_tip.hi.get(&Height::zero()), Some(&2),);
                assert_eq!(safe_tip.lo.get(&Height::zero()), Some(&5),);
            }
        }
    }

    #[test]
    fn test_dec_inc_internal() {
        // Test inc function
        let mut map = BTreeMap::new();

        // Test inc on non-existent entry
        inc(map.entry(Height::new(10)));
        assert_eq!(map.get(&Height::new(10)), Some(&1));

        // Test inc on existing entry
        inc(map.entry(Height::new(10)));
        assert_eq!(map.get(&Height::new(10)), Some(&2));

        // Test inc on different keys
        inc(map.entry(Height::new(20)));
        inc(map.entry(Height::new(30)));
        assert_eq!(map.get(&Height::new(20)), Some(&1));
        assert_eq!(map.get(&Height::new(30)), Some(&1));
        assert_eq!(map.len(), 3);

        // Test dec function
        // Test dec on existing entry
        dec(map.entry(Height::new(10)));
        assert_eq!(map.get(&Height::new(10)), Some(&1));

        // Test dec that removes entry (value becomes 0)
        dec(map.entry(Height::new(10)));
        assert_eq!(map.get(&Height::new(10)), None);
        assert_eq!(map.len(), 2);

        // Test dec on other entries
        dec(map.entry(Height::new(20)));
        assert_eq!(map.get(&Height::new(20)), None);
        assert_eq!(map.len(), 1);

        dec(map.entry(Height::new(30)));
        assert_eq!(map.get(&Height::new(30)), None);
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn test_reconcile_overall_behavior_lo_heap() {
        // Test overall reconcile behavior when removing validator from lo heap
        let (mut safe_tip, _) = setup_with_tips(7, &[5, 10, 15, 20, 25, 30, 35]);
        assert_eq!(safe_tip.get(), Height::new(25));

        // Remove validator with tip 10 (in lo heap), replace with new validator
        let new_validators = &[key(1), key(8), key(3), key(4), key(5), key(6), key(7)];
        safe_tip.reconcile(&new_validators.try_into().unwrap());

        assert_eq!(safe_tip.get(), Height::new(25)); // Should remain the same
        assert_eq!(*safe_tip.tips.get(&key(8)).unwrap(), Height::zero()); // New validator starts at 0
    }

    #[test]
    fn test_reconcile_overall_behavior_hi_heap() {
        // Test overall reconcile behavior when removing validator from hi heap
        let (mut safe_tip, _) = setup_with_tips(7, &[5, 10, 15, 20, 25, 30, 35]);
        assert_eq!(safe_tip.get(), Height::new(25));

        // Remove validator with tip 30 (in hi heap), replace with new validator
        let new_validators = &[key(1), key(2), key(3), key(4), key(5), key(8), key(7)];
        safe_tip.reconcile(&new_validators.try_into().unwrap());

        // When a validator with tip 30 is removed and replaced with one at tip 0,
        // the max of lo heap should drop from 25 to 20
        assert_eq!(safe_tip.get(), Height::new(20));
        assert_eq!(*safe_tip.tips.get(&key(8)).unwrap(), Height::zero());
    }

    #[test]
    fn test_reconcile_overall_behavior_with_rebalancing() {
        // Test overall reconcile behavior when heap rebalancing occurs
        let (mut safe_tip, validators) = setup_with_tips(4, &[10, 20, 30, 0]);
        assert_eq!(safe_tip.get(), Height::new(20));

        // Remove validator with tip 30 (validators[2] in hi heap), causing rebalancing
        let new_validators = &[
            validators[0].clone(),
            validators[1].clone(),
            key(8),
            validators[3].clone(),
        ];
        safe_tip.reconcile(&new_validators.try_into().unwrap());

        assert_eq!(*safe_tip.tips.get(&key(8)).unwrap(), Height::zero());
        // After removing validator with tip 30 and adding one with tip 0,
        // the safe tip should now be 10 (with tips [10, 20, 0, 0], lo heap has [0, 0, 10])
        assert_eq!(safe_tip.get(), Height::new(10));
    }

    #[test]
    fn test_reconcile_internal_case_1_noop() {
        // Test Case 1: No-op when validator already has tip 0
        let (mut safe_tip, validators) = setup_with_tips(4, &[0, 10, 20, 30]);

        let initial_hi = safe_tip.hi.clone();
        let initial_lo = safe_tip.lo.clone();

        // Remove validator that already has tip 0 (validators[0])
        let new_validators = &[
            key(8),
            validators[1].clone(),
            validators[2].clone(),
            validators[3].clone(),
        ];
        safe_tip.reconcile(&new_validators.try_into().unwrap());

        // Heaps should be unchanged since removing 0 -> 0 is a no-op
        assert_eq!(safe_tip.hi, initial_hi);
        assert_eq!(safe_tip.lo, initial_lo);
        assert_eq!(safe_tip.get(), Height::new(20));
    }

    #[test]
    fn test_reconcile_internal_case_2_remains_in_lo() {
        // Test Case 2: Value remains in lo heap
        let (mut safe_tip, validators) = setup_with_tips(4, &[5, 15, 25, 30]);
        assert_eq!(safe_tip.get(), Height::new(25));

        // Verify initial heap state: with n=4, f=1, we have 1 in hi, 3 in lo
        // Tips [5, 15, 25, 30] -> hi has [30], lo has [5, 15, 25]
        assert!(safe_tip.lo.contains_key(&Height::new(5)));
        assert!(safe_tip.lo.contains_key(&Height::new(15)));
        assert!(safe_tip.lo.contains_key(&Height::new(25)));
        assert!(safe_tip.hi.contains_key(&Height::new(30)));

        // Remove validator with tip 5 (validators[0] in lo heap)
        let new_validators = &[
            key(8),
            validators[1].clone(),
            validators[2].clone(),
            validators[3].clone(),
        ];
        safe_tip.reconcile(&new_validators.try_into().unwrap());

        // The removed tip 5 should be replaced with 0, both in lo heap
        assert!(safe_tip.lo.contains_key(&Height::zero()));
        assert!(!safe_tip.lo.contains_key(&Height::new(5)));
        assert_eq!(safe_tip.get(), Height::new(25)); // Safe tip unchanged
    }

    #[test]
    fn test_reconcile_internal_case_3_remains_in_hi() {
        // Test Case 3: Value remains in hi heap when new value >= max(lo)
        let (safe_tip, _) = setup_with_tips(4, &[5, 15, 25, 35]);
        assert_eq!(safe_tip.get(), Height::new(25));

        // Verify tip 35 is in hi heap
        assert!(safe_tip.hi.contains_key(&Height::new(35)));

        // Create a scenario where removed value can stay in hi:
        // Remove validator with tip 35, all lo values (5,15,25) <= 0 is false
        // But we can test by removing and replacing with a value that satisfies the condition

        // Actually, let's test the condition directly by creating the right setup
        let (mut safe_tip, _) = setup_with_tips(7, &[0, 0, 0, 0, 0, 10, 20]);
        assert_eq!(safe_tip.get(), Height::zero());

        // With n=7, f=2: hi has [10, 20], lo has [0, 0, 0, 0, 0]
        // Remove validator with tip 10 (in hi), max_lo is 0, so 0 <= 0 is true
        let new_validators = &[key(1), key(2), key(3), key(4), key(5), key(8), key(7)];
        safe_tip.reconcile(&new_validators.try_into().unwrap());

        // Value should remain in hi heap as 0, since max_lo (0) <= new (0)
        assert!(safe_tip.hi.contains_key(&Height::zero()) || safe_tip.hi.is_empty());
        assert_eq!(safe_tip.get(), Height::zero());
    }

    #[test]
    fn test_reconcile_internal_case_4_move_hi_to_lo() {
        // Test Case 4: Value must move from hi to lo heap with rebalancing
        let (mut safe_tip, validators) = setup_with_tips(4, &[10, 20, 30, 40]);
        assert_eq!(safe_tip.get(), Height::new(30));

        // With n=4, f=1: hi has [40], lo has [10, 20, 30]
        // Remove validator with tip 40 (validators[3] in hi), max_lo is 30, so 30 > 0, condition fails
        let new_validators = &[
            validators[0].clone(),
            validators[1].clone(),
            validators[2].clone(),
            key(8),
        ];
        safe_tip.reconcile(&new_validators.try_into().unwrap());

        // This should trigger Case 4: move from hi to lo with rebalancing
        // The 0 goes to lo, and max_lo (30) moves to hi
        assert!(safe_tip.hi.contains_key(&Height::new(30)));
        assert!(safe_tip.lo.contains_key(&Height::zero()));
        assert_eq!(safe_tip.get(), Height::new(20)); // New max of lo heap
    }

    #[test]
    fn test_update_internal_case_2_remains_in_lo() {
        // Test Case 2 in update: Value remains in lo heap
        let (mut safe_tip, validators) = setup_with_tips(4, &[5, 15, 25, 35]);
        assert_eq!(safe_tip.get(), Height::new(25));

        // With n=4, f=1: hi has [35], lo has [5, 15, 25]
        // Update validators[0]'s tip from 5 to 10 - both should stay in lo since min_hi (35) >= 10
        assert!(safe_tip.lo.contains_key(&Height::new(5)));
        safe_tip.update(validators[0].clone(), Height::new(10));

        assert!(safe_tip.lo.contains_key(&Height::new(10)));
        assert!(!safe_tip.lo.contains_key(&Height::new(5)));
        assert_eq!(safe_tip.get(), Height::new(25)); // Safe tip unchanged
    }

    #[test]
    fn test_update_internal_case_3_move_lo_to_hi() {
        // Test Case 3 in update: Value must move from lo to hi heap with rebalancing
        let (mut safe_tip, validators) = setup_with_tips(4, &[5, 15, 25, 35]);
        assert_eq!(safe_tip.get(), Height::new(25));

        // With n=4, f=1: hi has [35], lo has [5, 15, 25]
        // Update tip 5 to 40 - should move to hi and cause rebalancing
        safe_tip.update(validators[0].clone(), Height::new(40));

        // The 40 goes to hi, min_hi (35) moves to lo
        assert!(safe_tip.hi.contains_key(&Height::new(40)));
        assert!(safe_tip.lo.contains_key(&Height::new(35)));
        assert_eq!(safe_tip.get(), Height::new(35)); // New max of lo heap
    }

    #[test]
    fn test_update_edge_cases() {
        let (mut safe_tip, validators) = setup_with_tips(7, &[0, 0, 0, 0, 0, 10, 20]);

        // Test updating when hi heap might be empty after rebalancing
        // With n=7, f=2: initially hi has [10, 20], lo has [0, 0, 0, 0, 0]

        // Update one of the 0s to a very high value
        safe_tip.update(validators[0].clone(), Height::new(100));

        // This should cause rebalancing
        assert!(safe_tip.hi.contains_key(&Height::new(100)));
        assert_eq!(safe_tip.get(), Height::new(10)); // Should now be higher than 0
    }
}
