//! Protocol fee hooks of one transaction, read from the storage actions it recorded.
//!
//! The handler marks where each fee hook starts and ends. Application writes may touch the same
//! slots, and fee paths outside these hooks are not tracked.

use alloy_primitives::{Address, U256};
use std::ops::Range;
use tempo_precompiles::{
    storage::{Marker, StorageAction},
    tip_fee_manager::amm::{Pool, compute_amount_out},
};

/// One fee hook that returned: the marker that started it, the actions it recorded in order, and
/// the logs it emitted.
pub(super) struct FeeHook<'a> {
    pub(super) start: Marker,
    pub(super) actions: &'a [StorageAction],
    pub(super) logs: Range<usize>,
}

/// The post-transaction fee hook, if it returned.
pub(super) struct PostTxFee<'a> {
    pub(super) payer: Address,
    pub(super) token: Address,
    pub(super) charged: U256,
    pub(super) refunded: U256,
    /// Logs the hook emitted. Its fee transfer is the first.
    pub(super) logs: Range<usize>,
    /// Actions the hook recorded, in order.
    pub(super) actions: &'a [StorageAction],
}

/// The fee hooks in `actions` that returned, in order. A hook that failed has no end marker and
/// is skipped.
pub(super) fn fee_hooks(actions: &[StorageAction]) -> impl Iterator<Item = FeeHook<'_>> {
    actions.iter().enumerate().filter_map(|(start, action)| {
        let StorageAction::Marker(
            marker @ (Marker::PreTxFee { logs, .. } | Marker::PostTxFee { logs, .. }),
        ) = *action
        else {
            return None;
        };
        let rest = &actions[start + 1..];
        let end = rest
            .iter()
            .position(|action| matches!(action, StorageAction::Marker(_)))?;
        let StorageAction::Marker(Marker::FeeHookEnd { logs: end_logs }) = rest[end] else {
            return None;
        };
        Some(FeeHook {
            start: marker,
            actions: &rest[..end],
            logs: logs..end_logs,
        })
    })
}

/// The most the pre-transaction fee hook charged, if it returned.
pub(super) fn pre_tx_max(actions: &[StorageAction]) -> Option<U256> {
    fee_hooks(actions).find_map(|hook| match hook.start {
        Marker::PreTxFee { max_amount, .. } => Some(max_amount),
        _ => None,
    })
}

/// The post-transaction fee hook, if it returned.
pub(super) fn post_tx_fee(actions: &[StorageAction]) -> Option<PostTxFee<'_>> {
    fee_hooks(actions).find_map(|hook| match hook.start {
        Marker::PostTxFee {
            payer,
            token,
            charged,
            refunded,
            ..
        } => Some(PostTxFee {
            payer,
            token,
            charged,
            refunded,
            logs: hook.logs,
            actions: hook.actions,
        }),
        _ => None,
    })
}

/// The non-empty log ranges the fee hooks emitted, in order.
pub(super) fn fee_log_ranges(actions: &[StorageAction]) -> Vec<Range<usize>> {
    fee_hooks(actions)
        .map(|hook| hook.logs)
        .filter(|logs| !logs.is_empty())
        .collect()
}

/// Whether a fee hook wrote `slot` of `address`.
pub(super) fn fee_wrote(actions: &[StorageAction], address: Address, slot: U256) -> bool {
    fee_hooks(actions).any(|hook| {
        hook.actions
            .iter()
            .any(|action| written_slot(action) == Some((address, slot)))
    })
}

/// The slot a write action changes. `None` for reads, checks and markers.
fn written_slot(action: &StorageAction) -> Option<(Address, U256)> {
    match *action {
        StorageAction::Sstore(_, key, ..)
        | StorageAction::Sinc(_, key, ..)
        | StorageAction::Sdec(_, key, ..)
        | StorageAction::FeeAmmSwap(key, ..) => Some((action.address(), key)),
        StorageAction::Sload(..)
        | StorageAction::FeeTokenBalanceCheck(..)
        | StorageAction::FeeAmmLiquidityCheck(..)
        | StorageAction::Marker(_) => None,
    }
}

/// Derives a slot's entry and exit values from one hook's ordered writes.
/// Rejects discontinuous writes rather than attributing them to fees.
pub(super) fn fee_hook_slot_change(
    actions: &[StorageAction],
    address: Address,
    slot: U256,
) -> Option<(U256, U256)> {
    let mut change: Option<(U256, U256)> = None;
    for action in actions {
        if written_slot(action) != Some((address, slot)) {
            continue;
        }
        let (before, after) = match *action {
            StorageAction::Sstore(_, _, before, after) => (before, after),
            StorageAction::Sinc(_, _, before, delta) => (before, before.checked_add(delta)?),
            StorageAction::Sdec(_, _, before, delta) => (before, before.checked_sub(delta)?),
            StorageAction::FeeAmmSwap(_, before, amount_in) => {
                let mut pool = Pool::decode_from_slot(before);
                pool.apply_swap(amount_in, compute_amount_out(amount_in).ok()?)
                    .ok()?;
                (before, pool.encode_to_slot().ok()?)
            }
            _ => continue,
        };
        let initial = match change {
            Some((initial, current)) if current == before => initial,
            Some(_) => return None,
            None => before,
        };
        change = Some((initial, after));
    }
    change
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempo_contracts::precompiles::TIP_FEE_MANAGER_ADDRESS;

    #[test]
    fn fee_hook_writes_require_continuity() {
        let address = Address::repeat_byte(1);
        let slot = U256::from(2);
        let actions = [
            StorageAction::Sinc(address, slot, U256::from(10), U256::from(5)),
            StorageAction::Sdec(address, slot, U256::from(15), U256::from(2)),
        ];
        assert_eq!(
            fee_hook_slot_change(&actions, address, slot),
            Some((U256::from(10), U256::from(13)))
        );
        assert_eq!(fee_hook_slot_change(&actions, address, U256::from(3)), None);
        let bad = [
            actions[0],
            StorageAction::Sdec(address, slot, U256::from(14), U256::from(2)),
        ];
        assert_eq!(fee_hook_slot_change(&bad, address, slot), None);
    }

    #[test]
    fn fee_hook_swap_uses_the_packed_pool_transition() {
        let pool = Pool {
            reserve_user_token: 100,
            reserve_validator_token: 200,
        };
        let old = pool.encode_to_slot().unwrap();
        let slot = U256::from(2);
        let amount = U256::from(10);
        let mut expected = pool;
        expected
            .apply_swap(amount, compute_amount_out(amount).unwrap())
            .unwrap();
        assert_eq!(
            fee_hook_slot_change(
                &[StorageAction::FeeAmmSwap(slot, old, amount)],
                TIP_FEE_MANAGER_ADDRESS,
                slot,
            ),
            Some((old, expected.encode_to_slot().unwrap()))
        );
    }

    #[test]
    fn hooks_are_the_actions_between_their_markers() {
        let address = Address::repeat_byte(1);
        let write =
            |slot: u64| StorageAction::Sstore(address, U256::from(slot), U256::ZERO, U256::ONE);
        let actions = [
            StorageAction::Marker(Marker::PreTxFee {
                payer: address,
                token: address,
                max_amount: U256::from(10),
                logs: 0,
            }),
            write(1),
            StorageAction::Marker(Marker::FeeHookEnd { logs: 1 }),
            write(2),
            StorageAction::Marker(Marker::PostTxFee {
                payer: address,
                token: address,
                charged: U256::from(7),
                refunded: U256::from(3),
                logs: 3,
            }),
            write(3),
            StorageAction::Marker(Marker::FeeHookEnd { logs: 5 }),
        ];
        assert_eq!(pre_tx_max(&actions), Some(U256::from(10)));
        let post = post_tx_fee(&actions).unwrap();
        assert_eq!(
            (post.charged, post.refunded, post.logs),
            (U256::from(7), U256::from(3), 3..5)
        );
        assert_eq!(post.actions, &[write(3)]);
        assert_eq!(fee_log_ranges(&actions), vec![0..1, 3..5]);
        assert!(fee_wrote(&actions, address, U256::from(1)));
        assert!(
            !fee_wrote(&actions, address, U256::from(2)),
            "written by the call"
        );

        // A hook that failed has no end marker and counts for nothing.
        let failed = &actions[4..6];
        assert!(post_tx_fee(failed).is_none());
        assert!(!fee_wrote(failed, address, U256::from(3)));
    }
}
