//! Protocol fee hooks of one transaction, read from the storage actions it recorded.
//!
//! The handler marks where each fee hook starts and ends. Application writes may touch the same
//! slots, and fee paths outside these hooks are not tracked.

use alloy_primitives::{Address, U256};
use tempo_precompiles::{
    storage::{Marker, StorageAction},
    tip_fee_manager::amm::{Pool, compute_amount_out},
};

/// One fee hook that returned: the marker that started it and the actions it recorded in order.
struct FeeHook<'a> {
    start: Marker,
    actions: &'a [StorageAction],
}

/// The post-transaction fee hook, if it returned, with the pre-transaction charge it settles.
pub(super) struct PostTxFee<'a> {
    pub(super) payer: Address,
    pub(super) token: Address,
    /// The most the pre-transaction hook charged.
    pub(super) max: U256,
    pub(super) charged: U256,
    /// The index its fee transfer log has, if it emitted one.
    pub(super) log: usize,
    /// Actions the hook recorded, in order.
    pub(super) actions: &'a [StorageAction],
}

/// The fee hooks in `actions` that returned, in order. A hook that failed has no end marker and
/// is skipped.
fn fee_hooks(actions: &[StorageAction]) -> impl Iterator<Item = FeeHook<'_>> {
    actions.iter().enumerate().filter_map(|(at, action)| {
        let StorageAction::Marker(start @ (Marker::PreTxFee { .. } | Marker::PostTxFee { .. })) =
            *action
        else {
            return None;
        };
        let rest = &actions[at + 1..];
        let end = rest
            .iter()
            .position(|action| matches!(action, StorageAction::Marker(_)))?;
        matches!(rest[end], StorageAction::Marker(Marker::FeeHookEnd)).then(|| FeeHook {
            start,
            actions: &rest[..end],
        })
    })
}

/// The post-transaction fee hook, if both fee hooks returned.
pub(super) fn post_tx_fee(actions: &[StorageAction]) -> Option<PostTxFee<'_>> {
    let mut hooks = fee_hooks(actions);
    let Marker::PreTxFee {
        payer,
        token,
        amount,
    } = hooks.next()?.start
    else {
        return None;
    };
    let post = hooks.next()?;
    let Marker::PostTxFee { refund, log } = post.start else {
        return None;
    };
    Some(PostTxFee {
        payer,
        token,
        max: amount,
        charged: amount.checked_sub(refund)?,
        log,
        actions: post.actions,
    })
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
                amount: U256::from(10),
            }),
            write(1),
            StorageAction::Marker(Marker::FeeHookEnd),
            write(2),
            StorageAction::Marker(Marker::PostTxFee {
                refund: U256::from(3),
                log: 3,
            }),
            write(3),
            StorageAction::Marker(Marker::FeeHookEnd),
        ];
        let post = post_tx_fee(&actions).unwrap();
        assert_eq!(
            (post.payer, post.max, post.charged, post.log),
            (address, U256::from(10), U256::from(7), 3)
        );
        assert_eq!(post.actions, &[write(3)]);
        assert!(fee_wrote(&actions, address, U256::from(1)));
        assert!(
            !fee_wrote(&actions, address, U256::from(2)),
            "written by the call"
        );

        // A hook that failed has no end marker and counts for nothing.
        let failed = &actions[..6];
        assert!(post_tx_fee(failed).is_none());
        assert!(!fee_wrote(failed, address, U256::from(3)));
    }
}
