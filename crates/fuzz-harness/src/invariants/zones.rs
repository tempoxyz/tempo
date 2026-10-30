//! Zone portals: read after each step that touches one, or the factory that creates them, and for a
//! transaction also before it, then checked alone and against the step.

use alloy_primitives::{Address, KECCAK256_EMPTY};
use invariants_core::{Observe, ObserveError, Report, Violation};
use tempo_invariants::{
    all, applies_at,
    zones::portal::{
        self, Portal, ZONE_FACTORY_ADDRESS, ZONE_MESSENGER_ADDRESS, ZoneMessenger,
        is_portal_address, portal_address,
    },
};

use super::{
    logged_addresses,
    reader::Reader,
    views::{EvmViews, PreView, ViewFailed},
};

#[cfg(test)]
mod tests;

/// Checks every portal the step touched into `report`: after a transaction, those it changed,
/// logged from or called, and those whose zone it relayed a message for; otherwise the portals
/// among `accounts` that `selected` admits. A portal the step created is checked against its
/// absence before it.
pub(super) fn check(
    reader: &Reader<'_>,
    accounts: &[Address],
    selected: &dyn Fn(&Address) -> bool,
    report: &mut Report,
) {
    report.counts.entry(portal::VIEW).or_default();
    let mut portals: Vec<Address> = match reader.effects {
        None => accounts
            .iter()
            .copied()
            .filter(|account| is_portal_address(*account) && selected(account))
            .collect(),
        Some(effects) => {
            let relayed = effects
                .calls
                .iter()
                .filter(|frame| frame.target == ZONE_MESSENGER_ADDRESS)
                .filter_map(|frame| frame.decode::<ZoneMessenger::relayMessageCall>())
                .map(|call| portal_address(call.zoneId));
            effects
                .net
                .addresses()
                .copied()
                .chain(effects.logs.iter().map(|log| log.address))
                .chain(effects.calls.iter().map(|frame| frame.target))
                .filter(|address| is_portal_address(*address))
                .chain(relayed)
                .collect()
        }
    };
    portals.sort_unstable();
    portals.dedup();
    // The accounts whose refunds a step can have moved: those its events name, and its sender.
    let mut owners: Vec<Address> = reader
        .effects
        .iter()
        .flat_map(|effects| logged_addresses(effects.logs).chain([effects.tx.sender]))
        .collect();
    owners.sort_unstable();
    owners.dedup();

    let applies = |meta: &_| applies_at(meta, reader.env.spec);
    let pre_state = &reader.db.pre;
    for portal in portals {
        let at = portal::At {
            portal,
            factory: ZONE_FACTORY_ADDRESS,
            owners: &owners,
        };
        let after = EvmViews::new(
            reader.db.view(),
            reader.evm_config,
            reader.env.clone(),
            pre_state,
        );
        let Some(post) = observed(report, portal, Portal::observe(&mut { after }, at)) else {
            continue;
        };
        report.run_any_where(all(), &post, applies);
        let Some(effects) = reader.effects else {
            continue;
        };
        // An account the step deployed has no state before it to read.
        let deployed = |address: &Address| {
            effects.net.get(address).is_some_and(|account| {
                account
                    .original()
                    .is_none_or(|info| info.code_hash == KECCAK256_EMPTY)
            })
        };
        let pre = if deployed(&portal) {
            Portal::absent(portal)
        } else {
            let before = PreView {
                reader: reader.db.view(),
                net: effects.net,
            };
            let before = EvmViews::new(before, reader.evm_config, reader.env.clone(), pre_state);
            let read = Portal::observe(&mut { before }, at);
            // Nor does a token it reads that the step created.
            if let Err(ObserveError::Views(failed)) = &read
                && deployed(&failed.target())
            {
                continue;
            }
            let subject = format!("{portal} before the step");
            let Some(pre) = observed(report, subject, read) else {
                continue;
            };
            pre
        };
        report.run_any_where(all(), &effects.step(portal, pre, post), applies);
    }
}

/// `read`'s value, counting it under [`portal::VIEW`]: a read nothing answered is not armed, one
/// that failed otherwise breaks it.
fn observed<T>(
    report: &mut Report,
    subject: impl std::fmt::Display,
    read: Result<T, ObserveError<ViewFailed>>,
) -> Option<T> {
    let counts = report.counts.entry(portal::VIEW).or_default();
    counts.evaluated += 1;
    match read {
        Ok(value) => {
            counts.armed += 1;
            Some(value)
        }
        Err(err) if err.is_not_answered() => None,
        Err(err) => {
            counts.armed += 1;
            counts.fired += 1;
            report.violations.push(Violation {
                id: portal::VIEW,
                subject: subject.to_string(),
                detail: err.to_string(),
            });
            None
        }
    }
}
