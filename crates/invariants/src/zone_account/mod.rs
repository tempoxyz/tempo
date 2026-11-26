//! Configurable accounts on zones (TIP-1154): what a zone shows of each account beside what Tempo
//! holds for it at the zone's anchor.
//!
//! A zone reads Tempo state at a fixed anchor and never stores a commitment, so its checks compare
//! two chains. A producer observes [`Zone`] through the zone's views, then [`Tempo`] through
//! Tempo's views at the anchor the zone reported, and joins them into a [`Mirror`]. Without Tempo
//! only the zone's own checks are armed.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use alloy_primitives::{Address, B256, Bytes, FixedBytes, U256};
use alloy_sol_types::SolCall;
use invariants_core::{Call, Outcome};
use tempo_contracts::{
    precompiles::IConfigurableAccountShim::onERC721ReceivedCall,
    zones::{
        TEMPO_STATE_ADDRESS,
        TempoState::{tempoBlockHashCall, tempoBlockNumberCall},
        ZONE_ADDRESS_REGISTRY_ADDRESS, ZONE_FEE_MANAGER_ADDRESS, ZONE_IDENTITY_ADDRESS,
        ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS,
    },
};

use crate::{
    Observe, ObserveError, Ran, Step, TempoHardfork, Views,
    configurable_account::{Leaf, read_commitments, spec as account_spec},
    view,
};

mod checks;

pub use checks::{CHECKS, LEAF_CHECKS, STEP_CHECKS, VIEW};

/// The Tempo block a zone reads Tempo at: `TempoState`'s checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Anchor {
    pub number: u64,
    pub hash: B256,
}

impl fmt::Display for Anchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "anchor {} ({})", self.number, self.hash)
    }
}

/// What a zone shows of the observed accounts at one state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone {
    /// The `TempoState` predeploy read.
    tempo_state: Address,
    /// The configurable account precompile read.
    precompile: Address,
    anchor: Anchor,
    /// Each account's commitment as zone execution reads it; unanswered reads are left out.
    of: BTreeMap<Address, B256>,
    /// Whether a call to each eligible account answers as the account marker; unanswered calls are
    /// left out.
    marked: BTreeMap<Address, bool>,
    /// The observed accounts that hold zone code, so never read Tempo.
    coded: BTreeSet<Address>,
    /// The hardfork the zone runs, which decides its system contracts.
    spec: TempoHardfork,
}

impl Zone {
    /// The Tempo block the zone reads Tempo at.
    pub const fn anchor(&self) -> Anchor {
        self.anchor
    }
}

/// The predeploys and the accounts to read; `coded` are those of `accounts` whose code in zone
/// state is not empty.
#[derive(Debug, Clone, Copy)]
pub struct ZoneAt<'a> {
    pub tempo_state: Address,
    pub precompile: Address,
    pub accounts: &'a [Address],
    pub coded: &'a [Address],
    /// The hardfork the zone runs.
    pub spec: TempoHardfork,
}

impl Observe for Zone {
    type At<'a> = ZoneAt<'a>;

    /// Reads the anchor, each account's commitment and, for each eligible account, whether a call
    /// to it answers as the account marker's ERC-721 receiver hook (an account without code
    /// answers with empty output). Views must run as zone transactions, where the overlay applies.
    fn observe<V: Views>(views: &mut V, at: ZoneAt<'_>) -> Result<Self, ObserveError<V::Error>> {
        let anchor = Anchor {
            number: view(views, at.tempo_state, tempoBlockNumberCall {})?,
            hash: view(views, at.tempo_state, tempoBlockHashCall {})?,
        };
        let of = read_commitments(views, at.precompile, at.accounts)?;
        let coded: BTreeSet<Address> = at.coded.iter().copied().collect();
        let input: Bytes = onERC721ReceivedCall {
            operator: Address::ZERO,
            from: Address::ZERO,
            tokenId: U256::ZERO,
            data: Bytes::new(),
        }
        .abi_encode()
        .into();
        let calls: Vec<Call> = at
            .accounts
            .iter()
            .filter(|&&account| !coded.contains(&account) && reserved(account, at.spec).is_none())
            .map(|&account| Call {
                from: None,
                to: account,
                input: input.clone(),
            })
            .collect();
        let magic = onERC721ReceivedCall::abi_encode_returns(&FixedBytes::from(
            onERC721ReceivedCall::SELECTOR,
        ));
        let mut marked = BTreeMap::new();
        for (call, answer) in calls
            .iter()
            .zip(views.call(&calls).map_err(ObserveError::Views)?)
        {
            match answer {
                None => {}
                Some(Outcome::Return(output)) if output.is_empty() || output[..] == magic[..] => {
                    marked.insert(call.to, !output.is_empty());
                }
                answer => {
                    return Err(ObserveError::Unexpected {
                        call: onERC721ReceivedCall::SIGNATURE,
                        to: call.to,
                        answer,
                    });
                }
            }
        }
        Ok(Self {
            tempo_state: at.tempo_state,
            precompile: at.precompile,
            anchor,
            of,
            marked,
            coded,
            spec: at.spec,
        })
    }
}

/// Tempo's commitments of the observed accounts at one block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tempo {
    /// The block the views answered at, as the producer states it.
    block: u64,
    of: BTreeMap<Address, B256>,
}

impl Tempo {
    /// Tempo's commitments `of` the accounts at block `block`, as a producer that holds Tempo's
    /// state itself states them; an account left out was not read.
    pub const fn new(block: u64, of: BTreeMap<Address, B256>) -> Self {
        Self { block, of }
    }
}

/// The Tempo block the views answer at, and the accounts to read.
#[derive(Debug, Clone, Copy)]
pub struct TempoAt<'a> {
    pub block: u64,
    pub precompile: Address,
    pub accounts: &'a [Address],
}

impl Observe for Tempo {
    type At<'a> = TempoAt<'a>;

    /// Reads each account's commitment, leaving out unanswered ones.
    fn observe<V: Views>(views: &mut V, at: TempoAt<'_>) -> Result<Self, ObserveError<V::Error>> {
        Ok(Self {
            block: at.block,
            of: read_commitments(views, at.precompile, at.accounts)?,
        })
    }
}

/// A zone state beside Tempo at the zone's anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mirror {
    zone: Zone,
    tempo: Option<Tempo>,
}

/// Tempo was read at `read`, while the zone's anchor is `anchor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Misanchored {
    pub anchor: u64,
    pub read: u64,
}

impl fmt::Display for Misanchored {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Tempo read at block {}, the zone's anchor is block {}",
            self.read, self.anchor
        )
    }
}

impl std::error::Error for Misanchored {}

impl Mirror {
    /// `zone` beside `tempo`; without `tempo` only the zone's own checks are armed. Fails when
    /// `tempo` was read at another block than the zone's anchor.
    pub fn new(zone: Zone, tempo: Option<Tempo>) -> Result<Self, Misanchored> {
        match &tempo {
            Some(tempo) if tempo.block != zone.anchor.number => Err(Misanchored {
                anchor: zone.anchor.number,
                read: tempo.block,
            }),
            _ => Ok(Self { zone, tempo }),
        }
    }

    /// Why `account` reads nothing from Tempo on this zone, `None` when it is eligible.
    fn ineligible(&self, account: Address) -> Option<&'static str> {
        reserved(account, self.zone.spec).or_else(|| {
            self.zone
                .coded
                .contains(&account)
                .then_some("an account with zone code")
        })
    }

    /// Tempo's commitment of `account` at the anchor; `None` when unread.
    fn tempo(&self, account: Address) -> Option<B256> {
        self.tempo.as_ref()?.of.get(&account).copied()
    }
}

/// A zone transaction or block: the mirror before and after it, its zone logs, and its
/// step ran.
pub type ZoneStep = Step<Mirror, Ran>;

/// One account's leaf in zone state after a step, beside what the zone serves for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneLeaf {
    /// The leaf the zone's state root commits to.
    pub stored: Leaf,
    /// The code hash the zone serves: what an account load inside a zone transaction yields, or
    /// the hash of its operator RPC's `eth_getCode`; `None` when not read.
    pub served: Option<B256>,
    /// Tempo's commitment at the zone's anchor after the step; `None` when not read.
    pub tempo: Option<B256>,
}

/// Each changed or signing account's zone leaf after a step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneLeaves {
    /// Whether TIP-1154 is active (T14) at the zone block.
    pub active: bool,
    /// The hardfork the zone block runs, which decides its system contracts.
    pub spec: TempoHardfork,
    pub of: BTreeMap<Address, ZoneLeaf>,
}

/// Why `account` never reads Tempo on a zone running `spec`, whatever its code; `None` when its
/// address is eligible: Tempo's reserved address spaces and the zone's system contracts active at
/// `spec`, as the zone itself excludes them (`zone_precompiles::is_zone_precompile`).
// <https://github.com/tempoxyz/tempo/blob/4008a2986ad18fa3bf55838d2d63bbb878ee7da7/tips/tip-1154.md#L59>
pub(crate) fn reserved(account: Address, spec: TempoHardfork) -> Option<&'static str> {
    const SYSTEM: [Address; 4] = [
        TEMPO_STATE_ADDRESS,
        ZONE_INBOX_ADDRESS,
        ZONE_OUTBOX_ADDRESS,
        ZONE_FEE_MANAGER_ADDRESS,
    ];
    // Zones gain these at T15.
    const T15: [Address; 2] = [ZONE_IDENTITY_ADDRESS, ZONE_ADDRESS_REGISTRY_ADDRESS];
    if SYSTEM.contains(&account) || (spec.is_t15() && T15.contains(&account)) {
        Some("a zone system contract")
    } else {
        account_spec::reserved(account)
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::address;

    use super::*;

    #[test]
    fn a_zone_reserves_its_system_contracts_active_at_its_hardfork() {
        let unused = address!("1c00000000000000000000000000000000000004");
        for spec in [TempoHardfork::T14, TempoHardfork::T15] {
            for system in [
                TEMPO_STATE_ADDRESS,
                ZONE_INBOX_ADDRESS,
                ZONE_OUTBOX_ADDRESS,
                ZONE_FEE_MANAGER_ADDRESS,
            ] {
                assert!(reserved(system, spec).is_some(), "{system} at {spec:?}");
            }
            assert_eq!(reserved(unused, spec), None, "{spec:?}");
            for t15 in [ZONE_IDENTITY_ADDRESS, ZONE_ADDRESS_REGISTRY_ADDRESS] {
                assert_eq!(
                    reserved(t15, spec).is_some(),
                    spec.is_t15(),
                    "{t15} at {spec:?}"
                );
            }
        }
    }
}
