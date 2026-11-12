//! Configurable accounts on zones (TIP-1154): what a zone shows of each account beside what Tempo
//! holds for it at the zone's anchor.
//!
//! A zone reads Tempo state at a fixed anchor and never stores a commitment, so its checks compare
//! two chains. A check never reads two [`Views`]: a producer observes [`Zone`] through the zone's
//! views, then [`Tempo`] through Tempo's views at the anchor the zone reported, and joins them into
//! a [`Mirror`]. Without Tempo only the zone's own checks are armed.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use alloy_primitives::{Address, B256, Bytes, FixedBytes, U256};
use alloy_sol_types::SolCall;
use tempo_contracts::{
    precompiles::{
        IConfigurableAccountShim::onERC721ReceivedCall,
        ISignatureVerifier::{verifyConfigurableAccountCall, verifyKeychainAdminCall},
    },
    zones::{
        TEMPO_STATE_ADDRESS,
        TempoState::{tempoBlockHashCall, tempoBlockNumberCall},
        ZONE_FEE_MANAGER_ADDRESS, ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS,
    },
};

use crate::{
    Observe, ObserveError, Step, Tx, Views,
    configurable_account::{
        ConfigurableAccountConfig, Leaf, read_commitments, spec as account_spec,
    },
    view, view_many,
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
    /// Whether a call to each probed account answers as the account marker; unanswered probes are
    /// left out.
    marked: BTreeMap<Address, bool>,
    /// The observed accounts that hold zone code, so never read Tempo.
    coded: BTreeSet<Address>,
    /// The signature verifier's answer to each probe it answered.
    verified: Vec<Verified>,
}

/// A signature the producer asks the zone's signature verifier about, signed over `hash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    /// The account the signature claims to act for.
    pub account: Address,
    pub hash: B256,
    /// The encoded Tempo signature.
    pub signature: Bytes,
    pub kind: ProbeKind,
}

/// What a probe's signature is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeKind {
    /// An owner quorum carrying this configuration, asked through `verifyConfigurableAccount`.
    Quorum(ConfigurableAccountConfig),
    /// A keychain signature by the account's own root key, asked through `verifyKeychainAdmin`,
    /// which also guards TIP-20 `permit`'s retirement check.
    RootKey,
}

/// The verifier's answer to one probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub account: Address,
    pub kind: ProbeKind,
    pub accepted: bool,
}

impl fmt::Display for Verified {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ProbeKind::Quorum(config) => {
                write!(f, "version {} quorum of {}", config.version, self.account)
            }
            ProbeKind::RootKey => write!(f, "root key of {}", self.account),
        }
    }
}

impl Zone {
    /// The Tempo block the zone reads Tempo at.
    pub const fn anchor(&self) -> Anchor {
        self.anchor
    }
}

/// The predeploys, the accounts to read and the signatures to verify; `coded` are those of
/// `accounts` whose code in zone state is not empty.
#[derive(Debug, Clone, Copy)]
pub struct ZoneAt<'a> {
    pub tempo_state: Address,
    pub precompile: Address,
    pub verifier: Address,
    pub accounts: &'a [Address],
    pub coded: &'a [Address],
    pub probes: &'a [Probe],
}

impl Observe for Zone {
    type At<'a> = ZoneAt<'a>;

    /// Reads the anchor, each account's commitment and, for each eligible account, whether a call
    /// to it answers as the account marker's ERC-721 receiver hook (an account without code
    /// answers with empty output). Views must run as zone transactions, where the overlay applies.
    fn observe<V: Views>(views: &mut V, at: ZoneAt<'_>) -> Result<Self, ObserveError<V::Error>> {
        let ZoneAt {
            tempo_state,
            precompile,
            verifier,
            accounts,
            coded,
            probes,
        } = at;
        let anchor = Anchor {
            number: view(views, tempo_state, tempoBlockNumberCall {})?,
            hash: view(views, tempo_state, tempoBlockHashCall {})?,
        };
        let of = read_commitments(views, precompile, accounts)?;
        let coded: BTreeSet<Address> = coded.iter().copied().collect();
        let probed: Vec<Address> = accounts
            .iter()
            .copied()
            .filter(|account| !coded.contains(account) && reserved(*account).is_none())
            .collect();
        let input: Bytes = onERC721ReceivedCall {
            operator: Address::ZERO,
            from: Address::ZERO,
            tokenId: U256::ZERO,
            data: Bytes::new(),
        }
        .abi_encode()
        .into();
        let magic = onERC721ReceivedCall::abi_encode_returns(&FixedBytes::from(
            onERC721ReceivedCall::SELECTOR,
        ));
        let calls: Vec<(Address, Bytes)> = probed
            .iter()
            .map(|&account| (account, input.clone()))
            .collect();
        let outputs = views.call(&calls).map_err(ObserveError::Views)?;
        let mut marked = BTreeMap::new();
        for (&account, output) in probed.iter().zip(outputs) {
            match output {
                None => {}
                Some(output) if output.is_empty() => {
                    marked.insert(account, false);
                }
                Some(output) if output[..] == magic[..] => {
                    marked.insert(account, true);
                }
                Some(output) => {
                    return Err(ObserveError::Malformed {
                        call: onERC721ReceivedCall::SIGNATURE,
                        to: account,
                        output: Some(output),
                    });
                }
            }
        }
        Ok(Self {
            tempo_state,
            precompile,
            anchor,
            of,
            marked,
            coded,
            verified: verify(views, verifier, probes)?,
        })
    }
}

/// Asks the verifier about each probe, leaving out unanswered ones (a malformed or invalid
/// signature reverts).
fn verify<V: Views>(
    views: &mut V,
    verifier: Address,
    probes: &[Probe],
) -> Result<Vec<Verified>, ObserveError<V::Error>> {
    let (quorums, roots): (Vec<_>, Vec<_>) = probes
        .iter()
        .partition(|probe| matches!(probe.kind, ProbeKind::Quorum(_)));
    let quorum_calls: Vec<_> = quorums
        .iter()
        .map(|probe| {
            let call = verifyConfigurableAccountCall {
                account: probe.account,
                hash: probe.hash,
                signature: probe.signature.clone(),
            };
            (verifier, call)
        })
        .collect();
    let root_calls: Vec<_> = roots
        .iter()
        .map(|probe| {
            let call = verifyKeychainAdminCall {
                account: probe.account,
                hash: probe.hash,
                signature: probe.signature.clone(),
            };
            (verifier, call)
        })
        .collect();
    let answers = view_many(views, &quorum_calls)?
        .into_iter()
        .chain(view_many(views, &root_calls)?);
    Ok(quorums
        .into_iter()
        .chain(roots)
        .zip(answers)
        .filter_map(|(probe, accepted)| {
            Some(Verified {
                account: probe.account,
                kind: probe.kind.clone(),
                accepted: accepted?,
            })
        })
        .collect())
}

/// Tempo's commitments of the observed accounts at one block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tempo {
    /// The block the views answered at, as the producer states it.
    block: u64,
    /// Tempo's canonical hash of that block, when the producer knows it.
    hash: Option<B256>,
    of: BTreeMap<Address, B256>,
}

impl Tempo {
    /// Tempo at a block before T14, where no account has a commitment.
    pub fn unregistered(block: u64, hash: Option<B256>, accounts: &[Address]) -> Self {
        Self {
            block,
            hash,
            of: accounts
                .iter()
                .map(|&account| (account, B256::ZERO))
                .collect(),
        }
    }
}

/// The Tempo block the views answer at, its canonical hash when known, and the accounts to read.
#[derive(Debug, Clone, Copy)]
pub struct TempoAt<'a> {
    pub block: u64,
    pub hash: Option<B256>,
    pub precompile: Address,
    pub accounts: &'a [Address],
}

impl Observe for Tempo {
    type At<'a> = TempoAt<'a>;

    /// Reads each account's commitment, leaving out unanswered ones.
    fn observe<V: Views>(views: &mut V, at: TempoAt<'_>) -> Result<Self, ObserveError<V::Error>> {
        Ok(Self {
            block: at.block,
            hash: at.hash,
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

    /// The Tempo block the zone reads Tempo at.
    pub const fn anchor(&self) -> Anchor {
        self.zone.anchor
    }

    /// Why `account` reads nothing from Tempo on this zone, `None` when it is eligible.
    fn ineligible(&self, account: Address) -> Option<&'static str> {
        reserved(account).or_else(|| {
            self.zone
                .coded
                .contains(&account)
                .then_some("an account with zone code")
        })
    }

    /// Tempo's commitment of `account` at the anchor; `None` when unread, or when Tempo's block at
    /// the anchor's number is not the anchor (judged by ANCHOR-CANONICAL).
    fn tempo(&self, account: Address) -> Option<B256> {
        let tempo = self.tempo.as_ref()?;
        if tempo.hash.is_some_and(|hash| hash != self.zone.anchor.hash) {
            return None;
        }
        tempo.of.get(&account).copied()
    }
}

/// A zone transaction or block: the mirror before and after it, its zone logs, and its
/// transaction (`None` for a system transaction or a whole block).
pub type ZoneStep = Step<Mirror, Option<Tx>>;

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
    pub of: BTreeMap<Address, ZoneLeaf>,
}

/// Why `account` never reads Tempo on a zone whatever its code, `None` when its address is
/// eligible: Tempo's reserved address spaces and the zone's system contracts.
// <https://github.com/tempoxyz/tempo/blob/4008a2986ad18fa3bf55838d2d63bbb878ee7da7/tips/tip-1154.md#L59>
pub(crate) fn reserved(account: Address) -> Option<&'static str> {
    const SYSTEM: [Address; 4] = [
        TEMPO_STATE_ADDRESS,
        ZONE_INBOX_ADDRESS,
        ZONE_OUTBOX_ADDRESS,
        ZONE_FEE_MANAGER_ADDRESS,
    ];
    if SYSTEM.contains(&account) {
        Some("a zone system contract")
    } else {
        account_spec::reserved(account)
    }
}
