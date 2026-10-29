//! Tempo Zones, zone side: the predeploys every zone block runs (`TempoState`, `ZoneInbox`,
//! `ZoneOutbox`) and the zone's TIP-20 tokens, read through views at a zone block.
//!
//! The fuzz harness executes Tempo blocks only; these checks run where zone blocks execute, such
//! as the zone checker ExEx. A runner observes [`Zone`] before and after each canonical zone block
//! and judges:
//!
//! - [`CHECKS`] on one zone state;
//! - [`STEP_CHECKS`] on a block's [`Step`]: the states around it, its logs, and the
//!   [`ZoneBlock`] describing its header and transactions;
//! - [`HISTORY_CHECKS`] on a state beside the [`Bridged`] history folded over every block so far;
//! - [`PRIVACY_CHECKS`] on account-scoped getters asked as a third party ([`Privacy`]);
//! - [`ANCHOR_CHECKS`] on a block paired with the portal at the Tempo block it imports;
//! - [`BATCH_CHECKS`] on a batch the portal accepted paired with the zone block it proves.

use std::{collections::BTreeMap, fmt, ops::Range};

use alloy_primitives::{Address, B256, Bytes, Log, U256, address};
use alloy_sol_types::{SolCall, SolEvent};
use invariants_core::{AnyCheck, answered};
pub use invariants_core::{Fold, Folded, History, Outcome, Pair};

use crate::{Observe, ObserveError, Step, Views, decode};

pub use tempo_contracts::{
    precompiles::{
        ACCOUNT_KEYCHAIN_ADDRESS, IAccountKeychain, INonce, ITIP20, NONCE_PRECOMPILE_ADDRESS,
    },
    zones::{
        IZoneInbox, IZoneOutbox, TEMPO_STATE_ADDRESS, TempoState, ZONE_INBOX_ADDRESS,
        ZONE_OUTBOX_ADDRESS, ZonePortal,
    },
};

mod checks;
#[cfg(test)]
mod tests;

pub use checks::{
    ACCOUNT_GETTER_PRIVACY, ADVANCE_TEMPO_FIRST, ANCHOR_CHECKS, BALANCE_ALLOWANCE_PRIVACY,
    BATCH_CHECKS, BATCH_WITHDRAWAL_COMMITMENT, BLOCK_TIMESTAMP_MONOTONIC, CHECKS,
    CONTRACT_CREATION_DISABLED, DEPOSIT_NUMBER_MONOTONIC, DEPOSIT_PROCESSED_PREFIX, HISTORY_CHECKS,
    MINT_BURN_AUTHORITY, PREDEPLOY_ADDRESSES, PRIVACY_CHECKS, REFUND_READ_PRIVACY, STEP_CHECKS,
    SUPPLY_SOLVENCY, TEMPO_HEADER_CONTINUITY, TOKEN_ENABLEMENT_BINDING, WITHDRAWAL_BATCH_INDEX,
};

/// The account privacy reads are asked as: no key is known for it, so it owns no account, is no
/// sequencer and holds no role.
pub const THIRD_PARTY: Address = address!("0x7a1d000000000000000000000000000000000bad");

/// Every zone-side check, whatever its context.
pub fn all() -> impl Iterator<Item = &'static dyn AnyCheck> {
    CHECKS
        .iter()
        .map(|check| check as &dyn AnyCheck)
        .chain(STEP_CHECKS.iter().map(|check| check as &dyn AnyCheck))
        .chain(HISTORY_CHECKS.iter().map(|check| check as &dyn AnyCheck))
        .chain(PRIVACY_CHECKS.iter().map(|check| check as &dyn AnyCheck))
        .chain(ANCHOR_CHECKS.iter().map(|check| check as &dyn AnyCheck))
        .chain(BATCH_CHECKS.iter().map(|check| check as &dyn AnyCheck))
}

/// A zone's protocol state at one block, as the predeploys' views report it. A predeploy whose
/// views answer nothing (no code at its address, or a reverting getter) reads as `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone {
    /// `TempoState`: the last finalized Tempo block.
    pub tempo: Option<TempoBlock>,
    /// `ZoneInbox`: how far the portal's deposit queue has been processed.
    pub inbox: Option<Inbox>,
    /// `ZoneOutbox.lastBatch()`: the last finalized withdrawal batch.
    pub outbox: Option<IZoneOutbox::LastBatch>,
    /// `totalSupply()` of each observed zone token that answered.
    pub supplies: BTreeMap<Address, U256>,
}

/// A Tempo block the zone finalized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TempoBlock {
    pub number: u64,
    pub hash: B256,
}

/// The inbox's processed-deposit cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inbox {
    pub processed_deposit_number: u64,
    pub processed_deposit_queue_hash: B256,
    /// `processedTokenEnablementHash()`, `None` when it did not answer.
    pub processed_token_enablement_hash: Option<B256>,
}

impl Observe for Zone {
    type At<'a> = &'a [Address];

    /// Reads the three predeploys and the supply of each token in `at`, in one batch of view
    /// calls. Fails only when an answer is malformed.
    fn observe<V: Views>(
        views: &mut V,
        tokens: &[Address],
    ) -> Result<Self, ObserveError<V::Error>> {
        let calls: Vec<(Address, Bytes)> = [
            (
                TEMPO_STATE_ADDRESS,
                TempoState::tempoBlockNumberCall {}.abi_encode(),
            ),
            (
                TEMPO_STATE_ADDRESS,
                TempoState::tempoBlockHashCall {}.abi_encode(),
            ),
            (
                ZONE_INBOX_ADDRESS,
                IZoneInbox::processedDepositNumberCall {}.abi_encode(),
            ),
            (
                ZONE_INBOX_ADDRESS,
                IZoneInbox::processedDepositQueueHashCall {}.abi_encode(),
            ),
            (
                ZONE_INBOX_ADDRESS,
                IZoneInbox::processedTokenEnablementHashCall {}.abi_encode(),
            ),
            (
                ZONE_OUTBOX_ADDRESS,
                IZoneOutbox::lastBatchCall {}.abi_encode(),
            ),
        ]
        .into_iter()
        .chain(
            tokens
                .iter()
                .map(|&token| (token, ITIP20::totalSupplyCall {}.abi_encode())),
        )
        .map(|(to, input)| (to, input.into()))
        .collect();
        let mut out = views.call(&calls).map_err(ObserveError::Views)?.into_iter();
        let tempo_number = answered(decode::<TempoState::tempoBlockNumberCall, _>(
            TEMPO_STATE_ADDRESS,
            out.next(),
        ))?;
        let tempo_hash = answered(decode::<TempoState::tempoBlockHashCall, _>(
            TEMPO_STATE_ADDRESS,
            out.next(),
        ))?;
        let processed_number = answered(decode::<IZoneInbox::processedDepositNumberCall, _>(
            ZONE_INBOX_ADDRESS,
            out.next(),
        ))?;
        let processed_hash = answered(decode::<IZoneInbox::processedDepositQueueHashCall, _>(
            ZONE_INBOX_ADDRESS,
            out.next(),
        ))?;
        let enablement_hash = answered(decode::<IZoneInbox::processedTokenEnablementHashCall, _>(
            ZONE_INBOX_ADDRESS,
            out.next(),
        ))?;
        let outbox = answered(decode::<IZoneOutbox::lastBatchCall, _>(
            ZONE_OUTBOX_ADDRESS,
            out.next(),
        ))?;
        let mut supplies = BTreeMap::new();
        for &token in tokens {
            if let Some(supply) = answered(decode::<ITIP20::totalSupplyCall, _>(token, out.next()))?
            {
                supplies.insert(token, supply);
            }
        }
        Ok(Self {
            tempo: tempo_number
                .zip(tempo_hash)
                .map(|(number, hash)| TempoBlock { number, hash }),
            inbox: processed_number
                .zip(processed_hash)
                .map(|(number, hash)| Inbox {
                    processed_deposit_number: number,
                    processed_deposit_queue_hash: hash,
                    processed_token_enablement_hash: enablement_hash,
                }),
            outbox,
            supplies,
        })
    }
}

/// A zone block: its header and its transactions, the context of a [`Step`] over [`Zone`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneBlock {
    pub number: u64,
    pub timestamp: u64,
    pub parent_number: u64,
    pub parent_timestamp: u64,
    /// The transactions in block order.
    pub txs: Vec<ZoneTx>,
    /// The Tempo headers the block's `advanceTempo` or `advanceTempoHeaders` imported, in order;
    /// empty when it imported none or the runner did not decode them.
    pub imported: Vec<TempoHeader>,
}

impl ZoneBlock {
    /// The logs of transaction `index` in `logs`, the step's logs.
    pub fn logs_of<'a>(&self, index: usize, logs: &'a [Log]) -> &'a [Log] {
        self.txs
            .get(index)
            .and_then(|tx| logs.get(tx.logs.clone()))
            .unwrap_or_default()
    }

    /// Whether the block runs `advanceTempo`, a full Tempo import with deposits and token
    /// enablements, rather than only advancing the checkpoint.
    pub fn imports_tempo(&self) -> bool {
        self.txs.iter().any(|tx| {
            tx.success
                && tx.to == Some(ZONE_INBOX_ADDRESS)
                && tx.selector() == Some(IZoneInbox::advanceTempoCall::SELECTOR)
        })
    }
}

impl fmt::Display for ZoneBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "zone block {}", self.number)
    }
}

/// One transaction of a zone block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneTx {
    pub sender: Address,
    /// `None` for a contract creation.
    pub to: Option<Address>,
    pub input: Bytes,
    /// Whether its receipt reports success.
    pub success: bool,
    /// Its logs' positions in the step's logs.
    pub logs: Range<usize>,
}

impl ZoneTx {
    pub fn selector(&self) -> Option<[u8; 4]> {
        self.input.get(..4).and_then(|s| s.try_into().ok())
    }
}

/// A Tempo header a zone block imported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TempoHeader {
    pub number: u64,
    /// `keccak256` of the header's RLP, its block hash.
    pub hash: B256,
    pub parent_hash: B256,
}

/// Per token, the supply the bridge events since the first observed block account for: the
/// supply then, plus every mint the inbox announced (processed deposits, processed withdrawal
/// bounce-backs, claimed refunds), minus every user withdrawal the outbox announced (amount plus
/// fee, both burned).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bridged {
    /// `None` once the sum leaves `U256`.
    pub expected: BTreeMap<Address, Option<U256>>,
}

impl Fold<Step<Zone, ZoneBlock>> for Bridged {
    fn fold(&mut self, step: &Step<Zone, ZoneBlock>) {
        for (&token, &supply) in &step.pre.supplies {
            self.expected.entry(token).or_insert(Some(supply));
        }
        // A token the block enabled had no supply before it, so its first mints count from zero.
        for &token in step.post.supplies.keys() {
            if !step.pre.supplies.contains_key(&token) {
                self.expected.entry(token).or_insert(Some(U256::ZERO));
            }
        }
        let mut credit = |token: Address, amount: U256, mint: bool| {
            if let Some(expected) = self.expected.get_mut(&token) {
                *expected = expected.and_then(|value| {
                    if mint {
                        value.checked_add(amount)
                    } else {
                        value.checked_sub(amount)
                    }
                });
            }
        };
        for log in step.logs_from(ZONE_INBOX_ADDRESS) {
            if let Some((token, amount)) = inbox_mint(&log.data) {
                credit(token, amount, true);
            }
        }
        for e in step.events::<IZoneOutbox::WithdrawalRequested>(ZONE_OUTBOX_ADDRESS) {
            // A zero sender marks a deposit bounce-back, which burns nothing on the zone.
            if !e.sender.is_zero() {
                credit(e.token, U256::from(e.amount) + U256::from(e.fee), false);
            }
        }
    }
}

/// Account-scoped getters asked as a third party, beside what their owner reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Privacy {
    pub asker: Address,
    pub reads: Vec<PrivateRead>,
}

/// One account-scoped getter, asked as the third party and as its owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateRead {
    pub getter: Getter,
    /// The getter's target.
    pub to: Address,
    /// Who may read it: the asker gets nothing it may not.
    pub owner: Address,
    /// What the third party got; `None` when nothing answered.
    pub asked: Option<Outcome>,
    /// What `owner` got.
    pub owned: Option<Outcome>,
}

impl fmt::Display for PrivateRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} on {}", self.getter, self.to)
    }
}

/// An account-scoped getter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Getter {
    /// `ITIP20.balanceOf(account)`.
    Balance { account: Address },
    /// `ITIP20.allowance(owner, spender)`.
    Allowance { owner: Address, spender: Address },
    /// `ZoneInbox.refunds(token, owner)`.
    Refund { token: Address, owner: Address },
    /// `NonceManager.getNonce(account, 1)`.
    Nonce { account: Address },
    /// `AccountKeychain.getKey(account, account)`.
    Key { account: Address },
}

impl Getter {
    /// The getter's ABI call.
    fn input(&self) -> Bytes {
        match *self {
            Self::Balance { account } => ITIP20::balanceOfCall { account }.abi_encode(),
            Self::Allowance { owner, spender } => {
                ITIP20::allowanceCall { owner, spender }.abi_encode()
            }
            Self::Refund { token, owner } => IZoneInbox::refundsCall { token, owner }.abi_encode(),
            Self::Nonce { account } => INonce::getNonceCall {
                account,
                nonceKey: U256::from(1),
            }
            .abi_encode(),
            Self::Key { account } => IAccountKeychain::getKeyCall {
                account,
                keyId: account,
            }
            .abi_encode(),
        }
        .into()
    }

    /// Whose value the getter reads, the one caller always allowed.
    fn owner(&self) -> Address {
        match *self {
            Self::Balance { account } | Self::Nonce { account } | Self::Key { account } => account,
            Self::Allowance { owner, .. } | Self::Refund { owner, .. } => owner,
        }
    }
}

impl fmt::Display for Getter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Balance { account } => write!(f, "balanceOf({account})"),
            Self::Allowance { owner, spender } => write!(f, "allowance({owner}, {spender})"),
            Self::Refund { token, owner } => write!(f, "refunds({token}, {owner})"),
            Self::Nonce { account } => write!(f, "getNonce({account}, 1)"),
            Self::Key { account } => write!(f, "getKey({account}, {account})"),
        }
    }
}

/// Which getters to ask, and of which contract.
#[derive(Debug, Clone, Copy)]
pub struct PrivacyAt<'a> {
    pub asker: Address,
    /// Each getter with its target: a token for balances and allowances.
    pub getters: &'a [(Address, Getter)],
}

impl Observe for Privacy {
    type At<'a> = PrivacyAt<'a>;

    /// Asks each getter as `asker` and as its owner, through [`Views::call_from`]. Views that
    /// cannot set the caller answer nothing, and the checks then judge nothing.
    fn observe<V: Views>(views: &mut V, at: PrivacyAt<'_>) -> Result<Self, ObserveError<V::Error>> {
        let calls: Vec<(Address, Bytes)> = at
            .getters
            .iter()
            .map(|(to, getter)| (*to, getter.input()))
            .collect();
        let asked = views
            .call_from(at.asker, &calls)
            .map_err(ObserveError::Views)?;
        let mut reads = Vec::with_capacity(calls.len());
        for (&(to, getter), asked) in at.getters.iter().zip(asked) {
            let owner = getter.owner();
            let owned = views
                .call_from(owner, &[(to, getter.input())])
                .map_err(ObserveError::Views)?
                .into_iter()
                .next()
                .flatten();
            reads.push(PrivateRead {
                getter,
                to,
                owner,
                asked,
                owned,
            });
        }
        Ok(Self {
            asker: at.asker,
            reads,
        })
    }
}

/// The portal at the Tempo block a zone block imported, as its views report it there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortalAnchor {
    pub portal: Address,
    pub token_enablement_hash: Option<B256>,
    pub deposit_count: Option<u64>,
    pub current_deposit_queue_hash: Option<B256>,
}

impl fmt::Display for PortalAnchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "portal {}", self.portal)
    }
}

impl Observe for PortalAnchor {
    type At<'a> = Address;

    fn observe<V: Views>(views: &mut V, portal: Address) -> Result<Self, ObserveError<V::Error>> {
        let calls: Vec<(Address, Bytes)> = [
            ZonePortal::tokenEnablementHashCall {}.abi_encode(),
            ZonePortal::depositCountCall {}.abi_encode(),
            ZonePortal::currentDepositQueueHashCall {}.abi_encode(),
        ]
        .into_iter()
        .map(|input| (portal, input.into()))
        .collect();
        let mut out = views.call(&calls).map_err(ObserveError::Views)?.into_iter();
        Ok(Self {
            portal,
            token_enablement_hash: answered(decode::<ZonePortal::tokenEnablementHashCall, _>(
                portal,
                out.next(),
            ))?,
            deposit_count: answered(decode::<ZonePortal::depositCountCall, _>(
                portal,
                out.next(),
            ))?,
            current_deposit_queue_hash: answered(decode::<
                ZonePortal::currentDepositQueueHashCall,
                _,
            >(portal, out.next()))?,
        })
    }
}

/// A zone block paired with the portal at the Tempo block it imported.
pub type Anchored = Pair<Step<Zone, ZoneBlock>, PortalAnchor>;

/// A batch the portal accepted, as its `BatchSubmitted` event reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Submission {
    pub withdrawal_batch_index: u64,
    /// The zone block the batch proves.
    pub next_block_hash: B256,
    pub withdrawal_queue_hash: B256,
}

impl fmt::Display for Submission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "batch {} proving zone block {}",
            self.withdrawal_batch_index, self.next_block_hash
        )
    }
}

impl Submission {
    /// Decodes a `BatchSubmitted` log of either version; `None` for any other log.
    pub fn from_log(log: &Log) -> Option<Self> {
        if let Ok(e) = ZonePortal::BatchSubmitted_1::decode_log_data(&log.data) {
            return Some(Self {
                withdrawal_batch_index: e.withdrawalBatchIndex,
                next_block_hash: e.nextBlockHash,
                withdrawal_queue_hash: e.withdrawalQueueHash,
            });
        }
        let e = ZonePortal::BatchSubmitted_0::decode_log_data(&log.data).ok()?;
        Some(Self {
            withdrawal_batch_index: e.withdrawalBatchIndex,
            next_block_hash: e.nextBlockHash,
            withdrawal_queue_hash: e.withdrawalQueueHash,
        })
    }
}

/// The zone block a batch proves paired with the batch.
pub type Proven = Pair<Zone, Submission>;

impl fmt::Display for Zone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.tempo {
            Some(tempo) => write!(f, "zone at tempo block {}", tempo.number),
            None => f.write_str("zone"),
        }
    }
}

/// The token and amount an inbox event mints: a processed deposit, a processed withdrawal
/// bounce-back or a claimed refund. `None` for any other log.
pub fn inbox_mint(log: &alloy_primitives::LogData) -> Option<(Address, U256)> {
    if let Ok(e) = IZoneInbox::DepositProcessed::decode_log_data(log) {
        return Some((e.token, U256::from(e.amount)));
    }
    if let Ok(e) = IZoneInbox::WithdrawalBounceBackProcessed::decode_log_data(log) {
        return Some((e.token, U256::from(e.amount)));
    }
    let e = IZoneInbox::RefundClaimed::decode_log_data(log).ok()?;
    Some((e.token, U256::from(e.amount)))
}
