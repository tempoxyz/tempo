//! The zone's configurable account checks (TIP-1154): what the zone shows of the watched accounts
//! beside what Tempo holds for them at the zone's anchor, after every step.

use std::{
    collections::{BTreeMap, HashSet},
    fmt, iter,
    sync::Arc,
};

use alloy_primitives::{Address, B256, Bytes, KECCAK256_EMPTY, Signature, TxKind, U256};
use evm2::EvmFeatures;
use invariants_core::{Call, Observe as _, ObserveError, Outcome, Report, Views};
use reth_evm::ConfigureEvm as _;
use reth_primitives_traits::Recovered;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{CONFIGURABLE_ACCOUNT_ADDRESS, PATH_USD_ADDRESS};
use tempo_evm::TempoEvm;
use tempo_fuzz_engine::{StepState, invariant_infos, observed};
use tempo_fuzz_types::InvariantInfo;
use tempo_invariants::{
    Checked as _, StepChecked as _,
    configurable_account::Leaf,
    zone_account::{
        self, Mirror, Tempo, VIEW, VIEW_DOC, Zone as ZoneModel, ZoneAt, ZoneLeaf, ZoneLeaves,
        ZoneStep,
    },
};
use tempo_primitives::{
    TempoTxEnvelope,
    transaction::{TempoSignature, TempoTransaction, envelope::TEMPO_SYSTEM_TX_SENDER},
};
use zone_evm::{L1OverlayDB, ZoneEvmConfig};
use zone_precompiles::L1StorageReader as _;
use zone_primitives::constants::{
    TEMPO_STATE_ADDRESS, ZONE_FEE_MANAGER_ADDRESS, ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS,
};

use crate::engine::L1;

/// The most accounts the checks watch, as each costs views at every step.
const MAX_WATCHED: usize = 32;

/// The gas each zone view's simulated transaction may use.
const VIEW_GAS_LIMIT: u64 = 10_000_000;

/// The zone account checks and their counter of reads that failed, for the harness's catalog.
pub(crate) fn catalog() -> Vec<InvariantInfo> {
    invariant_infos(zone_account::CHECKS)
        .chain(invariant_infos(zone_account::STEP_CHECKS))
        .chain(invariant_infos(zone_account::LEAF_CHECKS))
        .chain(iter::once(InvariantInfo {
            id: VIEW.to_string(),
            doc: VIEW_DOC.to_string(),
            tip: Some("TIP-1154".to_string()),
            covers: Vec::new(),
            since: None,
            until: None,
        }))
        .collect()
}

/// The zone's configurable account checks over the accounts they watch.
#[derive(Debug, Clone)]
pub(crate) struct AccountChecks {
    /// The accounts the checks read: the zone's system contracts first.
    watched: Vec<Address>,
}

impl AccountChecks {
    /// Checks watching the zone's system contracts, then the accounts L1 holds a commitment for,
    /// `committed`, the ones TIP-1154 treats differently, then `watched`, up to [`MAX_WATCHED`] in
    /// all.
    pub(crate) fn new(
        committed: impl IntoIterator<Item = Address>,
        watched: impl IntoIterator<Item = Address>,
    ) -> Self {
        let mut accounts = vec![
            TEMPO_STATE_ADDRESS,
            ZONE_INBOX_ADDRESS,
            ZONE_OUTBOX_ADDRESS,
            ZONE_FEE_MANAGER_ADDRESS,
        ];
        accounts.extend(committed);
        accounts.extend(watched);
        let mut seen = HashSet::new();
        accounts.retain(|account| seen.insert(*account));
        accounts.truncate(MAX_WATCHED);
        Self { watched: accounts }
    }

    /// Checks what the zone shows after the step `state` ends against what it showed after the
    /// run's last step, `last`, which it then replaces.
    pub(crate) fn check(
        &self,
        last: &mut Option<Mirror>,
        state: &StepState<'_, ZoneEvmConfig<L1>>,
        report: &mut Report,
    ) {
        let fork = Some(&state.env().spec);
        // A pre-state can break only what the zone stores: how it reads and serves Tempo is the
        // zone's own, and a zone that gets it wrong would on any pre-state.
        if state.start() {
            if state.env().spec.is_t14() {
                let accounts: Vec<Address> = state.changed().collect();
                let leaves = self.leaves(state, &accounts, None, report);
                report.run(ZoneLeaves::CHECKS, &leaves, fork);
            }
            return;
        }
        let pre = last.take();
        let Some(zone) = self.zone(state, report) else {
            return;
        };
        let anchor = zone.anchor().number;
        let tempo = Tempo::new(self.commitments(state, anchor, report));
        let post = Mirror::new(zone, Some(tempo));
        report.run(Mirror::CHECKS, &post, fork);

        let ran = &state.effects().ran;
        // The sequencer's own transactions act for no account.
        let tx = ran.tx().filter(|tx| tx.sender != TEMPO_SYSTEM_TX_SENDER);
        let mut accounts: Vec<Address> = state
            .changed()
            .chain(
                tx.iter()
                    .flat_map(|tx| iter::once(tx.sender).chain(tx.authority.accounts())),
            )
            .collect();
        accounts.sort_unstable();
        accounts.dedup();
        let leaves = self.leaves(state, &accounts, Some(anchor), report);
        report.run(ZoneLeaves::CHECKS, &leaves, fork);
        // A block's pre- and post-execution changes emit no logs the step checks could read.
        *last = Some(match pre {
            Some(pre) if ran.tx().is_some() => {
                let step = ZoneStep::new(pre, post, Arc::clone(state.effects()));
                report.run(Mirror::STEP_CHECKS, &step, fork);
                step.post
            }
            _ => post,
        });
    }

    /// Tempo's commitment of each watched account at `anchor`, as the zone's L1 reader answers;
    /// one whose read fails breaks [`VIEW`] in `report` and is left out.
    fn commitments(
        &self,
        state: &StepState<'_, ZoneEvmConfig<L1>>,
        anchor: u64,
        report: &mut Report,
    ) -> BTreeMap<Address, B256> {
        let l1 = state.evm_config().l1_reader();
        self.watched
            .iter()
            .filter_map(|&address| {
                let read = l1.read_l1_commitment(address, anchor);
                let read = observed(report, VIEW, address, read.map_err(ObserveError::Views))?;
                Some((address, read))
            })
            .collect()
    }

    /// What the zone shows of the watched accounts after the step, from T14, when TIP-1154
    /// activates.
    fn zone(
        &self,
        state: &StepState<'_, ZoneEvmConfig<L1>>,
        report: &mut Report,
    ) -> Option<ZoneModel> {
        if !state.env().spec.is_t14() {
            return None;
        }
        let coded: Vec<Address> = self
            .watched
            .iter()
            .copied()
            .filter(|address| {
                matches!(
                    state.account(*address),
                    Some(Some(info)) if info.code_hash != KECCAK256_EMPTY
                )
            })
            .collect();
        let spec = state.env().spec;
        let reserved: Vec<Address> = self
            .watched
            .iter()
            .copied()
            .filter(|address| reserved(*address, spec))
            .collect();
        let mut views = ZoneViews::new(state);
        let at = ZoneAt {
            tempo_state: TEMPO_STATE_ADDRESS,
            precompile: CONFIGURABLE_ACCOUNT_ADDRESS,
            accounts: &self.watched,
            coded: &coded,
            reserved: &reserved,
        };
        observed(report, VIEW, "the zone", ZoneModel::observe(&mut views, at))
    }

    /// The TIP-1108 leaves of `accounts`: what the zone stores, what it serves through Tempo's
    /// overlay at `anchor`, and what Tempo commits to there. A read that fails breaks [`VIEW`]
    /// in `report`; one that needs a key an exact pre-state lacks is left unread. Without `anchor`
    /// only what the zone stores is read.
    fn leaves(
        &self,
        state: &StepState<'_, ZoneEvmConfig<L1>>,
        accounts: &[Address],
        anchor: Option<u64>,
        report: &mut Report,
    ) -> ZoneLeaves {
        use evm2::evm::DynDatabase as _;
        let spec = state.env().spec;
        let l1 = state.evm_config().l1_reader();
        let mut overlay = L1OverlayDB::new(
            evm2::evm::Db::new(state.database()),
            l1.clone(),
            state.evm_config().portal_address(),
            spec,
        );
        if let Some(anchor) = anchor {
            overlay.l1_state().begin_transaction(U256::from(anchor));
        }
        let mut of = BTreeMap::new();
        for &address in accounts {
            let Some(account) = state.account(address) else {
                continue;
            };
            let extension = account
                .as_ref()
                .is_some_and(|info| !info.extension.is_empty());
            // An extension that does not encode leaves no commitment, which `extension` catches.
            let stored = state.leaf(address).unwrap_or_else(|| Leaf {
                commitment: B256::ZERO,
                code_hash: account
                    .as_ref()
                    .map_or(KECCAK256_EMPTY, |info| info.code_hash),
            });
            let (served, tempo) = match anchor {
                None => (None, None),
                Some(anchor) => {
                    state.forget_missed();
                    let served = overlay.get_account(&address);
                    let served = if state.missed() {
                        None
                    } else {
                        let read = served.map_err(|err| ObserveError::Views(err.to_string()));
                        observed(report, VIEW, address, read)
                            .map(|info| info.map_or(KECCAK256_EMPTY, |info| info.code_hash))
                    };
                    // An unread commitment leaves the checks on Tempo's side unarmed.
                    let read = l1.read_l1_commitment(address, anchor);
                    let tempo = observed(report, VIEW, address, read.map_err(ObserveError::Views));
                    (served, tempo)
                }
            };
            of.insert(
                address,
                ZoneLeaf {
                    stored,
                    extension,
                    reserved: reserved(address, spec),
                    served,
                    tempo,
                },
            );
        }
        ZoneLeaves { of }
    }
}

/// Whether the zone never reads Tempo for `address` at `spec`: an address no native account
/// may hold, or one of the zone's precompiles.
fn reserved(address: Address, spec: TempoHardfork) -> bool {
    !tempo_chainspec::is_valid_native_account(address, spec)
        || zone_precompiles::is_zone_precompile(address, spec)
}

/// Read-only calls against zone state, each run as a simulated zone transaction from the zero
/// address without fees: Tempo's overlay applies only inside a zone transaction.
///
/// A call that reads a key an exact pre-state lacks is unanswered, as the engine's own views treat
/// it: the pre-state holds only what execution touched.
struct ZoneViews<'a, 's> {
    state: &'a StepState<'s, ZoneEvmConfig<L1>>,
    evm: TempoEvm<'a>,
    chain_id: u64,
}

impl<'a, 's> ZoneViews<'a, 's> {
    /// Views of the state after `state`'s step, in its zone block environment.
    fn new(state: &'a StepState<'s, ZoneEvmConfig<L1>>) -> Self {
        let mut env = state.env().clone();
        // A view pays no fee, so neither the sender's balance nor the block's base fee applies.
        for feature in [
            EvmFeatures::FEE_CHARGE,
            EvmFeatures::BALANCE_CHECK,
            EvmFeatures::BALANCE_TOP_UP,
            EvmFeatures::NONCE_CHECK,
            EvmFeatures::BLOCK_GAS_LIMIT_CHECK,
            EvmFeatures::BASE_FEE_CHECK,
        ] {
            env.version.features.remove(feature);
        }
        let chain_id = env.version.chain_id;
        Self {
            state,
            evm: state.evm_config().evm_with_env(state.database(), env),
            chain_id,
        }
    }
}

impl Views for ZoneViews<'_, '_> {
    type Error = ViewFailed;

    fn call(&mut self, calls: &[Call]) -> Result<Vec<Option<Outcome>>, ViewFailed> {
        calls
            .iter()
            .map(|call| {
                let tx = TempoTransaction {
                    chain_id: self.chain_id,
                    fee_token: Some(PATH_USD_ADDRESS),
                    gas_limit: VIEW_GAS_LIMIT,
                    calls: vec![tempo_primitives::transaction::Call {
                        to: TxKind::Call(call.to),
                        value: U256::ZERO,
                        input: call.input.clone(),
                    }],
                    ..Default::default()
                };
                let signature = TempoSignature::from(Signature::test_signature());
                let envelope = TempoTxEnvelope::AA(tx.into_signed(signature));
                let sender = call.from.unwrap_or(Address::ZERO);
                let tx = Recovered::new_unchecked(envelope, sender);
                // The EVM caches what it loads, so a call reaches the database for every key it
                // reads only on an empty cache.
                let cache = &mut self.evm.overlay_db_mut().cache;
                cache.accounts.clear();
                cache.storage.clear();
                self.state.forget_missed();
                let result = self
                    .evm
                    .call_tx(&Recovered::new_unchecked(tx.into(), sender));
                if self.state.missed() {
                    return Ok(None);
                }
                match result {
                    Err(err) => Err(ViewFailed {
                        selector: call
                            .input
                            .get(..4)
                            .map(Bytes::copy_from_slice)
                            .unwrap_or_default(),
                        target: call.to,
                        reason: err.to_string(),
                    }),
                    Ok(result) if result.status => Ok(Some(Outcome::Return(result.output))),
                    Ok(result) => Ok(Some(Outcome::Revert(result.output))),
                }
            })
            .collect()
    }

    fn partial(&self) -> bool {
        self.state.partial()
    }
}

/// A zone view call the EVM could not run.
#[derive(Debug)]
struct ViewFailed {
    selector: Bytes,
    target: Address,
    reason: String,
}

impl fmt::Display for ViewFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} on {}: {}", self.selector, self.target, self.reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounts_l1_commits_to_are_watched_ahead_of_the_inputs() {
        let committed = Address::repeat_byte(0xc0);
        let many = (1..=2 * MAX_WATCHED as u8).map(Address::repeat_byte);
        let checks = AccountChecks::new([committed], many);
        assert_eq!(checks.watched.len(), MAX_WATCHED);
        assert_eq!(checks.watched[4], committed);
    }
}
