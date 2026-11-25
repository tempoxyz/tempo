//! The zone's configurable account checks (TIP-1154): what the zone shows of the watched accounts
//! beside what Tempo holds for them at the zone's anchor, after every step.

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashSet},
    fmt, iter,
    sync::Arc,
};

use alloy_primitives::{Address, Bytes, KECCAK256_EMPTY, Signature, TxKind, U256};
use evm2::EvmFeatures;
use invariants_core::{Call, Observe as _, Outcome, Report, Views};
use reth_evm::ConfigureEvm as _;
use reth_primitives_traits::Recovered;
use tempo_contracts::precompiles::{CONFIGURABLE_ACCOUNT_ADDRESS, PATH_USD_ADDRESS};
use tempo_evm::{TempoEvm, TempoEvmEnv};
use tempo_fuzz_engine::{StepState, invariant_infos, observed};
use tempo_fuzz_types::InvariantInfo;
use tempo_invariants::{
    Checked as _, Ran, StepChecked as _,
    zone_account::{
        self, Mirror, Tempo, VIEW, Zone as ZoneModel, ZoneAt, ZoneLeaf, ZoneLeaves, ZoneStep,
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
    decode_zone_chain_id,
};

use crate::engine::L1;

/// The most accounts the checks watch, as each costs views at every step.
pub(crate) const MAX_WATCHED: usize = 32;

/// The gas each zone view's simulated transaction may use.
const VIEW_GAS_LIMIT: u64 = 10_000_000;

/// The zone account checks and their counter of reads that failed, for the harness's catalog.
pub(crate) fn catalog() -> Vec<InvariantInfo> {
    invariant_infos(zone_account::CHECKS)
        .chain(invariant_infos(zone_account::STEP_CHECKS))
        .chain(invariant_infos(zone_account::LEAF_CHECKS))
        .chain(iter::once(InvariantInfo {
            id: VIEW.to_string(),
            doc: "The zone's views of configurable accounts answer.".to_string(),
            tip: Some("TIP-1154".to_string()),
            covers: Vec::new(),
            since: None,
            until: None,
        }))
        .collect()
}

/// The zone's configurable account checks, with what the last step showed.
#[derive(Debug, Clone, Default)]
pub(crate) struct AccountChecks {
    /// The accounts the checks read: the zone's system contracts first.
    watched: Vec<Address>,
    /// What the zone showed after the last step, which the next is checked against.
    pre: RefCell<Option<Mirror>>,
}

impl AccountChecks {
    /// Checks watching the zone's system contracts, then `watched`, then the accounts `l1` holds a
    /// commitment for, up to [`MAX_WATCHED`] in all.
    pub(crate) fn new(l1: &L1, watched: impl IntoIterator<Item = Address>) -> Self {
        let mut accounts = vec![
            TEMPO_STATE_ADDRESS,
            ZONE_INBOX_ADDRESS,
            ZONE_OUTBOX_ADDRESS,
            ZONE_FEE_MANAGER_ADDRESS,
        ];
        accounts.extend(watched);
        accounts.extend(l1.committed());
        let mut seen = HashSet::new();
        accounts.retain(|account| seen.insert(*account));
        accounts.truncate(MAX_WATCHED);
        Self {
            watched: accounts,
            pre: RefCell::default(),
        }
    }

    /// Checks what the zone shows after the step `state` ends, reading Tempo from `l1`.
    pub(crate) fn check(
        &self,
        l1: &L1,
        state: &StepState<'_, ZoneEvmConfig<L1>>,
        report: &mut Report,
    ) {
        let pre = self.pre.take();
        let Some(zone) = self.zone(state, report) else {
            return;
        };
        let anchor = zone.anchor().number;
        let tempo = Tempo::new(anchor, l1.commitments(&self.watched, anchor));
        let post = Mirror::new(zone, Some(tempo)).expect("Tempo is read at the zone's anchor");
        let fork = Some(&state.env().spec);
        report.run(Mirror::CHECKS, &post, fork);

        // The sequencer's own transactions act for no account.
        let tx = state
            .ran()
            .tx()
            .filter(|tx| tx.sender != TEMPO_SYSTEM_TX_SENDER);
        let mut accounts: Vec<Address> = state
            .changed()
            .chain(
                tx.iter()
                    .flat_map(|tx| iter::once(tx.sender).chain(tx.authority.accounts())),
            )
            .collect();
        accounts.sort_unstable();
        accounts.dedup();
        // A block's pre- and post-execution changes emit no logs the step checks could read. The
        // sequencer's own transactions, such as `advanceTempo`, are judged as no user's.
        if let Some(pre) = pre
            && let Some(ran) = state.ran().tx()
        {
            let mut effects = state.effects();
            if ran.sender == TEMPO_SYSTEM_TX_SENDER {
                Arc::make_mut(&mut effects).ran = Ran::PreBlock;
            }
            let step = ZoneStep::new(pre, post.clone(), effects);
            report.run(Mirror::STEP_CHECKS, &step, fork);
        }
        report.run(
            ZoneLeaves::CHECKS,
            &self.leaves(l1, state, &accounts, anchor),
            fork,
        );
        *self.pre.borrow_mut() = Some(post);
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
        let mut views = ZoneViews::new(state, state.env().clone());
        let at = ZoneAt {
            tempo_state: TEMPO_STATE_ADDRESS,
            precompile: CONFIGURABLE_ACCOUNT_ADDRESS,
            accounts: &self.watched,
            coded: &coded,
        };
        observed(report, VIEW, "the zone", ZoneModel::observe(&mut views, at))
    }

    /// The TIP-1108 leaves of `accounts`: what the zone stores, what it serves through Tempo's
    /// overlay at `anchor`, and what Tempo commits to there.
    fn leaves(
        &self,
        l1: &L1,
        state: &StepState<'_, ZoneEvmConfig<L1>>,
        accounts: &[Address],
        anchor: u64,
    ) -> ZoneLeaves {
        use evm2::evm::DynDatabase as _;
        let spec = state.env().spec;
        let mut overlay = L1OverlayDB::new(
            evm2::evm::Db::new(state.database()),
            l1.clone(),
            portal(state.env()),
            spec,
        );
        overlay.l1_state().begin_transaction(U256::from(anchor));
        let mut of = BTreeMap::new();
        for &address in accounts {
            let Some(stored) = state.leaf(address) else {
                continue;
            };
            let served = overlay
                .get_account(&address)
                .ok()
                .map(|info| info.map_or(KECCAK256_EMPTY, |info| info.code_hash));
            // An unread commitment leaves the checks on Tempo's side unarmed.
            let tempo = l1.read_l1_commitment(address, anchor).ok();
            of.insert(
                address,
                ZoneLeaf {
                    stored,
                    served,
                    tempo,
                },
            );
        }
        ZoneLeaves {
            active: spec.is_t14(),
            of,
        }
    }
}

/// The portal of the zone `env`'s chain ID names.
fn portal(env: &TempoEvmEnv) -> Address {
    decode_zone_chain_id(env.version.chain_id)
        .map(|(_, zone_id)| tempo_precompiles::zone_factory::portal_address(zone_id))
        .unwrap_or_default()
}

/// Read-only calls against zone state, each run as a simulated zone transaction from the zero
/// address without fees: Tempo's overlay applies only inside a zone transaction.
struct ZoneViews<'a> {
    evm: TempoEvm<'a>,
    chain_id: u64,
}

impl<'a> ZoneViews<'a> {
    /// Views of the state after `state`'s step, in the zone block environment `env`.
    fn new(state: &'a StepState<'_, ZoneEvmConfig<L1>>, mut env: TempoEvmEnv) -> Self {
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
            evm: state.evm_config().evm_with_env(state.database(), env),
            chain_id,
        }
    }
}

impl Views for ZoneViews<'_> {
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
                match self
                    .evm
                    .call_tx(&Recovered::new_unchecked(tx.into(), sender))
                {
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
        false
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
