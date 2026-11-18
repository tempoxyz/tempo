//! The zone's configurable account checks (TIP-1154): what the zone shows of the watched accounts
//! beside what Tempo holds for them at the zone's anchor, after every step.

use std::{cell::RefCell, collections::BTreeMap, fmt, iter};

use alloy_primitives::{Address, Bytes, KECCAK256_EMPTY, Signature, TxKind, U256};
use evm2::EvmFeatures;
use invariants_core::{Observe as _, Report, Views};
use reth_primitives_traits::Recovered;
use tempo_contracts::precompiles::{CONFIGURABLE_ACCOUNT_ADDRESS, PATH_USD_ADDRESS};
use tempo_evm::{TempoEvm, TempoEvmEnv};
use tempo_fuzz_engine::{EvmConfig, StepState};
use tempo_invariants::{
    all,
    zone_account::{
        Mirror, Tempo, TempoAt, VIEW, Zone as ZoneModel, ZoneAt, ZoneLeaf, ZoneLeaves, ZoneStep,
    },
};
use tempo_primitives::{
    TempoTxEnvelope,
    transaction::{TempoSignature, TempoTransaction, envelope::TEMPO_SYSTEM_TX_SENDER},
};
use zone_evm::L1OverlayDB;
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

/// The zone's configurable account checks, with what the last step showed.
#[derive(Debug)]
pub(crate) struct AccountChecks {
    /// The accounts the checks read: the zone's system contracts first.
    watched: Vec<Address>,
    /// What the zone showed after the last step, which the next is checked against.
    pre: RefCell<Option<Mirror>>,
    /// What Tempo held at the last anchor read, which steps of one zone block share.
    tempo: RefCell<Option<(u64, Option<Tempo>)>>,
}

impl AccountChecks {
    /// Checks watching the zone's system contracts, then `watched`, then the accounts `l1` holds a
    /// commitment for, up to [`MAX_WATCHED`] in all.
    pub(crate) fn new(l1: &L1, watched: Vec<Address>) -> Self {
        let committed: Vec<Address> = match l1 {
            L1::State { commitments, .. } => commitments
                .iter()
                .filter(|(_, commitment)| !commitment.is_zero())
                .map(|(address, _)| *address)
                .collect(),
            L1::Chain(chain) => chain
                .anchors
                .iter()
                .flat_map(|anchor| {
                    anchor.accounts().filter_map(|(address, info)| {
                        let commitment = tempo_precompiles::storage::account_config_commitment(
                            info,
                            anchor.spec(),
                        )
                        .ok()?;
                        (!commitment.is_zero()).then_some(*address)
                    })
                })
                .collect(),
        };
        let mut accounts = vec![
            TEMPO_STATE_ADDRESS,
            ZONE_INBOX_ADDRESS,
            ZONE_OUTBOX_ADDRESS,
            ZONE_FEE_MANAGER_ADDRESS,
        ];
        accounts.extend(watched);
        accounts.extend(committed);
        let mut seen = std::collections::HashSet::new();
        accounts.retain(|account| seen.insert(*account));
        accounts.truncate(MAX_WATCHED);
        Self {
            watched: accounts,
            pre: RefCell::default(),
            tempo: RefCell::default(),
        }
    }

    /// Checks what the zone shows after the step `state` ends, reading Tempo from `l1`.
    pub(crate) fn check<C: EvmConfig>(
        &self,
        l1: &L1,
        state: &StepState<'_, C>,
        report: &mut Report,
    ) {
        let pre = self.pre.take();
        let Some(zone) = self.zone(state, report) else {
            return;
        };
        let anchor = zone.anchor().number;
        let tempo = {
            let mut cached = self.tempo.borrow_mut();
            match &*cached {
                Some((block, tempo)) if *block == anchor => tempo.clone(),
                _ => {
                    let tempo = self.tempo(l1, anchor, report);
                    *cached = Some((anchor, tempo.clone()));
                    tempo
                }
            }
        };
        let post = Mirror::new(zone, tempo).expect("Tempo is read at the zone's anchor");
        report.run_any(all(), &post);

        // The sequencer's own transactions act for no account.
        let tx = state
            .tx()
            .filter(|tx| tx.sender != TEMPO_SYSTEM_TX_SENDER)
            .cloned();
        let mut accounts: Vec<Address> = state
            .changed()
            .chain(
                tx.iter()
                    .flat_map(|tx| iter::once(tx.sender).chain(tx.authority.accounts())),
            )
            .collect();
        accounts.sort_unstable();
        accounts.dedup();
        if let Some(pre) = pre {
            let step = ZoneStep {
                pre,
                post: post.clone(),
                changes: Vec::new(),
                logs: state.logs().to_vec(),
                tx,
            };
            report.run_any(all(), &step);
        }
        report.run_any(all(), &self.leaves(l1, state, &accounts, anchor));
        *self.pre.borrow_mut() = Some(post);
    }

    /// What the zone shows of the watched accounts after the step, from T14.
    fn zone<C: EvmConfig>(
        &self,
        state: &StepState<'_, C>,
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
        tempo_fuzz_engine::observed(report, VIEW, "the zone", ZoneModel::observe(&mut views, at))
    }

    /// What Tempo holds for the watched accounts at block `number`, when `l1` is a chain the harness
    /// executed; a fixed L1 state holds no accounts.
    fn tempo(&self, l1: &L1, number: u64, report: &mut Report) -> Option<Tempo> {
        let L1::Chain(chain) = l1 else {
            return None;
        };
        let anchor = usize::try_from(number)
            .ok()
            .and_then(|number| chain.anchors.get(number))?;
        let at = TempoAt {
            block: number,
            precompile: CONFIGURABLE_ACCOUNT_ADDRESS,
            accounts: &self.watched,
        };
        let subject = format!("Tempo at block {number}");
        anchor.observe::<Tempo>(&chain.evm_config, report, VIEW, subject, at)
    }

    /// The TIP-1108 leaves of `accounts`: what the zone stores, what it serves through Tempo's
    /// overlay at `anchor`, and what Tempo commits to there.
    fn leaves<C: EvmConfig>(
        &self,
        l1: &L1,
        state: &StepState<'_, C>,
        accounts: &[Address],
        anchor: u64,
    ) -> ZoneLeaves {
        use evm2::evm::DynDatabase as _;
        let spec = state.env().spec;
        let portal = decode_zone_chain_id(state.env().version.chain_id)
            .map(|(_, zone_id)| tempo_precompiles::zone_factory::portal_address(zone_id))
            .unwrap_or_default();
        let mut overlay = L1OverlayDB::new(
            evm2::evm::Db::new(state.database()),
            l1.clone(),
            portal,
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

/// Read-only calls against zone state, each run as a simulated zone transaction from the zero
/// address without fees: Tempo's overlay applies only inside a zone transaction.
struct ZoneViews<'a> {
    evm: TempoEvm<'a>,
    chain_id: u64,
}

impl<'a> ZoneViews<'a> {
    /// Views of the state after `state`'s step, in the zone block environment `env`.
    fn new<C: EvmConfig>(state: &'a StepState<'_, C>, mut env: TempoEvmEnv) -> Self {
        for feature in [
            EvmFeatures::FEE_CHARGE,
            EvmFeatures::BALANCE_CHECK,
            EvmFeatures::BALANCE_TOP_UP,
            EvmFeatures::NONCE_CHECK,
            EvmFeatures::BLOCK_GAS_LIMIT_CHECK,
        ] {
            env.version.features.remove(feature);
        }
        let chain_id = env.version.chain_id;
        Self {
            evm: reth_evm::ConfigureEvm::evm_with_env(state.evm_config(), state.database(), env),
            chain_id,
        }
    }
}

impl Views for ZoneViews<'_> {
    type Error = ViewFailed;

    fn call(&mut self, calls: &[(Address, Bytes)]) -> Result<Vec<Option<Bytes>>, ViewFailed> {
        calls
            .iter()
            .map(|(target, input)| {
                let tx = TempoTransaction {
                    chain_id: self.chain_id,
                    fee_token: Some(PATH_USD_ADDRESS),
                    gas_limit: VIEW_GAS_LIMIT,
                    calls: vec![tempo_primitives::transaction::Call {
                        to: TxKind::Call(*target),
                        value: U256::ZERO,
                        input: input.clone(),
                    }],
                    ..Default::default()
                };
                let signature = TempoSignature::from(Signature::test_signature());
                let envelope = TempoTxEnvelope::AA(tx.into_signed(signature));
                let tx = Recovered::new_unchecked(envelope, Address::ZERO);
                let failed = |reason| ViewFailed {
                    selector: input
                        .get(..4)
                        .map(Bytes::copy_from_slice)
                        .unwrap_or_default(),
                    target: *target,
                    reason,
                };
                match self
                    .evm
                    .call_tx(&Recovered::new_unchecked(tx.into(), Address::ZERO))
                {
                    Err(err) => Err(failed(err.to_string())),
                    Ok(result) if !result.status => {
                        Err(failed(format!("reverted with {}", result.output)))
                    }
                    Ok(result) => Ok(Some(result.output)),
                }
            })
            .collect()
    }
}

/// A zone view call that reverted, halted or could not run.
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
