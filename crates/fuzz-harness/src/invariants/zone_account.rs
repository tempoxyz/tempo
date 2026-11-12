//! Zone configurable account checks (TIP-1154): what the zone shows of the watched accounts
//! beside what Tempo holds for them at the zone's anchor.

use std::iter;

use alloy_primitives::{Address, KECCAK256_EMPTY, Log, U256};
use evm2::evm::{Database as _, DynDatabase as _};
use invariants_core::{Observe as _, Report};
use reth_evm::ConfigureEvm as _;
use tempo_contracts::{
    precompiles::{CONFIGURABLE_ACCOUNT_ADDRESS, SIGNATURE_VERIFIER_ADDRESS},
    zones::TEMPO_STATE_ADDRESS,
};
use tempo_evm::{TempoEvmConfig, TempoEvmEnv};
use tempo_invariants::{
    Tx, all,
    zone_account::{Mirror, Tempo, TempoAt, VIEW, Zone, ZoneLeaf, ZoneLeaves, ZoneStep},
};
use zone_evm::{L1OverlayDB, ZoneEvmConfig};
use zone_precompiles::L1StorageReader as _;

use super::{
    configurable_account::{account_at, leaf},
    reader::observed,
    views::{EvmViews, ViewCache, ZoneViews},
};
use crate::{
    state::{Db, Net},
    zone::AnchorReader,
};

/// What the zone invariants read after a zone step.
pub(crate) struct ZoneContext<'a> {
    /// The zone state after the step.
    pub(crate) db: &'a Db,
    /// The zone's EVM configuration, which the zone views run with.
    pub(crate) config: &'a ZoneEvmConfig<AnchorReader>,
    /// Tempo's EVM configuration, which the views of Tempo at an anchor run with.
    pub(crate) tempo_config: &'a TempoEvmConfig,
    /// Tempo's state at each anchor.
    pub(crate) reader: &'a AnchorReader,
    /// The zone block's environment.
    pub(crate) env: TempoEvmEnv,
    /// The accounts whose commitments and marker the zone and Tempo are read for.
    pub(crate) watched: &'a [Address],
}

/// The zone as the invariants last read it, beside Tempo at its anchor.
#[derive(Default)]
pub(crate) struct ZoneMirror {
    /// The mirror after the last step; `None` before the first, or when it was not read.
    pre: Option<Mirror>,
    /// Tempo at the anchor read last, by its number; `None` inside when it was not read.
    tempo: Option<(u64, Option<Tempo>)>,
}

impl ZoneMirror {
    /// Reads the zone before its first block, which has no Tempo beside it, counting the read in
    /// `report`.
    pub(crate) fn start(&mut self, ctx: &ZoneContext<'_>, report: &mut Report) {
        self.pre = ctx
            .zone(report)
            .map(|zone| Mirror::new(zone, None).expect("only Tempo can be misanchored"));
    }

    /// Checks the zone after a step that made `net`'s changes and logged `logs`, with its user
    /// transaction `tx`, `None` for a block's opening system transaction: the mirror after it,
    /// the step from the last mirror, and the zone leaves of the accounts it changed or signed for.
    pub(crate) fn check(
        &mut self,
        ctx: &ZoneContext<'_>,
        net: &Net,
        tx: Option<Tx>,
        logs: &[Log],
        report: &mut Report,
    ) {
        let pre = self.pre.take();
        let Some(zone) = ctx.zone(report) else {
            return;
        };
        let anchor = zone.anchor().number;
        let tempo = match &self.tempo {
            Some((block, tempo)) if *block == anchor => tempo.clone(),
            _ => {
                let tempo = ctx.tempo(anchor, report);
                self.tempo = Some((anchor, tempo.clone()));
                tempo
            }
        };
        let post = Mirror::new(zone, tempo).expect("Tempo is read at the zone's anchor");
        report.run_any(all(), &post);

        let mut accounts: Vec<Address> = net
            .addresses()
            .copied()
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
                logs: logs.to_vec(),
                tx,
            };
            report.run_any(all(), &step);
        }
        report.run_any(all(), &ctx.leaves(&accounts, anchor));
        self.pre = Some(post);
    }
}

impl ZoneContext<'_> {
    /// The zone's view of the watched accounts, counting the read under [`VIEW`]. `None` before
    /// T14, where zones have no configurable accounts to read.
    fn zone(&self, report: &mut Report) -> Option<Zone> {
        if !self.env.spec.is_t14() {
            return None;
        }
        let coded: Vec<Address> = self
            .watched
            .iter()
            .copied()
            .filter(|address| {
                matches!(
                    self.db.view().get_account(address),
                    Ok(Some(info)) if info.code_hash != KECCAK256_EMPTY
                )
            })
            .collect();
        let mut views = ZoneViews::new(self.db.view(), self.config, self.env.clone());
        let at = tempo_invariants::zone_account::ZoneAt {
            tempo_state: TEMPO_STATE_ADDRESS,
            precompile: CONFIGURABLE_ACCOUNT_ADDRESS,
            verifier: SIGNATURE_VERIFIER_ADDRESS,
            accounts: self.watched,
            coded: &coded,
            // Not probed: a probe needs a signature over a hash the harness picks, and the input
            // carries only signatures over its transactions.
            probes: &[],
        };
        observed(report, VIEW, "the zone", Zone::observe(&mut views, at))
    }

    /// Tempo's commitments of the watched accounts at block `number`, counting the read under
    /// [`VIEW`]; `None` when the harness holds no such block or the read failed.
    fn tempo(&self, number: u64, report: &mut Report) -> Option<Tempo> {
        let anchor = self.reader.get(number)?;
        if !anchor.spec().is_t14() {
            return Some(Tempo::unregistered(
                number,
                Some(anchor.hash()),
                self.watched,
            ));
        }
        let db = anchor.db();
        let env = self
            .tempo_config
            .evm_env(anchor.header())
            .expect("a Tempo header the harness built has an environment");
        let view_cache = ViewCache::default();
        let mut views = EvmViews::new(
            db.view(),
            self.tempo_config,
            env,
            &db.pre,
            &view_cache,
            false,
        );
        let at = TempoAt {
            block: number,
            hash: Some(anchor.hash()),
            precompile: CONFIGURABLE_ACCOUNT_ADDRESS,
            accounts: self.watched,
        };
        let subject = format!("Tempo at block {number}");
        observed(report, VIEW, subject, Tempo::observe(&mut views, at))
    }

    /// The zone leaves of `accounts` after the step: stored in zone state, served by an account
    /// load inside a zone transaction at `anchor`, and Tempo's commitment at `anchor`.
    fn leaves(&self, accounts: &[Address], anchor: u64) -> ZoneLeaves {
        let spec = self.env.spec;
        let of = accounts
            .iter()
            .filter_map(|&address| {
                let stored = leaf(account_at(self.db, None, address)?, spec)?;
                let view = evm2::evm::Db::new(self.db.view());
                let mut overlay = L1OverlayDB::new(view, self.reader.clone(), Address::ZERO, spec);
                overlay.l1_state().begin_transaction(U256::from(anchor));
                let served = match overlay.get_account(&address) {
                    Ok(info) => Some(info.map_or(KECCAK256_EMPTY, |info| info.code_hash)),
                    Err(_) => None,
                };
                // An unread commitment leaves the checks on Tempo's side unarmed.
                let tempo = self.reader.read_l1_commitment(address, anchor).ok();
                Some((
                    address,
                    ZoneLeaf {
                        stored,
                        served,
                        tempo,
                    },
                ))
            })
            .collect();
        ZoneLeaves {
            active: spec.is_t14(),
            of,
        }
    }
}
