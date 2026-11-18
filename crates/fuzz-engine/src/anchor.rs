//! Tempo blocks with the state each left, which a chain built on Tempo, such as a zone, reads Tempo
//! at.

use std::fmt::Display;

use alloy_primitives::{Address, B256, U256};
use evm2::evm::{AccountInfo, Cache};
use invariants_core::{Observe, Report};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_fuzz_types::PreState;
use tempo_primitives::TempoHeader;

use crate::{
    engine::EvmConfig,
    invariants::{self, ViewCache},
    state,
};

/// A Tempo block the harness executed, with the state after it: the genesis header with the
/// pre-state, then each block that applied.
#[derive(Debug, Clone)]
pub struct Anchor {
    header: TempoHeader,
    spec: TempoHardfork,
    state: Cache,
}

impl Anchor {
    pub(crate) const fn new(header: TempoHeader, spec: TempoHardfork, state: Cache) -> Self {
        Self {
            header,
            spec,
            state,
        }
    }

    /// The block's header.
    pub const fn header(&self) -> &TempoHeader {
        &self.header
    }

    /// The hardfork active at the block.
    pub const fn spec(&self) -> TempoHardfork {
        self.spec
    }

    /// The account at `address` after the block; `None` if it does not exist.
    pub fn account(&self, address: &Address) -> Option<&AccountInfo> {
        self.state.accounts.get(address).and_then(Option::as_ref)
    }

    /// The accounts the state after the block holds.
    pub fn accounts(&self) -> impl Iterator<Item = (&Address, &AccountInfo)> {
        self.state
            .accounts
            .iter()
            .filter_map(|(address, info)| Some((address, info.as_ref()?)))
    }

    /// The value of `slot` of `account` after the block. The state started from genesis, so a
    /// slot it does not hold is zero.
    pub fn storage(&self, account: &Address, slot: B256) -> B256 {
        self.state
            .storage
            .get(account)
            .and_then(|storage| storage.slots.get(&U256::from_be_bytes(slot.0)))
            .copied()
            .unwrap_or_default()
            .into()
    }

    /// Reads the model `at` names from the state after the block with view calls on
    /// `evm_config`, counting the read under `view` as [`invariants::observed`] does.
    pub fn observe<M: Observe>(
        &self,
        evm_config: &impl EvmConfig,
        report: &mut Report,
        view: &'static str,
        subject: impl Display,
        at: M::At<'_>,
    ) -> Option<M> {
        let env = evm_config
            .evm_env(&self.header)
            .expect("a header the harness built has an environment");
        let db = state::seed(&PreState::Genesis(Default::default()), &self.state)
            .expect("an empty pre-state seeds");
        let view_cache = ViewCache::default();
        let mut views =
            invariants::EvmViews::new(db.view(), evm_config, env, &db.pre, &view_cache, false);
        invariants::observed(report, view, subject, M::observe(&mut views, at))
    }
}
