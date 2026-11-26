//! Which models a step could have changed, read and checked through a runner's [`Reader`].

use alloy_primitives::{Address, Log};
use invariants_core::{Effects, Probe};

use crate::{Checked, Observe, Ran, StepChecked, TempoHardfork, Views, dex, fee_amm, tip20};

/// What a runner checks: the accounts its state holds, and the step that led to it.
pub struct Scope<'a> {
    /// The TIP-20 tokens the state holds, sorted.
    pub tokens: &'a [Address],
    /// The accounts whose balances to read, sorted.
    pub holders: &'a [Address],
    /// The block's fee recipient.
    pub beneficiary: Address,
    /// What the step did, `None` for a state checked on its own.
    pub effects: Option<&'a Effects<Ran>>,
    /// Whether to check the contract at an address.
    pub selected: &'a dyn Fn(&Address) -> bool,
}

impl Scope<'_> {
    /// The step's logs, none for a state checked on its own.
    pub fn logs(&self) -> &[Log] {
        self.effects.map_or(&[], |effects| &effects.logs)
    }
}

/// Reads models from a runner's state and checks them.
pub trait Reader {
    /// The views reads go through.
    type Views: Views;

    /// Views of the state after the step, for reads that choose which models to check.
    fn after(&mut self) -> &mut Self::Views;

    /// Reads the model `at` names at `contract` after the step and, with a step, before it, and
    /// runs its checks and step checks. A read that fails breaks `view`.
    fn check<M>(&mut self, at: M::At<'_>, contract: Address, view: &'static str)
    where
        M: Observe + Checked<TempoHardfork> + StepChecked<Ran, TempoHardfork>;

    /// Probes the model `at` names at `contract` on a throwaway copy of the state after the step,
    /// and runs its checks. A probe that fails breaks `view`.
    fn probe<M>(&mut self, at: M::At<'_>, contract: Address, view: &'static str)
    where
        M: Probe + Checked<TempoHardfork>;
}

/// Reads and checks every model the step could have changed.
pub fn check<R: Reader>(reader: &mut R, scope: &Scope<'_>) {
    tip20::check(reader, scope);
    fee_amm::check(reader, scope);
    dex::check(reader, scope);
}

/// The addresses in the topics of `logs`, such as the holders a `Transfer` names.
pub fn logged_addresses<'a>(
    logs: impl IntoIterator<Item = &'a Log>,
) -> impl Iterator<Item = Address> {
    logs.into_iter()
        .flat_map(|log| log.topics())
        .filter(|topic| topic[..12] == [0; 12])
        .map(|topic| Address::from_word(*topic))
}
