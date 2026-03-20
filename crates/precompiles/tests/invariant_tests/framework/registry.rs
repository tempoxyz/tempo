use super::{context::InvariantContext, result::InvariantResult};

pub(crate) struct Invariant {
    pub(crate) name: &'static str,
    #[allow(dead_code)]
    pub(crate) description: &'static str,
    pub(crate) check: fn(&InvariantContext<'_>) -> eyre::Result<InvariantResult>,
}

pub(crate) fn all_invariants() -> Vec<Invariant> {
    vec![]
}
