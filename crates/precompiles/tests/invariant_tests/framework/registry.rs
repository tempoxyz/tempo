use super::{context::InvariantContext, result::InvariantResult};

pub(crate) struct Invariant {
    pub(crate) name: &'static str,
    #[allow(dead_code)]
    pub(crate) description: &'static str,
    pub(crate) check: fn(&InvariantContext<'_>) -> eyre::Result<InvariantResult>,
}

pub(crate) fn all_invariants() -> Vec<Invariant> {
    use crate::invariant_tests::invariants::*;

    vec![
        Invariant {
            name: "linked_list_integrity",
            description: "Doubly-linked list pointers consistent at every tick level",
            check: linked_list::check_linked_list,
        },
    ]
}
