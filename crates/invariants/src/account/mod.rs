//! Configurable accounts (TIP-1107..1114): the configuration commitment each account holds, read
//! through the configurable account precompile.

use std::collections::BTreeMap;

use alloy_primitives::{Address, B256};

use crate::{Observe, ObserveError, Views, optional, view_many};

pub use tempo_contracts::precompiles::IConfigurableAccount::{
    self, AccountUpgraded, ConfigurableAccountConfigUpdated,
};

mod checks;

pub use checks::{COMMITMENT_BY_SELF, COMMITMENT_EVENT, COMMITMENT_KEPT, STEP_CHECKS, VIEW};

/// The configuration commitments of the observed accounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitments {
    /// The precompile read.
    pub precompile: Address,
    /// Each observed account's commitment, zero for an account without a configuration.
    pub of: BTreeMap<Address, B256>,
}

impl Observe for Commitments {
    type At<'a> = At<'a>;

    /// Reads each account's commitment. Over partial views, an account nothing answers for is
    /// left out.
    fn observe<V: Views>(views: &mut V, at: At<'_>) -> Result<Self, ObserveError<V::Error>> {
        let At {
            precompile,
            accounts,
        } = at;
        let calls: Vec<_> = accounts
            .iter()
            .map(|&account| {
                (
                    precompile,
                    IConfigurableAccount::getConfigCommitmentCall { account },
                )
            })
            .collect();
        let read = view_many(views, &calls)?;
        let mut of = BTreeMap::new();
        for (&account, commitment) in accounts.iter().zip(read) {
            let commitment = commitment.map(Ok).unwrap_or(Err(ObserveError::NotAnswered {
                call: "getConfigCommitment(address)",
                to: precompile,
            }));
            if let Some(commitment) = optional(views, commitment)? {
                of.insert(account, commitment);
            }
        }
        Ok(Self { precompile, of })
    }
}

/// The precompile and the accounts whose commitments to read.
#[derive(Debug, Clone, Copy)]
pub struct At<'a> {
    pub precompile: Address,
    pub accounts: &'a [Address],
}
