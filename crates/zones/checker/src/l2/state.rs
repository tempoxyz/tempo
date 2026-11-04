//! Exact L2 state reads used by bootstrap and accounting verification.

use std::collections::{BTreeMap, BTreeSet};

use alloy_eips::BlockNumHash;
use alloy_primitives::{Address, B256, U256};
use reth_storage_api::{StateProviderFactory, errors::provider::ProviderError};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::TempoStateAccess as _;
use tempo_precompiles::{
    error::TempoPrecompileError,
    storage::{ContractStorage, StorageActions},
    tip20::{ITIP20, TIP20Token},
};
use zone_precompiles::zone_state::ZoneStateSnapshot;

use crate::AttemptError;

/// Protocol checkpoint embedded in local Zone genesis.
pub(crate) struct ZoneGenesisEvidence {
    pub(crate) tempo_block_hash: B256,
    pub(crate) tempo_block_number: u64,
    pub(crate) processed_deposit_queue_hash: B256,
    pub(crate) processed_deposit_number: u64,
    pub(crate) withdrawal_queue_hash: B256,
    pub(crate) withdrawal_batch_index: u64,
    pub(crate) default_fee_token: Address,
    pub(crate) initial_token_supply: U256,
}

/// Read the protocol checkpoint encoded in exact Zone state.
pub(crate) fn read_zone_genesis<P>(
    provider: &P,
    hash: B256,
    spec: TempoHardfork,
) -> eyre::Result<ZoneGenesisEvidence>
where
    P: StateProviderFactory + ?Sized,
{
    let mut state = provider.state_by_block_hash(hash)?;
    state.with_read_only_storage_ctx(spec, StorageActions::disabled(), || {
        let snapshot = ZoneStateSnapshot::read()?;
        let initial_token_supply =
            TIP20Token::from_address(snapshot.default_fee_token)?.total_supply()?;
        Ok(ZoneGenesisEvidence {
            tempo_block_hash: snapshot.tempo_block_hash,
            tempo_block_number: snapshot.tempo_block_number,
            processed_deposit_queue_hash: snapshot.processed_deposit_queue_hash,
            processed_deposit_number: snapshot.processed_deposit_number,
            withdrawal_queue_hash: snapshot.last_withdrawal_batch.withdrawalQueueHash,
            withdrawal_batch_index: snapshot.last_withdrawal_batch.withdrawalBatchIndex,
            default_fee_token: snapshot.default_fee_token,
            initial_token_supply,
        })
    })
}

/// Exact balances and supply for one token at one Zone block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TokenAccountingEvidence {
    pub(crate) token: Address,
    pub(crate) total_supply: U256,
    pub(crate) balances: BTreeMap<Address, U256>,
}

/// Failure reading exact accounting state for one Zone block.
#[derive(Debug)]
pub(crate) enum AccountingStateError {
    /// The requested block state is not currently available.
    Unavailable(eyre::Report),
    /// Deterministic provider or checker failure prevents verification.
    Disable(eyre::Report),
}

impl From<AttemptError> for AccountingStateError {
    fn from(error: AttemptError) -> Self {
        match error {
            AttemptError::Retry(error) => Self::Unavailable(error),
            AttemptError::Disable(error) => Self::Disable(error),
        }
    }
}

/// Read exact balances and supply for affected accounts at one Zone block.
pub(crate) fn read_accounting_state<P: StateProviderFactory>(
    provider: &P,
    accounts: &BTreeMap<Address, BTreeSet<Address>>,
    block: BlockNumHash,
    spec: TempoHardfork,
) -> Result<Vec<TokenAccountingEvidence>, AccountingStateError> {
    let canonical_hash = provider
        .block_hash(block.number)
        .map_err(|error| classify_provider_error(error, block.hash))?;
    match canonical_hash {
        Some(hash) if hash == block.hash => {}
        Some(_) => {
            return Err(AccountingStateError::Disable(eyre::eyre!(
                "Zone block {} ({}) is not canonical",
                block.number,
                block.hash
            )));
        }
        None => {
            return Err(AccountingStateError::Unavailable(eyre::eyre!(
                "Zone block {} ({}) is not yet available in local canonical history",
                block.number,
                block.hash
            )));
        }
    }
    let mut state = provider
        .history_by_block_number(block.number)
        .map_err(|error| classify_provider_error(error, block.hash))?;
    state
        .with_read_only_storage_ctx(spec, StorageActions::disabled(), || {
            accounts
                .iter()
                .map(|(&token, accounts)| {
                    let token = TIP20Token::from_address(token)?;
                    let balances = accounts
                        .iter()
                        .map(|&account| {
                            token
                                .balance_of(ITIP20::balanceOfCall { account })
                                .map(|balance| (account, balance))
                        })
                        .collect::<tempo_precompiles::Result<BTreeMap<_, _>>>()?;
                    Ok(TokenAccountingEvidence {
                        token: token.address(),
                        total_supply: token.total_supply()?,
                        balances,
                    })
                })
                .collect::<tempo_precompiles::Result<Vec<_>>>()
        })
        .map_err(|error| classify_read_error(error, block.hash))
}

fn classify_read_error(error: TempoPrecompileError, block: B256) -> AccountingStateError {
    // Storage reads surface provider failures as `Fatal` or `Database`, including a block being
    // persisted and evicted from the in-memory overlay while it is being read; re-open state
    // and retry.
    let fatal = matches!(
        error,
        TempoPrecompileError::Fatal(_) | TempoPrecompileError::Database(_)
    );
    let report = eyre::Report::new(error)
        .wrap_err(format!("failed to read accounting state for block {block}"));
    if fatal {
        AccountingStateError::Unavailable(report)
    } else {
        AccountingStateError::Disable(report)
    }
}

fn classify_provider_error(error: ProviderError, block: B256) -> AttemptError {
    let report = |error| {
        eyre::Report::new(error).wrap_err(format!("failed to obtain state for block {block}"))
    };
    match error {
        error @ (ProviderError::BlockHashNotFound(_)
        | ProviderError::HeaderNotFound(_)
        | ProviderError::UnknownBlockHash(_)
        | ProviderError::StateForHashNotFound(_)
        | ProviderError::StateForNumberNotFound(_)
        | ProviderError::BlockNotExecuted { .. }) => AttemptError::retry(report(error)),
        error @ ProviderError::StateAtBlockPruned(_) => AttemptError::disable(
            report(error).wrap_err("checker requires unpruned historical Zone state"),
        ),
        error => AttemptError::disable(report(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use evm2::DatabaseError;

    #[test]
    fn classifies_transient_and_permanent_provider_failures() {
        let block = B256::repeat_byte(1);
        assert!(matches!(
            classify_provider_error(ProviderError::StateForHashNotFound(block), block),
            AttemptError::Retry(_)
        ));

        assert!(matches!(
            classify_provider_error(ProviderError::StateAtBlockPruned(1), block),
            AttemptError::Disable(_)
        ));
    }

    #[test]
    fn retries_fatal_storage_reads_and_disables_other_read_failures() {
        let block = B256::repeat_byte(1);
        assert!(matches!(
            classify_read_error(TempoPrecompileError::Fatal("db".into()), block),
            AccountingStateError::Unavailable(_)
        ));
        assert!(matches!(
            classify_read_error(
                TempoPrecompileError::Database(DatabaseError::new(
                    std::io::Error::other("db"),
                    true
                )),
                block
            ),
            AccountingStateError::Unavailable(_)
        ));

        assert!(matches!(
            classify_read_error(TempoPrecompileError::OutOfGas, block),
            AccountingStateError::Disable(_)
        ));
    }
}
