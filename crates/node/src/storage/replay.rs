use alloy_primitives::{B256, U256};
use reth_chainspec::EthChainSpec;
use reth_db_api::{DatabaseError, tables, transaction::DbTx};
use reth_primitives_traits::AlloyBlockHeader;
use reth_provider::{HeaderProvider, TransactionsProvider, providers::StaticFileProviderBuilder};
use std::{collections::BTreeMap, path::Path};
use tempo_chainspec::{TempoChainSpec, TempoHardforks};
use tempo_precompiles::{
    EXPIRING_NONCE_PRECOMPILE_ADDRESS,
    expiring_nonce::ExpiringNonceManager,
    storage::{Handler, PrecompileStorageProvider, StorageCtx, hashmap::HashMapStorageProvider},
};
use tempo_primitives::TempoPrimitives;

fn error(err: impl std::fmt::Display) -> DatabaseError {
    DatabaseError::Other(format!("derived replay storage: {err}"))
}

pub(super) fn reconstruct(
    tx: &impl DbTx,
    chain: &TempoChainSpec,
    path: &Path,
) -> Result<BTreeMap<B256, U256>, DatabaseError> {
    let genesis = chain.genesis();
    let account = genesis.alloc.get(&EXPIRING_NONCE_PRECOMPILE_ADDRESS);
    let mut storage = HashMapStorageProvider::new_with_spec(
        chain.chain().id(),
        chain.tempo_hardfork_at(genesis.timestamp),
    );
    storage.set_tip1060_storage_credits(false);
    for (key, value) in account
        .and_then(|a| a.storage.as_ref())
        .into_iter()
        .flatten()
    {
        storage
            .sstore(
                EXPIRING_NONCE_PRECOMPILE_ADDRESS,
                U256::from_be_slice(key.as_slice()),
                U256::from_be_slice(value.as_slice()),
            )
            .map_err(error)?;
    }
    let slots = |storage: HashMapStorageProvider| {
        storage
            .into_storage()
            .filter(|(_, _, value)| !value.is_zero())
            .map(|(_, key, value)| (B256::from(key), value))
            .collect()
    };
    let Some(finish) = tx.get::<tables::StageCheckpoints>("Finish".to_owned())? else {
        return Ok(slots(storage));
    };
    let genesis_number = chain.genesis_header().number();
    if finish.block_number <= genesis_number {
        return Ok(slots(storage));
    }
    // Opening after the MDBX transaction pins the required files against reorg truncation.
    // A fresh view also avoids stale static-file indexes after persistence.
    let source = StaticFileProviderBuilder::read_only(path)
        .with_genesis_block_number(genesis_number)
        .build::<TempoPrimitives>()
        .map_err(error)?;
    let mut deployed = account
        .and_then(|a| a.code.as_ref())
        .is_some_and(|code| !code.is_empty());
    for number in genesis_number + 1..=finish.block_number {
        let header = source
            .header_by_number(number)
            .map_err(error)?
            .ok_or_else(|| error(format!("missing header {number}")))?;
        let spec = chain.tempo_hardfork_at(header.timestamp());
        let body = tx
            .get::<tables::BlockBodyIndices>(number)?
            .ok_or_else(|| error(format!("missing body indices {number}")))?;
        let transactions = source
            .transactions_by_tx_range(body.tx_num_range())
            .map_err(error)?;
        if transactions.len() as u64 != body.tx_count {
            return Err(error(format!("incomplete transactions for block {number}")));
        }
        storage.set_block_number(number);
        storage.set_timestamp(U256::from(header.timestamp()));
        storage.set_spec(spec);
        // Match execution: nonce bookkeeping does not use storage credits or tx gas.
        storage.set_tip1060_storage_credits(false);
        StorageCtx::enter(&mut storage, || {
            let mut manager = ExpiringNonceManager::new();
            if !deployed {
                manager.oldest_unpruned_block.write(number).map_err(error)?;
                deployed = true;
            }
            for transaction in transactions {
                let Some(signed) = transaction.as_aa() else {
                    continue;
                };
                if !spec.is_t1() || !signed.tx().is_expiring_nonce_tx() {
                    continue;
                }
                let hash = if spec.is_t1b() {
                    signed
                        .recover_signer_with_expiring_nonce_hash()
                        .map_err(error)?
                        .1
                        .ok_or_else(|| error("missing replay hash"))?
                } else {
                    *signed.hash()
                };
                let expiry = signed
                    .tx()
                    .valid_before
                    .ok_or_else(|| error("missing expiry"))?;
                manager
                    .check_and_mark_expiring_nonce(hash, expiry.get())
                    .map_err(error)?;
            }
            manager.prune().map_err(error)
        })?;
    }
    Ok(slots(storage))
}
