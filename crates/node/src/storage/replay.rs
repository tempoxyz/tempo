use alloy_primitives::{B256, U256};
use reth_chainspec::EthChainSpec;
use reth_db_api::{DatabaseError, tables, transaction::DbTx};
use reth_primitives_traits::AlloyBlockHeader;
use reth_provider::{HeaderProvider, TransactionsProvider, providers::StaticFileProviderBuilder};
use std::{collections::BTreeMap, path::Path};
use tempo_chainspec::{TempoChainSpec, TempoHardforks};
use tempo_precompiles::{EXPIRING_NONCE_PRECOMPILE_ADDRESS, expiring_nonce::ExpiringNonceManager};
use tempo_primitives::TempoPrimitives;

fn error(err: impl std::fmt::Display) -> DatabaseError {
    DatabaseError::Other(format!("derived replay storage: {err}"))
}

fn set(slots: &mut BTreeMap<B256, U256>, key: U256, value: U256) {
    let key = B256::from(key);
    if value.is_zero() {
        slots.remove(&key);
    } else {
        slots.insert(key, value);
    }
}
fn get(slots: &BTreeMap<B256, U256>, key: U256) -> U256 {
    slots.get(&B256::from(key)).copied().unwrap_or_default()
}

pub(super) fn reconstruct(
    tx: &impl DbTx,
    chain: &TempoChainSpec,
    path: &Path,
) -> Result<BTreeMap<B256, U256>, DatabaseError> {
    let genesis = chain.genesis();
    let account = genesis.alloc.get(&EXPIRING_NONCE_PRECOMPILE_ADDRESS);
    let mut slots: BTreeMap<_, _> = account
        .and_then(|a| a.storage.as_ref())
        .into_iter()
        .flatten()
        .filter(|(_, v)| **v != B256::ZERO)
        .map(|(k, v)| (*k, U256::from_be_slice(v.as_slice())))
        .collect();
    let Some(finish) = tx.get::<tables::StageCheckpoints>("Finish".to_owned())? else {
        return Ok(slots);
    };
    let genesis_number = chain.genesis_header().number();
    if finish.block_number <= genesis_number {
        return Ok(slots);
    }
    // Opening after the MDBX transaction pins the required files against reorg truncation.
    // A fresh view also avoids stale static-file indexes after persistence.
    let source = StaticFileProviderBuilder::read_only(path)
        .with_genesis_block_number(genesis_number)
        .build::<TempoPrimitives>()
        .map_err(error)?;
    let manager = ExpiringNonceManager::new();
    let mut deployed = account
        .and_then(|a| a.code.as_ref())
        .is_some_and(|code| !code.is_empty());
    for number in genesis_number + 1..=finish.block_number {
        let header = source
            .header_by_number(number)
            .map_err(error)?
            .ok_or_else(|| error(format!("missing header {number}")))?;
        if !deployed {
            set(
                &mut slots,
                manager.oldest_unpruned_block.slot(),
                U256::from(number),
            );
            deployed = true;
        }
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
            append(&mut slots, number, hash, expiry.get())?;
        }
        prune(&mut slots, number, header.timestamp())?;
    }
    Ok(slots)
}

fn append(
    slots: &mut BTreeMap<B256, U256>,
    number: u64,
    hash: B256,
    expiry: u64,
) -> Result<(), DatabaseError> {
    let manager = ExpiringNonceManager::new();
    let count: u64 = get(slots, manager.bucket_count[number].slot())
        .try_into()
        .map_err(error)?;
    let next = count
        .checked_add(1)
        .ok_or_else(|| error("bucket overflow"))?;
    set(slots, manager.seen[hash].slot(), U256::from(expiry));
    set(
        slots,
        manager.bucket[number][count].slot(),
        U256::from_be_slice(hash.as_slice()),
    );
    set(slots, manager.bucket_count[number].slot(), U256::from(next));
    let maximum = get(slots, manager.bucket_max_expiry[number].slot()).max(U256::from(expiry));
    set(slots, manager.bucket_max_expiry[number].slot(), maximum);
    Ok(())
}

fn prune(
    slots: &mut BTreeMap<B256, U256>,
    number: u64,
    timestamp: u64,
) -> Result<(), DatabaseError> {
    let manager = ExpiringNonceManager::new();
    let mut oldest: u64 = get(slots, manager.oldest_unpruned_block.slot())
        .try_into()
        .map_err(error)?;
    while oldest < number {
        if get(slots, manager.bucket_max_expiry[oldest].slot()) > U256::from(timestamp) {
            break;
        }
        let count: u64 = get(slots, manager.bucket_count[oldest].slot())
            .try_into()
            .map_err(error)?;
        for i in 0..count {
            let hash = B256::from(get(slots, manager.bucket[oldest][i].slot()));
            set(slots, manager.seen[hash].slot(), U256::ZERO);
            set(slots, manager.bucket[oldest][i].slot(), U256::ZERO);
        }
        if count != 0 {
            set(slots, manager.bucket_count[oldest].slot(), U256::ZERO);
            set(slots, manager.bucket_max_expiry[oldest].slot(), U256::ZERO);
        }
        oldest += 1;
    }
    set(
        slots,
        manager.oldest_unpruned_block.slot(),
        U256::from(oldest),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempo_chainspec::TempoHardfork;
    use tempo_precompiles::storage::{
        Handler, PrecompileStorageProvider, StorageCtx, hashmap::HashMapStorageProvider,
    };

    #[test]
    fn reconstruction_matches_precompile_through_pruning() {
        let mut actual = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        actual.set_tip1060_storage_credits(false);
        let mut derived = BTreeMap::new();
        let mut touched = std::collections::BTreeSet::new();
        let blocks = [
            (
                1,
                1000,
                vec![
                    (B256::with_last_byte(1), 1100),
                    (B256::with_last_byte(2), 1300),
                ],
            ),
            (2, 1001, vec![]),
            (3, 1002, vec![(B256::with_last_byte(3), 1200)]),
            (4, 1200, vec![]),
            (5, 1300, vec![(B256::with_last_byte(4), 1301)]),
            (6, 1301, vec![]),
        ];
        for (number, timestamp, entries) in blocks {
            actual.set_block_number(number);
            actual.set_timestamp(U256::from(timestamp));
            StorageCtx::enter(&mut actual, || {
                let mut manager = ExpiringNonceManager::new();
                if number == 1 {
                    manager.oldest_unpruned_block.write(number).unwrap();
                    set(
                        &mut derived,
                        manager.oldest_unpruned_block.slot(),
                        U256::from(number),
                    );
                }
                for (hash, expiry) in entries {
                    manager.check_and_mark_expiring_nonce(hash, expiry).unwrap();
                    append(&mut derived, number, hash, expiry).unwrap();
                }
                touched.extend(derived.keys().copied());
                manager.prune().unwrap();
                prune(&mut derived, number, timestamp).unwrap();
            });
            for slot in &touched {
                assert_eq!(
                    actual
                        .sload(
                            EXPIRING_NONCE_PRECOMPILE_ADDRESS,
                            U256::from_be_slice(slot.as_slice())
                        )
                        .unwrap(),
                    derived.get(slot).copied().unwrap_or_default(),
                    "block {number}, slot {slot}"
                );
            }
        }
        let actual: BTreeMap<_, _> = actual
            .into_storage()
            .filter(|(_, _, v)| !v.is_zero())
            .map(|(address, k, v)| {
                assert_eq!(address, EXPIRING_NONCE_PRECOMPILE_ADDRESS);
                (B256::from(k), v)
            })
            .collect();
        assert_eq!(actual, derived);
    }
}
