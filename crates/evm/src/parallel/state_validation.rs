//! Exact validation against the current authoritative revm State cache.

use super::{Address, DBErrorMarker, Database, ReadKey, ReadValue, SpeculativeResult, U256, read};
use reth_revm::{State, db::states::CacheAccount};
use tempo_revm::replay::{account_info_matches, bytecode_matches};

enum CachedRead {
    Equal,
    Different(ReadValue),
    Unknown,
}

impl<E: DBErrorMarker> SpeculativeResult<E> {
    /// Validates using borrowed, current cache values when available. BAL-backed
    /// state always uses Database reads, including indexed values and BAL errors.
    pub(crate) fn validate_state<P: Database>(&mut self, db: &mut State<P>) -> Result<bool, E>
    where
        State<P>: Database<Error = E>,
    {
        if db.has_bal() {
            return self.validate(db);
        }
        self.validate_with(|reads| first_difference(db, reads))
    }
}

/// Borrow an account once for consecutive warm reads. The borrow ends before
/// any cold read can populate or replace entries in the authoritative cache.
/// Nothing is retained across calls, commits or mutable access to State.
fn first_difference<P: Database>(
    db: &mut State<P>,
    reads: &[(ReadKey, ReadValue)],
) -> Result<Option<(usize, ReadValue)>, <State<P> as reth_revm::Database>::Error> {
    let mut offset = 0;
    'reads: while let Some((key, expected)) = reads.get(offset) {
        let cached = if let Some(address) = account_address(*key) {
            match db.cache.accounts.get(&address) {
                Some(account) => loop {
                    let (key, expected) = &reads[offset];
                    match cached_account_read(account, *key, expected) {
                        CachedRead::Equal => {
                            offset += 1;
                            if reads
                                .get(offset)
                                .is_some_and(|(key, _)| account_address(*key) == Some(address))
                            {
                                continue;
                            }
                            continue 'reads;
                        }
                        different_or_unknown => break different_or_unknown,
                    }
                },
                None => CachedRead::Unknown,
            }
        } else {
            cached_other_read(db, *key, expected)
        };
        match cached {
            CachedRead::Equal => {}
            CachedRead::Different(actual) => return Ok(Some((offset, actual))),
            CachedRead::Unknown => {
                // A warm run may have advanced to this cold or malformed read.
                let (key, expected) = &reads[offset];
                let actual = read(db, *key)?;
                if matches!((key, expected), (ReadKey::Account(_), ReadValue::Account(Some(info))) if info.account_id.is_some())
                    || actual != *expected
                {
                    return Ok(Some((offset, actual)));
                }
            }
        }
        offset += 1;
    }
    Ok(None)
}

fn account_address(key: ReadKey) -> Option<Address> {
    match key {
        ReadKey::Account(address) | ReadKey::Storage(address, _) => Some(address),
        _ => None,
    }
}

fn cached_account_read(cached: &CacheAccount, key: ReadKey, expected: &ReadValue) -> CachedRead {
    match (key, expected) {
        (ReadKey::Account(_), ReadValue::Account(expected)) => {
            let actual = cached.account.as_ref().map(|account| &account.info);
            let matches = match (actual, expected.as_ref()) {
                (Some(actual), Some(expected)) => {
                    expected.account_id.is_none() && account_info_matches(actual, expected)
                }
                (None, None) => true,
                _ => false,
            };
            if matches {
                CachedRead::Equal
            } else {
                CachedRead::Different(ReadValue::Account(actual.cloned()))
            }
        }
        (ReadKey::Storage(_, slot), ReadValue::Storage(expected)) => {
            let actual = match &cached.account {
                None => U256::ZERO,
                Some(account) => match account.storage.get(&slot) {
                    Some(value) => *value,
                    // State::storage materializes missing slots even when
                    // their value is already known to be zero. Keep that
                    // insertion observable to later direct cache mutations.
                    None => return CachedRead::Unknown,
                },
            };
            if actual == *expected {
                CachedRead::Equal
            } else {
                CachedRead::Different(ReadValue::Storage(actual))
            }
        }
        // Malformed key/value pairs retain the generic validator's behavior.
        _ => CachedRead::Unknown,
    }
}

fn cached_other_read<P: Database>(db: &State<P>, key: ReadKey, expected: &ReadValue) -> CachedRead {
    match (key, expected) {
        (ReadKey::Code(hash), ReadValue::Code(expected)) => {
            let Some(actual) = db.cache.contracts.get(&hash) else {
                return CachedRead::Unknown;
            };
            if bytecode_matches(actual, expected) {
                CachedRead::Equal
            } else {
                CachedRead::Different(ReadValue::Code(actual.clone()))
            }
        }
        (ReadKey::BlockHash(number), ReadValue::BlockHash(expected)) => {
            let Some(actual) = db.block_hashes.get(number) else {
                return CachedRead::Unknown;
            };
            if actual == *expected {
                CachedRead::Equal
            } else {
                CachedRead::Different(ReadValue::BlockHash(actual))
            }
        }
        // Malformed key/value pairs retain the generic validator's behavior.
        _ => CachedRead::Unknown,
    }
}
