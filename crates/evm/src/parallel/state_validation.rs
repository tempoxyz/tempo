//! Exact validation against the current authoritative revm State cache.

use super::{DBErrorMarker, Database, ReadKey, ReadValue, SpeculativeResult, U256, read};
use reth_revm::State;

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
        self.validate_with(|key, expected| match cached_read(db, key, expected) {
            CachedRead::Equal => Ok(None),
            CachedRead::Different(actual) => Ok(Some(actual)),
            CachedRead::Unknown => {
                let actual = read(db, key)?;
                Ok((actual != *expected).then_some(actual))
            }
        })
    }
}

fn cached_read<P: Database>(db: &State<P>, key: ReadKey, expected: &ReadValue) -> CachedRead {
    match (key, expected) {
        (ReadKey::Account(address), ReadValue::Account(expected)) => {
            let Some(cached) = db.cache.accounts.get(&address) else {
                return CachedRead::Unknown;
            };
            let actual = cached.account.as_ref().map(|account| &account.info);
            // Preserve AccountInfo's existing equality exactly; do not impose
            // additional comparisons on inline code or BAL account IDs.
            if actual == expected.as_ref() {
                CachedRead::Equal
            } else {
                CachedRead::Different(ReadValue::Account(actual.cloned()))
            }
        }
        (ReadKey::Storage(address, slot), ReadValue::Storage(expected)) => {
            let Some(cached) = db.cache.accounts.get(&address) else {
                return CachedRead::Unknown;
            };
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
        (ReadKey::Code(hash), ReadValue::Code(expected)) => {
            let Some(actual) = db.cache.contracts.get(&hash) else {
                return CachedRead::Unknown;
            };
            if actual == expected {
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
