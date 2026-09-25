use alloy_eips::eip2930::{AccessList, AccessListItem};
use alloy_primitives::{Address, B256, U256};
use eyre::{bail, Result};
use serde::Deserialize;
use txgen_core::{BuildContext, GenValue};

/// A transaction access-list entry. Sequence bindings can share keys with calldata.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessListEntry {
    pub address: GenValue<Address>,
    #[serde(default)]
    pub storage_keys: StorageKeys,
}

/// Explicit keys or a bounded consecutive range, expanded before signing.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum StorageKeys {
    Keys(Vec<GenValue<B256>>),
    Range { range: StorageKeyRange },
}

impl Default for StorageKeys {
    fn default() -> Self {
        Self::Keys(Vec::new())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageKeyRange {
    pub start: GenValue<U256>,
    pub count: usize,
}

const MAX_GENERATED_KEYS: usize = 65_536;

pub(crate) fn resolve_access_list(
    entries: &[AccessListEntry],
    ctx: &mut BuildContext<'_>,
) -> Result<AccessList> {
    let mut items = Vec::with_capacity(entries.len());
    let mut total = 0usize;
    for entry in entries {
        let count = match &entry.storage_keys {
            StorageKeys::Keys(keys) => keys.len(),
            StorageKeys::Range { range } => range.count,
        };
        total = total.checked_add(count).ok_or_else(|| eyre::eyre!("access list is too large"))?;
        if total > MAX_GENERATED_KEYS {
            bail!("access list exceeds {MAX_GENERATED_KEYS} generated storage keys");
        }
        let address = ctx.resolve_value(&entry.address)?;
        let storage_keys = match &entry.storage_keys {
            StorageKeys::Keys(keys) => {
                keys.iter().map(|key| ctx.resolve_value(key)).collect::<Result<_>>()?
            }
            StorageKeys::Range { range } => {
                if range.count == 0 {
                    bail!("storage key range must contain at least one key");
                }
                let start = ctx.resolve_value(&range.start)?;
                // Check the final key before allocating, including the valid single MAX key.
                start
                    .checked_add(U256::from(range.count - 1))
                    .ok_or_else(|| eyre::eyre!("storage key range overflows uint256"))?;
                (0..range.count)
                    .map(|offset| B256::from((start + U256::from(offset)).to_be_bytes::<32>()))
                    .collect()
            }
        };
        items.push(AccessListItem { address, storage_keys });
    }
    Ok(AccessList(items))
}
