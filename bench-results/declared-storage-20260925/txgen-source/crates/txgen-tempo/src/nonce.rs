//! Tempo-specific nonce fetching from the nonce precompile.
//!
//! The nonce precompile is at address 0x4E4F4E4345000000000000000000000000000000
//! Storage layout: keccak256(abi.encode(account_address, nonce_key)) -> nonce (uint64)
//!
//! For protocol nonce (key 0), the nonce is stored in the account state directly.

use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_provider::{network::Ethereum, Provider};
use eyre::{Result, WrapErr};
use tempo_primitives::transaction::TEMPO_EXPIRING_NONCE_KEY;

/// Tempo nonce precompile address (ASCII hex for "NONCE")
pub const NONCE_PRECOMPILE: Address = Address::new([
    0x4E, 0x4F, 0x4E, 0x43, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
]);

/// Prefetch parallel lane nonces for all (account, nonce_key) pairs found in templates.
///
/// Scans the spec templates for literal `nonce_key` values and fetches the current
/// nonce from the nonce precompile for each (sender, nonce_key) combination.
/// Protocol nonces (key=0) are skipped — use [`txgen_ethereum::fetch_protocol_nonces`]
/// for those.
pub async fn prefetch_parallel_nonces<P: Provider<Ethereum> + Clone + Send + Sync>(
    provider: &P,
    accounts: &txgen_core::AccountManager,
    spec: &txgen_core::WorkloadSpec,
    nonces: &mut txgen_core::NonceTracker,
) -> Result<()> {
    prefetch_parallel_nonces_with_state(provider, accounts, spec, nonces, false).await
}

pub(crate) async fn prefetch_pending_parallel_nonces<
    P: Provider<Ethereum> + Clone + Send + Sync,
>(
    provider: &P,
    accounts: &txgen_core::AccountManager,
    spec: &txgen_core::WorkloadSpec,
    nonces: &mut txgen_core::NonceTracker,
) -> Result<()> {
    prefetch_parallel_nonces_with_state(provider, accounts, spec, nonces, true).await
}

async fn prefetch_parallel_nonces_with_state<P: Provider<Ethereum> + Clone + Send + Sync>(
    provider: &P,
    accounts: &txgen_core::AccountManager,
    spec: &txgen_core::WorkloadSpec,
    nonces: &mut txgen_core::NonceTracker,
    pending: bool,
) -> Result<()> {
    use crate::compute_parallel_scheduling_key;

    let nonce_keys = collect_prefetchable_parallel_nonce_keys(spec, pending);

    if nonce_keys.is_empty() {
        return Ok(());
    }

    eprintln!("prefetching nonces for {} parallel lane(s)...", nonce_keys.len());

    // Count instead of per-lane eprintln: the cross product of accounts ×
    // lanes can be in the thousands, and one `eprintln!` per pair would
    // serialize on the global stderr lock and dominate the loop.
    let mut fetched = 0usize;
    for (pool_name, addresses) in accounts.all_addresses() {
        for address in addresses {
            for &nonce_key in &nonce_keys {
                let nonce = fetch_parallel_lane_nonce(provider, address, nonce_key, pending)
                    .await
                    .wrap_err_with(|| format!("pool {pool_name} lane {nonce_key} ({address})"))?;
                let scheduling_key = compute_parallel_scheduling_key(address, nonce_key);
                nonces.reset(scheduling_key, nonce);
                fetched += 1;
            }
        }
    }
    eprintln!("prefetched {fetched} (account, lane) nonce(s)");

    Ok(())
}

/// Fetch the on-chain nonce for `(address, nonce_key)`.
///
/// Dispatches between standard `eth_getTransactionCount` (protocol nonce,
/// `key=0`), the reserved expiring-nonce key (always 0), and the nonce
/// precompile storage read (any other parallel lane). Used both by the
/// up-front [`prefetch_parallel_nonces`] path and the lazy first-touch path
/// in [`crate::TempoAdapter`].
pub(crate) async fn fetch_lane_nonce<P: Provider<Ethereum>>(
    provider: &P,
    address: Address,
    nonce_key: U256,
    pending: bool,
) -> Result<u64> {
    if nonce_key.is_zero() {
        let request = provider.get_transaction_count(address);
        let request = if pending { request.pending() } else { request.latest() };
        request.await.wrap_err("failed to fetch protocol nonce")
    } else if nonce_key == TEMPO_EXPIRING_NONCE_KEY {
        Ok(0)
    } else {
        fetch_parallel_lane_nonce(provider, address, nonce_key, pending).await
    }
}

/// Read the parallel-lane nonce for `(address, nonce_key)` from the nonce
/// precompile storage. Caller is responsible for handling reserved keys
/// (`0` and [`TEMPO_EXPIRING_NONCE_KEY`]); this function unconditionally
/// reads the precompile storage.
async fn fetch_parallel_lane_nonce<P: Provider<Ethereum>>(
    provider: &P,
    address: Address,
    nonce_key: U256,
    pending: bool,
) -> Result<u64> {
    let storage_key = compute_nonce_storage_key(address, nonce_key);
    let request = provider.get_storage_at(NONCE_PRECOMPILE, storage_key);
    let request = if pending { request.pending() } else { request.latest() };
    let storage_value = request.await.wrap_err_with(|| {
        format!("failed to fetch parallel nonce for {address} lane {nonce_key}")
    })?;
    Ok(storage_value.to::<u64>())
}

/// Collect constant 2D nonce lanes that can be prefetched before generation.
///
/// Prefetch only makes sense for nonce keys that are already fixed in the spec.
/// Generated keys (`uniform`, `choice`, etc.) are resolved per transaction and
/// cannot be known ahead of time.
fn collect_prefetchable_parallel_nonce_keys(
    spec: &txgen_core::WorkloadSpec,
    include_all_templates: bool,
) -> std::collections::HashSet<U256> {
    let mut nonce_keys = std::collections::HashSet::new();

    if include_all_templates {
        for value in spec.templates.values() {
            collect_nonce_key_from_template_value(value.clone(), &mut nonce_keys);
        }
        return nonce_keys;
    }

    for entry in &spec.mix {
        match &entry.item {
            txgen_core::MixItem::Template(template_name) => {
                if let Some(value) = spec.templates.get(template_name) {
                    collect_nonce_key_from_template_value(value.clone(), &mut nonce_keys);
                }
            }
            txgen_core::MixItem::Sequence(sequence_name) => {
                if let Some(sequence) = spec.sequences.get(sequence_name) {
                    for step in &sequence.steps {
                        if let Some(base) = spec.templates.get(&step.template) {
                            let mut value = base.clone();
                            txgen_core::merge_yaml(&mut value, step.with_value.clone());
                            collect_nonce_key_from_template_value(value, &mut nonce_keys);
                        }
                    }
                }
            }
        }
    }

    nonce_keys
}

fn collect_nonce_key_from_template_value(
    value: serde_yaml::Value,
    nonce_keys: &mut std::collections::HashSet<U256>,
) {
    use crate::TempoTemplate;
    use txgen_core::GenValue;

    if let Ok(template) = serde_yaml::from_value::<TempoTemplate>(value) &&
        !template.expiring_nonce &&
        let Some(GenValue::Literal(key)) = &template.nonce_key &&
        !key.is_zero() &&
        *key != TEMPO_EXPIRING_NONCE_KEY
    {
        nonce_keys.insert(*key);
    }
}

/// Compute the storage slot for `nonces[address][nonce_key]` in the nonce
/// precompile.
///
/// The precompile lays out parallel-nonce state as a Solidity nested mapping
/// `mapping(address => mapping(uint256 => uint64)) public nonces` at base
/// slot 0, so the slot is:
///
/// ```text
/// outer = keccak256(abi.encode(address, 0))
/// slot  = keccak256(abi.encode(nonce_key, outer))
/// ```
fn compute_nonce_storage_key(address: Address, nonce_key: U256) -> U256 {
    // outer = keccak256(abi.encode(address, 0))
    let mut outer_data = [0u8; 64];
    outer_data[12..32].copy_from_slice(address.as_slice());
    // remaining 32 bytes are zero (base slot 0).
    let outer = keccak256(outer_data);

    // slot = keccak256(abi.encode(nonce_key, outer))
    let mut slot_data = [0u8; 64];
    slot_data[..32].copy_from_slice(&nonce_key.to_be_bytes::<32>());
    slot_data[32..64].copy_from_slice(outer.as_slice());

    let hash: B256 = keccak256(slot_data);
    U256::from_be_bytes(hash.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use txgen_core::WorkloadSpec;

    #[test]
    fn test_nonce_precompile_address() {
        // "NONCE" in ASCII hex
        assert_eq!(
            format!("{:?}", NONCE_PRECOMPILE).to_lowercase(),
            "0x4e4f4e4345000000000000000000000000000000"
        );
    }

    #[test]
    fn test_compute_storage_key() {
        let address = Address::repeat_byte(0xab);
        let nonce_key = U256::from(42);

        let key = compute_nonce_storage_key(address, nonce_key);

        // Should be deterministic
        let key2 = compute_nonce_storage_key(address, nonce_key);
        assert_eq!(key, key2);

        // Different nonce_key should give different storage key
        let key3 = compute_nonce_storage_key(address, U256::from(43));
        assert_ne!(key, key3);
    }

    #[test]
    fn test_compute_storage_key_matches_solidity_nested_mapping() {
        // Lock in the slot formula against an externally computed reference
        // so the layout assumption stays in sync with the on-chain
        // `mapping(address => mapping(uint256 => uint64)) public nonces`.
        //
        // Reference (computed with `cast keccak`):
        //   addr  = 0x000000000000000000000000000000000000abAB
        //   lane  = 42
        //   outer = keccak256(abi.encode(addr, 0))
        //         = 0xf11631168a553db43e44374e1de6445a95a7667e3724045d06ba239ddc4b0939
        //   slot  = keccak256(abi.encode(lane, outer))
        //         = 0x2028c9f493f53a125e5a3e03d423a869339e3d2dd8a77340dd393eab48750b1c
        let address: Address = "0x000000000000000000000000000000000000abAB".parse().unwrap();
        let nonce_key = U256::from(42);
        let expected: U256 =
            "0x2028c9f493f53a125e5a3e03d423a869339e3d2dd8a77340dd393eab48750b1c".parse().unwrap();
        assert_eq!(compute_nonce_storage_key(address, nonce_key), expected);
    }

    #[test]
    fn test_collect_prefetchable_parallel_nonce_keys_skips_expiring_nonce_templates() {
        let spec = WorkloadSpec::parse(
            r#"
chain_id: 1
templates:
  expiring_flag:
    type: tempo
    from: { pool: users, select: random }
    to: "0x0000000000000000000000000000000000000001"
    gas_limit: 21000
    expiring_nonce: true
    valid_before: 1700000000
  expiring_reserved_key:
    type: tempo
    from: { pool: users, select: random }
    to: "0x0000000000000000000000000000000000000001"
    gas_limit: 21000
    nonce_key: "115792089237316195423570985008687907853269984665640564039457584007913129639935"
    valid_before: 1700000000
  parallel_lane:
    type: tempo
    from: { pool: users, select: random }
    to: "0x0000000000000000000000000000000000000001"
    gas_limit: 21000
    nonce_key: "42"
mix:
  - template: expiring_flag
    weight: 1
  - template: expiring_reserved_key
    weight: 1
  - template: parallel_lane
    weight: 1
"#,
        )
        .unwrap();

        let nonce_keys = collect_prefetchable_parallel_nonce_keys(&spec, false);
        assert_eq!(nonce_keys.len(), 1);
        assert!(nonce_keys.contains(&U256::from(42)));
    }
}
