//! Integration tests for the L1StateProvider against live Tempo L1 RPC.
//!
//! Run with: `cargo test -p zone-node --test l1_state_reader -- --ignored --nocapture`
//!
//! Requires `L1_RPC_URL` env var or defaults to moderato RPC.

use alloy_primitives::{Address, B256, address};
use alloy_provider::{Provider, ProviderBuilder};
use tempo_alloy::TempoNetwork;
use zone_l1::state::{L1StateCache, L1StateProvider, L1StateProviderConfig};

/// ZonePortal address on Tempo L1 moderato.
const ZONE_PORTAL: Address = address!("0x1bc99e6a8c4689f1884527152ba542f012316149");

fn l1_rpc_url() -> String {
    std::env::var("L1_RPC_URL").unwrap_or_else(|_| "https://rpc.moderato.tempo.xyz".into())
}

async fn make_provider() -> L1StateProvider {
    let config = L1StateProviderConfig {
        l1_rpc_url: l1_rpc_url(),
        portal_address: ZONE_PORTAL,
        ..Default::default()
    };
    let cache = L1StateCache::new();
    let rt = tokio::runtime::Handle::current();
    L1StateProvider::new(config, cache, rt)
        .await
        .expect("failed to connect L1 state provider")
}

async fn recent_block_number() -> u64 {
    let l1 = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect_http(l1_rpc_url().parse().unwrap())
        .erased();
    l1.get_block_number().await.unwrap().saturating_sub(100)
}

// ---------------------------------------------------------------
//  Test 1: L1StateProvider can fetch a storage slot from L1 RPC
// ---------------------------------------------------------------

#[tokio::test]
#[ignore = "requires live L1 RPC"]
async fn l1_provider_reads_storage_slot() {
    let provider = make_provider().await;
    let block = recent_block_number().await;

    let value = provider
        .get_storage_async(ZONE_PORTAL, B256::ZERO, block)
        .await
        .expect("should read storage from L1 RPC");

    println!("ZonePortal slot 0 at block {block}: {value}");
    assert_ne!(value, B256::ZERO, "slot 0 should be non-zero");
}

// ---------------------------------------------------------------
//  Test 2: Cached reads return the same value
// ---------------------------------------------------------------

#[tokio::test]
#[ignore = "requires live L1 RPC"]
async fn l1_provider_caches_result() {
    let provider = make_provider().await;
    let block = recent_block_number().await;

    let v1 = provider
        .get_storage_async(ZONE_PORTAL, B256::ZERO, block)
        .await
        .unwrap();

    // Should be served from cache now
    let v2 = provider
        .get_storage_async(ZONE_PORTAL, B256::ZERO, block)
        .await
        .unwrap();

    assert_eq!(v1, v2, "cached and fresh values must match");

    let cached = provider.cache().lock().get(ZONE_PORTAL, B256::ZERO, block);
    assert_eq!(cached, Some(v1), "value should be in cache after read");
    println!("Cache hit verified for slot 0 at block {block}: {v1}");
}

// ---------------------------------------------------------------
//  Test 3: Multiple slots can be read in sequence
// ---------------------------------------------------------------

#[tokio::test]
#[ignore = "requires live L1 RPC"]
async fn l1_provider_reads_multiple_slots() {
    let provider = make_provider().await;
    let block = recent_block_number().await;

    let slots = [
        B256::ZERO,
        B256::with_last_byte(1),
        B256::with_last_byte(2),
        B256::with_last_byte(3),
    ];

    for (i, slot) in slots.iter().enumerate() {
        let value = provider
            .get_storage_async(ZONE_PORTAL, *slot, block)
            .await
            .expect("should read slot from L1");
        println!("ZonePortal slot[{i}] at block {block}: {value}");
    }

    // Slot 0 should be non-zero (contains init data)
    let v0 = provider.cache().lock().get(ZONE_PORTAL, B256::ZERO, block);
    assert!(
        v0.is_some_and(|v| !v.is_zero()),
        "slot 0 should be non-zero"
    );
}

// ---------------------------------------------------------------
//  Test 4: Synchronous get_storage works from a blocking context
// ---------------------------------------------------------------

#[tokio::test]
#[ignore = "requires live L1 RPC"]
async fn l1_provider_sync_read_from_blocking_thread() {
    let provider = make_provider().await;
    let block = recent_block_number().await;

    let value = tokio::task::spawn_blocking(move || {
        provider
            .get_storage(ZONE_PORTAL, B256::ZERO, block)
            .expect("sync get_storage should work from blocking thread")
    })
    .await
    .unwrap();

    println!("Sync read ZonePortal slot 0 at block {block}: {value}");
    assert_ne!(value, B256::ZERO);
}
