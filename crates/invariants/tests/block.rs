//! Block invariant behaviour tests (mirrors `src/block/`).
//!
//! One test per invariant, covering all combinations.

use tempo_invariants::{RunEntities, block::BlockView, run};
use tempo_precompiles::storage::hashmap::HashMapStorageProvider;

#[test]
fn block_gas_limit() {
    let fires = |gas_used: u64, gas_limit: u64| {
        let mut p = HashMapStorageProvider::new(1);
        let block = BlockView {
            number: 1,
            gas_used,
            gas_limit,
        };
        run(
            &mut p,
            &RunEntities {
                block: Some(&block),
                ..Default::default()
            },
        )
        .failures
        .iter()
        .any(|f| f.id == "TEMPO-BLOCK-GAS-LIMIT")
    };

    assert!(fires(11, 10)); // over limit -> fires
    assert!(!fires(9, 10)); // under limit -> ok
    assert!(!fires(10, 10)); // exactly at limit -> ok
}
