use alloy_primitives::B256;
use tempo_light::{
    checkpoint::Checkpoint,
    config::{Layout, Network},
};

pub(super) fn checkpoint() -> Checkpoint {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../fixtures/mpt-finality-v1.json")).unwrap();
    Checkpoint {
        version: 1,
        network: Network {
            chain_id: 1337,
            genesis_hash: B256::repeat_byte(42),
            anchor: serde_json::from_value(fixture["trustAnchor"].clone()).unwrap(),
            epoch_length: std::num::NonZeroU64::new(fixture["epochLength"].as_u64().unwrap())
                .unwrap(),
            layout: Layout::V1,
            unsupported_layout_from: None,
        },
        identity: serde_json::from_value(fixture["trustAnchor"].clone()).unwrap(),
        head: serde_json::from_value(fixture["evidence"].clone()).unwrap(),
        transition: None,
    }
}
