//! Config options specific to the p2p layer.

use reth_consensus_common::validation::MAX_RLP_BLOCK_SIZE;

/// Set the maximum permitted message size to Reth's maximum RLP-encoded block size.
///
/// It is enforced on the builder side in `crates/payload/builder/src/lib.rs`.
const DEFAULT_MAX_MESSAGE_SIZE_BYTES: usize = MAX_RLP_BLOCK_SIZE;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct Config {
    /// The maximum permitted message size in bytes for messages sent over the
    /// p2p network.
    pub max_message_size_bytes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_message_size_bytes: DEFAULT_MAX_MESSAGE_SIZE_BYTES,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Dummy test to catch any upstream Reth changes of max RLP block size.
    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.max_message_size_bytes, 8_388_608);
    }
}
