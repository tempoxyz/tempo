//! Config options specific to the p2p layer.

const DEFAULT_MAX_MESSAGE_SIZE_BYTES: usize = 5 * 1024 * 1024; // 5MB

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
