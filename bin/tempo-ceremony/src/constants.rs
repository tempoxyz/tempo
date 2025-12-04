//! Constants for the genesis ceremony.

/// Epoch for the genesis ceremony.
pub const GENESIS_EPOCH: u64 = 0;

/// Output filenames for ceremony results.
pub mod output {
    /// Private signing share (unique per participant).
    pub const SHARE: &str = "share-private.hex";
    /// Public polynomial commitment (shared across all participants).
    pub const PUBLIC_POLYNOMIAL: &str = "public-polynomial.hex";
    /// Genesis extra data for chain initialization (shared across all participants).
    pub const GENESIS_EXTRA_DATA: &str = "genesis-extra-data.hex";
    /// Human-readable genesis outcome JSON (shared across all participants).
    pub const GENESIS_OUTCOME: &str = "genesis-outcome.json";
    /// All dealings from the ceremony (shared across all participants).
    pub const ALL_DEALINGS: &str = "all-dealings.json";

    /// Files that should be identical across all participants.
    pub const SHARED_FILES: &[&str] = &[
        PUBLIC_POLYNOMIAL,
        GENESIS_EXTRA_DATA,
        GENESIS_OUTCOME,
        ALL_DEALINGS,
    ];
}

/// Network configuration defaults.
pub mod network {
    /// Default maximum message size (1MB).
    pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 1024 * 1024;
    /// Default mailbox size for P2P channels.
    pub const DEFAULT_MAILBOX_SIZE: usize = 1024;
    /// Channel ID for ceremony messages.
    pub const CHANNEL_ID: u64 = 0;

    /// Returns default max message size (for serde default).
    pub const fn default_max_message_size() -> usize {
        DEFAULT_MAX_MESSAGE_SIZE
    }
    /// Returns default mailbox size (for serde default).
    pub const fn default_mailbox_size() -> usize {
        DEFAULT_MAILBOX_SIZE
    }
}

/// Protocol namespaces for signature domains.
pub mod protocol {
    /// Namespace for ack signatures.
    pub const ACK_NAMESPACE: &[u8] = b"_DKG_ACK";
    /// Namespace for outcome signatures.
    pub const OUTCOME_NAMESPACE: &[u8] = b"_DKG_OUTCOME";
}
