use crate::{
    simplex::types::Finalization,
    types::{Epoch, Epocher, ViewDelta},
    Block,
};
use commonware_cryptography::{
    certificate::{Provider, Scheme},
    Digest, Digestible,
};
use commonware_parallel::Strategy;
use commonware_runtime::buffer::paged::CacheRef;
use std::num::{NonZeroU64, NonZeroUsize};

/// Startup anchor for marshal.
///
/// Durable progress from a previous run takes precedence when it already
/// supersedes the configured anchor.
pub enum Start<S: Scheme, C: Digest, B> {
    /// Start from the height-zero genesis block.
    Genesis(B),
    /// Start from a finalized commitment.
    Floor(Finalization<S, C>),
}

/// Marshal configuration.
///
/// # Epocher and Provider Coverage
///
/// Any height marshal is asked to sync must be covered by both the
/// [epocher](Self::epocher) and the [provider](Self::provider). If
/// either returns `None` for a requested height, resolved requests will
/// be acknowledged and then dropped. If no longer needed (say a duplicate request
/// for a height we've long since processed), this drop is harmless. However, failing
/// to provide either the epocher or the provider for a height we still require to
/// process the canonical chain will lead marshal to stall (acknowledged requests
/// may not be retried).
///
/// ## Safe Pruning
///
/// Applications may prune epocher/provider entries once the last processed
/// height passes a prune target. The last processed height can be
/// derived from an `Update::Block` at height `H` as
/// `H - max_pending_acks` (the maximum backlog of blocks the application can buffer).
pub struct Config<P, ES, T, AB, B, C = <AB as Digestible>::Digest>
where
    AB: Block,
    C: Digest,
    P: Provider<Scope = Epoch>,
    ES: Epocher,
    T: Strategy,
{
    /// Provider for epoch-specific signing schemes.
    ///
    /// Must cover every epoch that contains heights the marshal will sync.
    pub provider: P,

    /// Configuration for epoch lengths across block height ranges.
    ///
    /// Must cover every height the marshal will sync.
    pub epocher: ES,

    /// Startup anchor for marshal's processed floor.
    pub start: Start<P::Scheme, C, B>,

    /// The prefix to use for all partitions.
    pub partition_prefix: String,

    /// Size of backfill request/response mailbox.
    pub mailbox_size: NonZeroUsize,

    /// Minimum number of views to retain temporary data after the application processes a block.
    ///
    /// Useful for keeping around information that peers may desire to have.
    pub view_retention_timeout: ViewDelta,

    /// Prunable archive partition prefix.
    pub prunable_items_per_section: NonZeroU64,

    /// The page cache to use for the freezer journal.
    pub page_cache: CacheRef,

    /// The size of the replay buffer for storage archives.
    pub replay_buffer: NonZeroUsize,

    /// The size of the write buffer for the key journal of storage archives.
    pub key_write_buffer: NonZeroUsize,

    /// The size of the write buffer for the value journal of storage archives.
    pub value_write_buffer: NonZeroUsize,

    /// Codec configuration for block type.
    pub block_codec_config: AB::Cfg,

    /// Maximum number of blocks to repair at once.
    pub max_repair: NonZeroUsize,

    /// Maximum number of blocks dispatched to the application that have not
    /// yet been acknowledged. Increasing this value allows the application
    /// to buffer work while marshal continues dispatching, hiding ack latency.
    pub max_pending_acks: NonZeroUsize,

    /// Strategy for parallel operations.
    pub strategy: T,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::{coding::types::CodedBlock, mocks::block::Block as MockBlock},
        simplex::{scheme::ed25519, types::Context},
        types::{coding::Commitment, FixedEpocher},
    };
    use commonware_coding::ReedSolomon;
    use commonware_cryptography::{
        certificate::ConstantProvider,
        ed25519::PublicKey,
        sha256::{Digest as Sha256Digest, Sha256},
    };
    use commonware_parallel::Sequential;

    #[test]
    fn config_compiles_with_distinct_application_and_start_blocks() {
        type AB = MockBlock<Sha256Digest, Context<Commitment, PublicKey>>;
        type B = CodedBlock<AB, ReedSolomon<Sha256>, Sha256>;
        type Provider = ConstantProvider<ed25519::Scheme, Epoch>;

        fn assert_well_formed<T>() {}

        assert_well_formed::<Config<Provider, FixedEpocher, Sequential, AB, B, Commitment>>();
    }
}
