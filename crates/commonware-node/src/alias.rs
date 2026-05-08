//! A collection of aliases for frequently used (primarily commonware) types.

pub(crate) mod marshal {
    use commonware_consensus::{
        marshal::{core, standard::Standard},
        simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization},
        types::FixedEpocher,
    };
    use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
    use commonware_parallel::Sequential;
    use commonware_storage::archive::immutable;
    use commonware_utils::acknowledgement::Exact;
    use reth_ethereum::provider::db::DatabaseEnv;
    use reth_node_builder::NodeTypesWithDBAdapter;
    use reth_provider::providers::BlockchainProvider;
    use tempo_node::node::TempoNode;

    use crate::{
        consensus::{Digest, block::Block},
        storage::Hybrid,
    };

    /// Concrete reth provider used by [`tempo_node::TempoFullNode`].
    type TempoProvider = BlockchainProvider<NodeTypesWithDBAdapter<TempoNode, DatabaseEnv>>;

    pub(crate) type Actor<TContext> = core::Actor<
        TContext,
        Standard<Block>,
        crate::epoch::SchemeProvider,
        immutable::Archive<TContext, Digest, Finalization<Scheme<PublicKey, MinSig>, Digest>>,
        Hybrid<TContext, TempoProvider>,
        FixedEpocher,
        Sequential,
        Exact,
    >;

    pub(crate) type Mailbox = core::Mailbox<Scheme<PublicKey, MinSig>, Standard<Block>>;
}
