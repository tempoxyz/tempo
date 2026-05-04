//! A collection of aliases for frequently used (primarily commonware) types.

pub(crate) mod marshal {
    use commonware_consensus::{
        marshal::{core, standard},
        simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization},
        types::FixedEpocher,
    };
    use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
    use commonware_parallel::Sequential;
    use commonware_storage::archive::immutable;
    use commonware_utils::acknowledgement::Exact;

    use crate::consensus::{Digest, application::TempoApplication, block::Block};

    pub(crate) type Actor<TContext> = core::Actor<
        TContext,
        standard::Standard<Block>,
        crate::epoch::SchemeProvider,
        immutable::Archive<TContext, Digest, Finalization<Scheme<PublicKey, MinSig>, Digest>>,
        immutable::Archive<TContext, Digest, Block>,
        FixedEpocher,
        Sequential,
        Exact,
    >;

    pub(crate) type Mailbox = core::Mailbox<Scheme<PublicKey, MinSig>, standard::Standard<Block>>;

    pub(crate) type Inline<TContext> = standard::Inline<
        TContext,
        Scheme<PublicKey, MinSig>,
        TempoApplication,
        Block,
        FixedEpocher,
    >;
}
