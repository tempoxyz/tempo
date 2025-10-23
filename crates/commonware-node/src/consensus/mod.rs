//! Mainly aliases to define consensus within tempo.

pub(crate) mod block;
pub(crate) mod engine;
pub(crate) mod execution_driver;
mod supervisor;

use commonware_consensus::{Reporters, marshal, threshold_simplex::types::Activity};
use commonware_cryptography::bls12381::primitives::variant::MinSig;
pub(crate) use supervisor::Supervisor;

pub use engine::{Builder, Engine};

use tempo_commonware_node_cryptography::{BlsScheme, Digest, PrivateKey};

use crate::utils::ChannelReporter;

type Consensus<TContext, TBlocker> = commonware_consensus::threshold_simplex::Engine<
    TContext,
    PrivateKey,
    TBlocker,
    BlsScheme,
    Digest,
    crate::consensus::execution_driver::ExecutionDriverMailbox,
    crate::consensus::execution_driver::ExecutionDriverMailbox,
    Reporter,
    Supervisor,
>;

// This seems to be the reporter that the marshal "syncer" is talking to.
// Alto actually has 2 reporters, this "marshal mailbox" and a custom indexer::Pusher;
// we skip the latter for now.
type Reporter = Reporters<
    Activity<MinSig, Digest>,
    marshal::Mailbox<BlsScheme, block::Block>,
    ChannelReporter<Activity<MinSig, Digest>>,
>;
