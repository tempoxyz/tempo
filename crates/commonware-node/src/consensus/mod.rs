//! Mainly aliases to define consensus within tempo.

pub mod block;
pub mod engine;
pub mod execution_driver;
mod supervisor;

pub use engine::Engine;

use commonware_consensus::marshal;
pub use execution_driver::ExecutionDriver;
pub use supervisor::Supervisor;

use tempo_commonware_node_cryptography::{BlsScheme, Digest, PrivateKey};

pub type Consensus<TContext, TBlocker> = commonware_consensus::threshold_simplex::Engine<
    TContext,
    PrivateKey,
    TBlocker,
    BlsScheme,
    Digest,
    crate::consensus::execution_driver::Mailbox<tempo_primitives::Block>,
    crate::consensus::execution_driver::Mailbox<tempo_primitives::Block>,
    Reporter,
    Supervisor,
>;

pub type Activity = commonware_consensus::threshold_simplex::types::Activity<BlsScheme, Digest>;
pub type Context = commonware_consensus::threshold_simplex::types::Context<Digest>;

pub type Finalization =
    commonware_consensus::threshold_simplex::types::Finalization<BlsScheme, Digest>;
pub type Notarization =
    commonware_consensus::threshold_simplex::types::Notarization<BlsScheme, Digest>;

// This seems to be the reporter that the marshal "syncer" is talking to.
// Alto actually has 2 reporters, this "marshal mailbox" and a custom indexer::Pusher;
// we skip the latter for now.
pub type Reporter = marshal::Mailbox<BlsScheme, block::Block<tempo_primitives::Block>>;

pub type View = commonware_consensus::threshold_simplex::types::View;
