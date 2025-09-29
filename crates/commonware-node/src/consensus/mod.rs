//! Mainly aliases to define consensus within tempo.

pub mod block;
pub mod engine;
pub mod execution_driver;
mod supervisor;

pub use engine::Engine;

use commonware_consensus::marshal;
pub use supervisor::Supervisor;

use tempo_commonware_node_cryptography::{BlsScheme, Digest, PrivateKey};

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
type Reporter = marshal::Mailbox<BlsScheme, block::Block>;
