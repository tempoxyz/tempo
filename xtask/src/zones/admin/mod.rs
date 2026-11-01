use clap::Subcommand;

mod check;
mod config;
mod encryption_key;
mod identity;
mod invariants;
mod leader;
pub(crate) mod secret_file;
mod sequencer_set;
mod snapshot;

pub(crate) use check::Check;
pub(crate) use encryption_key::EncryptionKey;
pub(crate) use identity::Identity;
pub(crate) use leader::Leader;
pub(crate) use sequencer_set::SequencerSet;
pub(crate) use snapshot::{PortalSnapshot, read_portal_snapshot};

#[derive(Debug, clap::Parser)]
pub(crate) struct Admin {
    #[command(subcommand)]
    command: AdminCommand,
}

#[derive(Debug, Subcommand)]
enum AdminCommand {
    /// Audit finalized Portal state and live Zone nodes without changing state.
    Check(Check),
    /// Prepare or register a shared sequencer encryption key.
    EncryptionKey(EncryptionKey),
    /// Prepare independent per-node P2P and sequencer identities.
    Identity(Identity),
    /// Move finalized Zone leadership to a different sequencer.
    Leader(Leader),
    /// Guard changes to the Portal sequencer set.
    SequencerSet(SequencerSet),
}

impl Admin {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        match self.command {
            AdminCommand::Check(command) => command.run().await,
            AdminCommand::EncryptionKey(command) => command.run().await,
            AdminCommand::Identity(command) => command.run(),
            AdminCommand::Leader(command) => command.run().await,
            AdminCommand::SequencerSet(command) => command.run().await,
        }
    }
}
