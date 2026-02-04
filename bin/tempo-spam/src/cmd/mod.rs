mod spam;

use clap::{Parser, Subcommand};
pub use spam::SpamArgs;

#[derive(Parser, Debug)]
#[command(name = "tempo-spam", version, about, long_about = None)]
pub struct TempoSpam {
    #[command(subcommand)]
    pub cmd: TempoSpamSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum TempoSpamSubcommand {
    /// Run comprehensive transaction spam covering all Tempo codepaths
    Spam(SpamArgs),
}

impl TempoSpamSubcommand {
    pub async fn run(self) -> eyre::Result<()> {
        match self {
            Self::Spam(args) => args.run().await,
        }
    }
}
