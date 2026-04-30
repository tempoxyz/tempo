use crate::opts::{TempoSidecar, TempoSidecarSubcommand};
use clap::Parser;

mod cmd;
pub mod monitor;
mod opts;
mod synthetic_load;

/// Force-install the default crypto provider.
///
/// This is necessary in case there are more than one available backends enabled in rustls (ring,
/// aws-lc-rs).
///
/// This should be called high in the main fn.
///
/// See also:
///   <https://github.com/snapview/tokio-tungstenite/issues/353#issuecomment-2455100010>
///   <https://github.com/awslabs/aws-sdk-rust/discussions/1257>
fn install_crypto_provider() {
    // https://github.com/snapview/tokio-tungstenite/issues/353
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default rustls crypto provider");
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    install_crypto_provider();

    let args = TempoSidecar::parse();

    match args.cmd {
        TempoSidecarSubcommand::FeeAMMMonitor(cmd) => cmd.run().await,
        TempoSidecarSubcommand::SimpleArb(cmd) => cmd.run().await,
        TempoSidecarSubcommand::SyntheticLoad(cmd) => cmd.run().await,
        TempoSidecarSubcommand::TxLatencyMonitor(cmd) => cmd.run().await,
    }
}
