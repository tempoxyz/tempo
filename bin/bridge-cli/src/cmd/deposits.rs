use clap::Parser;
use eyre::Result;
use std::path::PathBuf;
use tempo_bridge_exex::StateManager;

#[derive(Parser, Debug)]
pub struct DepositsArgs {
    /// Path to bridge state file
    #[arg(short, long, default_value = "bridge-state.json")]
    state: PathBuf,

    /// Show only pending (non-finalized) deposits
    #[arg(long, default_value_t = true)]
    pending: bool,

    /// Output format (table, json)
    #[arg(short, long, default_value = "table")]
    format: String,
}

impl DepositsArgs {
    pub async fn run(self) -> Result<()> {
        if !self.state.exists() {
            println!("No state file found at {:?}", self.state);
            return Ok(());
        }

        let state_manager = StateManager::new_persistent(&self.state)?;
        let pending_ids = state_manager.get_pending_deposits().await;

        if self.format == "json" {
            println!("{}", serde_json::to_string_pretty(&pending_ids)?);
            return Ok(());
        }

        println!("Pending Deposits");
        println!("================");
        println!();

        if pending_ids.is_empty() {
            println!("No pending deposits found.");
            return Ok(());
        }

        println!("{:<66} {:>10}", "Request ID", "Status");
        println!("{}", "-".repeat(80));

        for request_id in &pending_ids {
            println!("{:<66} {:>10}", request_id, "pending");
        }

        println!();
        println!("Total: {} pending deposit(s)", pending_ids.len());

        Ok(())
    }
}
